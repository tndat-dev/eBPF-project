#!/usr/bin/env python3
"""Rule labels for every normal alert (RCA case outside the campaign), protocol label-review-v1 (Arp et al. P2).

Suspects are re-ranked with the current ranking (privilege-drop-at-start rule) against the workload's binary
baseline frozen before the campaign (as ``rca.evaluate_ranking --rerank-db``). Labels, in this order:

- ``suspicious``: a security operation (not a drop at start), an unknown or novel binary, or a public destination;
- ``benign_probe``: probe-only (``rca.triage``, declared exec probes);
- ``benign_routine_exec``: execs present, every executed binary in the baseline;
- ``benign_no_process_cause``: no exec in the case;
- ``unclear``: anything else.

Writes the counts and a reading list (every suspicious / unclear case, plus a seeded sample of 10 per benign label)
with a compact evidence summary per case, for the manual verification step of the protocol.
"""
import argparse
from collections import Counter, defaultdict
import ipaddress
import json
import math
from pathlib import Path
import random
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from sentinel_pulse.rca.evaluate_ranking import load_binaries, rerank  # noqa: E402
from sentinel_pulse.rca.triage import iso_seconds, triage  # noqa: E402

LABELS = ('suspicious', 'benign_probe', 'benign_routine_exec', 'benign_no_process_cause', 'unclear')


def public_destinations(case):
    out = []
    for entry in case.get('network_destinations', []):
        try:
            ip = json.loads(entry)[0] if isinstance(entry, str) else entry[0]
            addr = ipaddress.ip_address(str(ip))
        except (ValueError, TypeError, IndexError, json.JSONDecodeError):
            continue
        if not (addr.is_private or addr.is_loopback or addr.is_link_local):
            out.append(str(addr))
    return sorted(set(out))


def label(case, suspects, entries):
    # unknown/novel only count for binaries executed in the case: the RCA baseline learns executed binaries only, so a
    # long-running main process started days earlier (uvicorn, java, redis-server) is always "unknown" without being new.
    # Correction 22/10 01:58, after the first run labelled 3 679/4 766 cases suspicious through such processes; the
    # protocol's intent ("a binary absent from the baseline" = new code running) is unchanged.
    reasons = {r for s in suspects for r in s.get('reasons', []) if r not in ('unknown_binary', 'novel_binary')}
    reasons |= {r for s in suspects if 'started_in_window' in s.get('reasons', []) for r in s.get('reasons', [])}
    t = triage(case, entries)
    public = public_destinations(case)
    flags = sorted(reasons & {'security_operation', 'unknown_binary', 'novel_binary'}) + (['public_destination'] if public else [])
    if flags:
        return 'suspicious', flags, t, public
    if t.get('probe_only'):
        return 'benign_probe', [], t, public
    if t.get('execs', 0) > 0:
        return 'benign_routine_exec', [], t, public
    has_exec = any(n.get('kind') == 'runtime_event' and n.get('operation') == 'exec' for n in case['nodes'])
    if not has_exec:
        return 'benign_no_process_cause', [], t, public
    return 'unclear', ['exec_without_process_source'], t, public


def summary(case, suspects, t, public, lab, flags):
    nodes = {n['id']: n for n in case['nodes']}
    by_exec = {n.get('exec_id'): n for n in case['nodes'] if n['kind'] in ('process', 'process_parent')}
    trig = next(n['trigger'] for n in case['nodes'] if n['kind'] == 'signal')
    ws = iso_seconds(trig.get('window_start')) or 0.0
    execs, security = [], Counter()
    for e in case['edges']:
        tgt, src = nodes.get(e['target']), nodes.get(e['source'])
        if not tgt or tgt.get('kind') != 'runtime_event':
            continue
        if tgt.get('operation') == 'exec' and src:
            parent = by_exec.get(src.get('parent_exec_id'), {})
            execs.append((round((iso_seconds(tgt.get('observed_at')) or ws) - ws, 1), src.get('binary'), parent.get('binary'), src.get('uid')))
        if tgt.get('category') not in ('process', 'network', None):
            security[f"{tgt.get('category')}:{tgt.get('operation')}"] += 1
    return dict(case_id=case['case_id'], label=lab, flags=flags, workload=trig.get('workload_key'), node=trig.get('node_name'),
                pod=case.get('coverage', {}).get('pod_name'), at_utc=time.strftime('%m-%d %H:%M:%S', time.gmtime(ws)),
                joint_p=trig.get('joint_p'), tree_p=trig.get('tree_p'), support_p=trig.get('support_p'),
                triage={k: t.get(k) for k in ('exec_in_window', 'execs', 'probe_execs', 'probe_only')},
                execs=sorted(execs)[:12], other_events=dict(security), public_destinations=public,
                destinations=len(case.get('network_destinations', [])),
                suspects=[(s.get('binary'), s.get('score'), s.get('reasons')) for s in suspects[:3]])


def wilson(k, n, z=1.96):
    if not n:
        return None
    p = k / n; d = 1 + z * z / n; c = p + z * z / (2 * n); h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return [max(0.0, (c - h) / d), min(1.0, (c + h) / d)]


def campaign_span(campaign: Path, margin=60.0):
    starts = [float(json.loads(l)['start_at']) for l in (campaign / 'INTERVALS.jsonl').read_text().splitlines() if l]
    return min(starts) - margin, float(json.loads((campaign / 'TERMINAL.json').read_text())['finished_at_unix']) + margin


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--cases', type=Path, required=True); p.add_argument('--rerank-db', type=Path, required=True)
    p.add_argument('--frozen-at', type=float, required=True); p.add_argument('--campaign', type=Path, required=True)
    p.add_argument('--probe-spec', type=Path, required=True); p.add_argument('--output', type=Path, required=True)
    p.add_argument('--seed', type=int, default=20261022); p.add_argument('--per-label', type=int, default=10)
    a = p.parse_args()
    lo, hi = campaign_span(a.campaign)
    spec = json.loads(a.probe_spec.read_text())['workloads']
    binaries = load_binaries(a.rerank_db)
    counts, by_workload, pools, flags_count = Counter(), defaultdict(Counter), defaultdict(list), Counter()
    for path in sorted(a.cases.glob('*.json')):
        case = json.loads(path.read_text())
        trig = next(n['trigger'] for n in case['nodes'] if n['kind'] == 'signal')
        we = iso_seconds(trig.get('window_end'))
        if we is None or lo <= we <= hi:
            continue
        suspects = rerank(case, binaries, a.frozen_at)
        entries = set((spec.get(trig.get('workload_key')) or {}).get('entry_binaries', ()))
        lab, flags, t, public = label(case, suspects, entries)
        counts[lab] += 1; by_workload[trig.get('workload_key')][lab] += 1
        flags_count.update(flags)
        pools[lab].append(summary(case, suspects, t, public, lab, flags))
    rng = random.Random(a.seed)
    reading = []
    for lab in LABELS:
        items = pools[lab]
        reading += items if lab in ('suspicious', 'unclear') else rng.sample(items, min(a.per_label, len(items)))
    total = sum(counts.values())
    out = dict(schema='pulse-label-review-v1', protocol='sentinel_pulse/protocol/label-review-v1.json', cases=total,
               counts={l: counts[l] for l in LABELS}, share={l: counts[l] / total if total else None for l in LABELS},
               share_ci95={l: wilson(counts[l], total) for l in LABELS}, suspicious_flags=dict(flags_count),
               by_workload={w: dict(c) for w, c in sorted(by_workload.items())}, reading_list=reading,
               frozen_at=a.frozen_at, campaign_span_unix=[lo, hi], computed_at_unix=time.time())
    a.output.write_text(json.dumps(out, indent=1))
    print(json.dumps({k: out[k] for k in ('cases', 'counts', 'suspicious_flags')}), len(reading), 'to read')


if __name__ == '__main__':
    main()
