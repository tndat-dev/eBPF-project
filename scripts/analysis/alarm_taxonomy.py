#!/usr/bin/env python3
"""What do Pulse's normal alerts coincide with? A taxonomy of RCA cases outside the campaign (Pulse 5.18).

Alahmadi, Axon & Martinovic (USENIX Security 2022, "99% False Positives") found that most alarms SOC analysts
call false positives are *benign triggers*: the detector saw a real event, which happened to be harmless.
This splits Pulse's normal alerts the same way, using the RCA evidence tree of each case (Tetragon exec events
of the same container), with definitions fixed before the first run:

- ``exec_in_window``: at least one process exec in the container within [window_start - LOOKBACK,
  window_end + 0.5 s] of the triggering decision. LOOKBACK = 2.5 s covers the 4-window context (1.5 s
  of history) and k2of2 confirmation (one more window) plus 0.5 s margin. A benign trigger candidate;
- ``exec_in_case_only``: no exec in that window, but at least one in the case's 30 s look-back;
- ``no_exec``: no exec in the case at all; the alert has no process-level trigger in the evidence
  (score noise, drift, or an in-process change such as a traffic burst or garbage collection).

Cases whose trigger window lies inside the campaign span (first interval - 60 s to campaign end + 60 s)
or before ``--since`` are left out; follow-up cases (opened *because* of a new exec) are counted apart.
One case is the first trigger of a container per cooldown (300 s), so cases sample alert episodes, they
do not count them. Exec capture relies on the Tetragon exec policy (no sampling for process_exec).

``--probe-spec`` (declared Kubernetes exec probes per workload, from the pod specs) adds a candidate triage rule,
fixed before its first run, in the spirit of NoDoze (Hassan et al., NDSS 2019: discount alerts whose provenance
is historically frequent) and of Falco exceptions for known-benign processes:

- a *probe exec* is an exec whose in-container ancestor chain starts at a process whose parent is ``runc`` and
  whose binary basename is a declared exec-probe entry of that workload (descendants such as ``redis-cli``
  under the probe's ``sh`` count as the probe);
- a case is *probe-only* when it has an exec in the trigger window and **every** exec of its 30 s look-back is a
  probe exec. Probe-only cases are what a probe-aware triage tier would hold back.

The same rule is applied to the campaign cases matched to attack and benign-launch trials (same container,
trigger window end within [start, start + 20 s]) to count how many would be held back. Without process
arguments (not kept in the case) the rule matches binaries, not full command lines: an attacker running the
probe's interpreter through ``kubectl exec`` would be held back too, so a deployable version must also match
the probe's argument vector.
"""
import argparse
from collections import Counter, defaultdict
from datetime import datetime
import json
from pathlib import Path
import time

LOOKBACK = 2.5
AFTER = 0.5


def iso_seconds(text):
    if text is None:
        return None
    if isinstance(text, (int, float)):
        return float(text)
    # Tetragon timestamps: 2026-10-20T12:08:48.362031828Z (nanoseconds; datetime keeps microseconds)
    head, _, frac = text.rstrip('Z').partition('.')
    base = datetime.fromisoformat(head + '+00:00').timestamp()
    return base + (float('0.' + frac) if frac else 0.0)


def classify(case, lookback=LOOKBACK, after=AFTER):
    """(class, trigger, [(seconds, binary)] in window) for one evidence tree."""
    nodes = {n['id']: n for n in case['nodes']}
    trigger = next(n['trigger'] for n in case['nodes'] if n['kind'] == 'signal')
    ws, we = float(trigger['window_start']), float(trigger['window_end'])
    execs = []
    for edge in case['edges']:
        target, source = nodes.get(edge['target']), nodes.get(edge['source'])
        if target and target.get('kind') == 'runtime_event' and target.get('operation') == 'exec':
            execs.append((iso_seconds(target.get('observed_at')), (source or {}).get('binary')))
    inside = sorted((t, b) for t, b in execs if t is not None and ws - lookback <= t <= we + after)
    kind = 'exec_in_window' if inside else ('exec_in_case_only' if execs else 'no_exec')
    return kind, trigger, inside


def probe_flags(case, entry_binaries):
    """(exec count in look-back, probe exec count) using the declared probe entries of the workload."""
    nodes = {n['id']: n for n in case['nodes']}
    by_exec = {n.get('exec_id'): n for n in case['nodes'] if n['kind'] in ('process', 'process_parent')}
    execs = probes = 0
    for edge in case['edges']:
        target, source = nodes.get(edge['target']), nodes.get(edge['source'])
        if not (target and target.get('kind') == 'runtime_event' and target.get('operation') == 'exec' and source):
            continue
        execs += 1
        node, seen = source, set()
        while node is not None and node.get('exec_id') not in seen:
            seen.add(node.get('exec_id'))
            parent = by_exec.get(node.get('parent_exec_id'))
            if parent is None or not parent.get('container_name'):
                if (parent is not None and str(parent.get('binary', '')).rsplit('/', 1)[-1] == 'runc'
                        and str(node.get('binary', '')).rsplit('/', 1)[-1] in entry_binaries):
                    probes += 1
                break
            node = parent
    return execs, probes


def trials(campaign: Path):
    out = []
    for path in sorted(campaign.glob('trials/*/EVALUATION_INPUT.json')):
        d = json.loads(path.read_text())
        for label in ('attack', 'benign'):
            if label in d:
                t = d[label]
                out.append(dict(kind=label, start=float(t['start_at']),
                                key=(t['node_name'], str(t['pod_uid']), t['container_name'])))
    return out


def campaign_span(campaign: Path, margin=60.0):
    starts = [float(json.loads(line)['start_at']) for line in (campaign/'INTERVALS.jsonl').read_text().splitlines() if line]
    return min(starts) - margin, float(json.loads((campaign/'TERMINAL.json').read_text())['finished_at_unix']) + margin


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--cases', type=Path, required=True)
    p.add_argument('--campaign', type=Path, action='append', default=[])
    p.add_argument('--since', type=float, help='ignore triggers before this time (e.g. the end of the RCA warm-up)')
    p.add_argument('--probe-spec', type=Path, help='declared exec probes per workload (exec-probe-spec.json)')
    p.add_argument('--output', required=True)
    a = p.parse_args()
    spans = [campaign_span(c) for c in a.campaign]
    spec = json.loads(a.probe_spec.read_text())['workloads'] if a.probe_spec else None
    probe_only, probe_only_by_workload = Counter(), defaultdict(Counter)
    campaign_cases = defaultdict(list)    # container -> [(trigger end, probe-only)]
    counts, by_workload = Counter(), defaultdict(Counter)
    binaries, binaries_by_workload = Counter(), defaultdict(Counter)
    follow_ups = Counter(); skipped = Counter()
    for path in sorted(a.cases.glob('*.json')):
        try:
            case = json.loads(path.read_text())
            kind, trigger, inside = classify(case)
        except (ValueError, KeyError, StopIteration):
            skipped['unreadable'] += 1; continue
        we = float(trigger['window_end'])
        if a.since is not None and we < a.since:
            skipped['before_since'] += 1; continue
        workload = trigger.get('workload_key')
        held = False
        if spec is not None:
            execs, probes = probe_flags(case, set((spec.get(workload) or {}).get('entry_binaries', ())))
            held = kind == 'exec_in_window' and execs > 0 and probes == execs
        if any(lo <= we <= hi for lo, hi in spans):
            skipped['campaign_span'] += 1
            campaign_cases[(trigger.get('node_name'), str(trigger.get('pod_uid')), trigger.get('container_name'))].append((we, held))
            continue
        if trigger.get('follow_up_of'):
            follow_ups[kind] += 1; continue
        counts[kind] += 1; by_workload[workload][kind] += 1
        probe_only[held] += 1; probe_only_by_workload[workload][held] += 1
        for b in {b for _, b in inside}:
            binaries[b] += 1; binaries_by_workload[workload][b] += 1
    total = sum(counts.values())
    share = {k: v / total for k, v in counts.items()} if total else {}
    triage = None
    if spec is not None:
        matched = defaultdict(Counter)
        for c in a.campaign:
            for t in trials(c):
                hits = [held for end, held in campaign_cases.get(t['key'], ()) if t['start'] <= end <= t['start'] + 20]
                matched[t['kind']]['with_case' if hits else 'without_case'] += 1
                if hits and all(hits):
                    matched[t['kind']]['all_matched_cases_held_back'] += 1
        triage = dict(rule='probe-only cases held back (see docstring)', normal_cases_held_back=probe_only[True],
                      normal_share_held_back=probe_only[True] / total if total else None,
                      by_workload={w: dict(cases=sum(c.values()), held_back=c[True]) for w, c in sorted(probe_only_by_workload.items())},
                      campaign_trials={k: dict(v) for k, v in matched.items()})
    result = dict(schema='pulse-alarm-taxonomy-v1', cases_dir=str(a.cases), campaigns=[str(c) for c in a.campaign],
                  since_unix=a.since, lookback_seconds=LOOKBACK, after_seconds=AFTER, cases=total, counts=dict(counts),
                  share=share, follow_up_cases=dict(follow_ups), skipped=dict(skipped), probe_triage=triage,
                  top_binaries_in_window=binaries.most_common(25),
                  by_workload={w: dict(cases=sum(c.values()), **{k: c[k] for k in ('exec_in_window', 'exec_in_case_only', 'no_exec')},
                                       top_binaries=binaries_by_workload[w].most_common(5))
                               for w, c in sorted(by_workload.items())},
                  note='descriptive; one case per container per cooldown; normal windows unadjudicated',
                  computed_at_unix=time.time())
    Path(a.output).write_text(json.dumps(result, indent=2))
    print(json.dumps(dict(cases=total, share={k: round(v, 3) for k, v in share.items()}, follow_ups=dict(follow_ups),
                          skipped=dict(skipped), top=binaries.most_common(8),
                          triage=None if triage is None else {k: triage[k] for k in ('normal_cases_held_back', 'normal_share_held_back', 'campaign_trials')})))


if __name__ == '__main__':
    main()
