#!/usr/bin/env python3
"""Rule track of pulse-live-final-v1 (protocol sentinel_pulse/protocol/rule-intent-v1.json): the frozen intent
catalogue of exec-intent-v1 as a rule in parallel with the token model, with and without, on a finished live run.

A window fires when one of its calls (the last token of each gram, top 9 bits) is in the catalogue; mprotect counts
only in the steady phase (no execve/execveat in the same window of the container or the one before). Intervals as
native_stream.py (pairs with an attack interval, the H0 denominators), flagged when a window ending in
[start, start + 15 s] fires. ML = rescoring of the whole window with the run's models (equal to the live score).
Burden on the normal tail after the campaign as burden_context.py: alarms of one container merged when < 15 s apart.

    python3 rule_intent.py --run-root RUN --models FIT/token/MODELS.json --output out.json [--jobs 4]
"""
# RULE TRACK: rule danh mục ý đồ (đóng băng từ exec-intent-v1) chạy SONG SONG với mô hình token; so ML một mình,
# rule một mình, ML hoặc rule — trên các bước tấn công, lotl, event-generator, admin, binary vô hại, control, và gánh
# cảnh báo trên đoạn normal cuối lượt.
import argparse
from collections import Counter, defaultdict
import json
from multiprocessing import Pool
import os
from pathlib import Path
import sys

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from sentinel_pulse.common import open_sealed  # noqa: E402
import live_attribution as la  # noqa: E402
import burden_context as bc  # noqa: E402

live = la.live
NR_SHIFT = 23
CATALOGUE = {101: 'ptrace', 308: 'setns', 272: 'unshare', 165: 'mount', 155: 'pivot_root', 126: 'capset',
             105: 'setuid', 106: 'setgid', 317: 'seccomp', 322: 'execveat', 90: 'chmod'}
FAMILY = {91: 'fchmod', 268: 'fchmodat', 452: 'fchmodat2', 113: 'setreuid', 114: 'setregid', 117: 'setresuid',
          119: 'setresgid', 122: 'setfsuid', 123: 'setfsgid'}
MPROTECT, EXECS = 10, (59, 322)
LABELS = ('control', 'admin', 'benign', 'attack', 'lotl', 'eventgen')
SYSTEMS = ('ml_only', 'rule_only', 'ml_or_rule', 'family_only', 'ml_or_family')


def calls_of(grams):
    return {int(g[3]) >> NR_SHIFT for g in grams}


def flags(calls):
    """(exec, mprotect, frozen catalogue calls, family calls) of one window's call set."""
    return (any(c in calls for c in EXECS), MPROTECT in calls,
            tuple(sorted(c for c in calls if c in CATALOGUE)), tuple(sorted(c for c in calls if c in FAMILY)))


def fires(f, exec_before):
    """(frozen fires, family fires, reason calls) given this window's flags and whether the window before had an exec."""
    exec_now, mprot, cat, fam = f
    steady = mprot and not exec_now and not exec_before
    reason = list(cat) + ([MPROTECT] if steady else [])
    return bool(reason), bool(reason or fam), reason + list(fam)


# ------------------------------------------------------------------ reading

def read_intervals(job):
    """Interval windows of one tokens.jsonl (spans extended 1 s back for the exec-before test)."""
    path, spans = job
    pods = {k[0] for k in spans}
    out = []
    with open_sealed(Path(path)) as stream:
        for line in stream:
            pod = la._field(line, 'pod_uid')
            if pod not in pods:
                continue
            key = (pod, la._field(line, 'container_name'))
            ranges = spans.get(key)
            if not ranges:
                continue
            end = float(la._field(line, 'window_end'))
            if not any(a - 1.0 <= end <= b for a, b in ranges):
                continue
            row = json.loads(line)
            out.append((key, end, int(row['window']), row['grams']))
    return out


def read_tail_tokens(job):
    """Normal-tail windows of one tokens.jsonl that hold an exec, an mprotect or a catalogue call: flags only."""
    path, lo, hi, spans = job
    out = []
    with open_sealed(Path(path)) as stream:
        for line in stream:
            if line.startswith('{"type":"prog_names"'):   # exec-identity-v1 program-name lines
                continue
            end = float(la._field(line, 'window_end'))
            if not (lo <= end < hi) or live.in_spans(end, spans):
                continue
            row = json.loads(line)
            f = flags(calls_of(row['grams']))
            if f[0] or f[1] or f[2] or f[3]:
                out.append(((row['pod_uid'], row['container_name']), row['workload_key'], int(row['window']), end, f))
    return out


def read_tail_decisions(job):
    """Normal-tail ML alarms (arm T) and replica-seconds of one decisions.jsonl."""
    path, lo, hi, spans = job
    alarms, seconds, workload_of = defaultdict(list), defaultdict(float), {}
    with open_sealed(Path(path)) as stream:
        for line in stream:
            if '"token-score"' not in line and '"candidate-raw-score-only"' not in line:
                continue
            end = la._field(line, 'window_end')
            if end is None:
                continue
            end = float(end)
            if not (lo <= end < hi) or live.in_spans(end, spans):
                continue
            row = json.loads(line)
            key = (row['pod_uid'], row['container_name'])
            workload_of[key] = row['workload_key']
            if 'T' in live.arms_of(row):
                alarms[key].append(end)
            if row.get('status') == 'candidate-raw-score-only':
                seconds[row['workload_key']] += live.WINDOW_SECONDS
    return dict(alarms), dict(seconds), workload_of


# ------------------------------------------------------------------ intervals

def interval_table(trials, windows, models, lms):
    attack_pairs = {t['pair']: t for t in trials if t['label'] == 'attack'}
    counts = defaultdict(lambda: {s: [0, 0] for s in SYSTEMS})
    by_action = defaultdict(lambda: {s: [0, 0] for s in SYSTEMS})
    latency = defaultdict(list)
    rescued, rule_reasons = [], defaultdict(Counter)
    for t in trials:
        if t['label'] not in LABELS or t['pair'] not in attack_pairs or t['workload'] not in models:
            continue
        pair = attack_pairs[t['pair']]
        lm, thr = lms[t['workload']], models[t['workload']][1]
        wins = sorted(windows.get(t['key'], ()), key=lambda w: w[1])
        execs = {w for _, w, g in wins if flags(calls_of(g))[0]}
        a, b = t['start'], t['start'] + la.HORIZON
        first = {s: None for s in SYSTEMS}
        reasons = Counter()
        for end, w, grams in wins:
            if not a <= end <= b:
                continue
            ml = lm.window_score(grams) > thr
            frozen, family, why = fires(flags(calls_of(grams)), (w - 1) in execs)
            hit = dict(ml_only=ml, rule_only=frozen, ml_or_rule=ml or frozen, family_only=family, ml_or_family=ml or family)
            for s, h in hit.items():
                if h and first[s] is None:
                    first[s] = end
            if frozen or family:
                reasons.update(CATALOGUE.get(c) or FAMILY.get(c) or 'mprotect' for c in why)
        pad = pair.get('pad') or 0
        sets = [f"{t['label']}-pad{pad}"] if pad else [t['label']] + ([f"{t['label']}-primary"] if pair['rate'] in la.PRIMARY else [])
        for name in sets:
            for s in SYSTEMS:
                counts[name][s][0] += first[s] is not None
                counts[name][s][1] += 1
        rule_reasons[t['label'] if not pad else f"{t['label']}-pad{pad}"].update(reasons)
        if t['label'] == 'eventgen' and not pad:
            for s in SYSTEMS:
                by_action[t['command']][s][0] += first[s] is not None
                by_action[t['command']][s][1] += 1
            if first['ml_only'] is None:
                rescued.append(dict(pair=t['pair'], action=t['command'], workload=t['workload'],
                                    rule=first['rule_only'] is not None, family=first['family_only'] is not None,
                                    reasons=dict(reasons)))
        if t['label'] == 'attack' and not pad and pair['rate'] in la.PRIMARY:
            origin = t.get('kernel') or t['start']
            for s in ('ml_only', 'ml_or_rule'):
                if first[s] is not None:
                    latency[s].append(first[s] - origin)
    rate = lambda kn: dict(k=kn[0], n=kn[1], rate=kn[0] / kn[1] if kn[1] else None, ci95=live.wilson(kn[0], kn[1]))
    pct = lambda v: dict(n=len(v), p50=float(np.percentile(v, 50)), p95=float(np.percentile(v, 95))) if v else None
    return (dict(sorted((k, {s: rate(v) for s, v in row.items()}) for k, row in counts.items())),
            dict(sorted((k, {s: rate(v) for s, v in row.items()}) for k, row in by_action.items())),
            {s: pct(v) for s, v in latency.items()}, rescued, {k: dict(v.most_common()) for k, v in rule_reasons.items()})


# ------------------------------------------------------------------ burden

def episodes_of(times):
    return bc.episodes(sorted(times))


def burden(root, jobs):
    cfg = json.loads((root / 'CONFIG.json').read_text())
    normal = (float(cfg['selection_end']), float(cfg['selection_start']) + float(cfg['seconds']))
    spans = [live.campaign_span(root / live.CAMPAIGN)]
    lo = max([normal[0]] + [b for a, b in spans])           # the tail after the campaign (selection prefix is before it)
    hi = normal[1]
    pick = lambda name: [str(p) for p in sorted(root.glob(f'workers/*/segments/*/{name}*')) if os.stat(p).st_mtime >= lo]
    with Pool(jobs) as pool:
        dec = pool.map(read_tail_decisions, [(f, lo, hi, spans) for f in pick('decisions.jsonl')], chunksize=1)
        tok = pool.map(read_tail_tokens, [(f, lo, hi, spans) for f in pick('tokens.jsonl')], chunksize=1)
    ml, seconds, workload_of = defaultdict(list), defaultdict(float), {}
    for alarms, sec, wo in dec:
        for k, v in alarms.items():
            ml[k] += v
        for w, s in sec.items():
            seconds[w] += s
        workload_of.update(wo)
    rows = defaultdict(list)
    for part in tok:
        for key, workload, w, end, f in part:
            rows[key].append((w, end, f))
            workload_of.setdefault(key, workload)
    rule, family, why = defaultdict(list), defaultdict(list), defaultdict(Counter)
    for key, rs in rows.items():
        execs = {w for w, _, f in rs if f[0]}
        for w, end, f in rs:
            frozen, fam, reason = fires(f, (w - 1) in execs)
            if frozen:
                rule[key].append(end)
            if fam:
                family[key].append(end)
            if frozen or fam:
                why[workload_of[key]].update(CATALOGUE.get(c) or FAMILY.get(c) or 'mprotect' for c in reason)
    hours = sum(seconds.values()) / 3600
    systems = dict(ml_only=ml, rule_only=rule, family_only=family,
                   ml_or_rule={k: ml.get(k, []) + rule.get(k, []) for k in set(ml) | set(rule)},
                   ml_or_family={k: ml.get(k, []) + family.get(k, []) for k in set(ml) | set(family)})
    out = {}
    for name, alarms in systems.items():
        per_w = Counter()
        for key, times in alarms.items():
            per_w[workload_of.get(key, '?')] += len(episodes_of(times))
        total = sum(per_w.values())
        out[name] = dict(episodes=total, per_replica_hour=total / hours if hours else None, by_workload=dict(per_w.most_common()))
    return dict(span=[lo, hi], replica_hours=hours, systems=out,
                rule_calls_by_workload={w: dict(c.most_common()) for w, c in sorted(why.items())})


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--run-root', type=Path, required=True)
    ap.add_argument('--models', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--jobs', type=int, default=4)
    a = ap.parse_args()
    trials = live.load_trials(a.run_root / la.CAMPAIGN)
    models = la.load_models(a.models)
    spans = la.spans_of(trials)
    files = [str(p) for p in sorted(a.run_root.glob('workers/*/segments/*/tokens.jsonl*'))]
    windows = defaultdict(list)
    with Pool(a.jobs) as pool:
        for rows in pool.imap_unordered(read_intervals, [(f, spans) for f in files], chunksize=1):
            for key, end, w, grams in rows:
                windows[key].append((end, w, grams))
    lms = {w: la.load_lm(models[w][0]) for w in sorted({t['workload'] for t in trials} & set(models))}
    intervals, actions, latency, rescued, reasons = interval_table(trials, windows, models, lms)
    windows.clear()
    load = burden(a.run_root, a.jobs)
    ev = lambda s: intervals.get('eventgen', {}).get(s, {}).get('k', 0)
    lo = lambda s: intervals.get('lotl', {}).get(s, {}).get('k', 0)
    gain = (ev('ml_or_rule') - ev('ml_only')) + (lo('ml_or_rule') - lo('ml_only'))
    control = intervals.get('control', {}).get('ml_or_rule', {}).get('rate')
    b = load['systems']['ml_or_rule']['per_replica_hour']
    decision = dict(recall_gain_intervals=gain, control_rate=control, burden_ml_or_rule=b,
                    adopted=bool(gain >= 1 and control is not None and control <= 0.05 and b is not None and b <= 1.76))
    doc = dict(schema='rule-intent-v1', protocol='sentinel_pulse/protocol/rule-intent-v1.json', run=str(a.run_root),
               models=str(a.models), segments_read=len(files), catalogue=CATALOGUE, family=FAMILY,
               intervals=intervals, eventgen_by_action=actions, latency_primary_attack=latency,
               eventgen_ml_misses=rescued, rule_calls_in_intervals=reasons, burden=load, decision=decision)
    a.output.write_text(json.dumps(doc, indent=1, default=float))
    print(json.dumps(dict(decision=decision, **{k: {s: v[s]['k'] for s in ('ml_only', 'rule_only', 'ml_or_rule')} | {'n': v['ml_only']['n']}
                                               for k, v in intervals.items()},
                          burden={s: v['per_replica_hour'] for s, v in load['systems'].items()}), default=float))


if __name__ == '__main__':
    main()
