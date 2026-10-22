#!/usr/bin/env python3
"""Rule tier on top of Pulse ML (protocol rule-integration-v1), kept apart from the ML evaluation.

Takes the ML configurations exactly as ``burden_levers.py`` evaluated and chose them (reference CUSUM b3 h6 and the
choice per latency tier in BURDEN-LEVERS.json), recomputes their alarms on the same window tables, and reports:

- ``ml``: the ML-level metrics again, unchanged (a check that this script scores the same alarms);
- ``paged``: after the post-ML probe triage tier. An ML episode is held back from paging when it has at least one
  RCA case of the same container whose trigger window_end lies within 5 s of the episode and every such case is
  probe-only (alarm_taxonomy definitions, declared exec probes from the pod specs); otherwise it pages
  (fail-open). Two burdens: fail-open (an upper bound: RCA opens at most one case per container and cooldown,
  plus follow-ups) and estimated (unmatched episodes held back at the held share of matched episodes of the
  same workload). An ML-positive trial is held back when all RCA cases of its container within
  [start, start + 20 s] are probe-only.

Rules never change an ML decision here: every ML preview stays recorded, and the paged level is a second,
separately reported view (owner decisions 22/10).
"""
import argparse, json, sys, time
from collections import defaultdict
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import burden_levers as bl  # noqa: E402

CASE_FIELDS = ('node_name', 'pod_uid', 'container_name')
TRIAGE_MATCH, TRIAL_CASE_SPAN = 5.0, 20.0


def load_triage(cases_dir, spec_path):
    """{(node, pod_uid, container): sorted [(trigger window_end, probe-only)]} over every RCA case."""
    import alarm_taxonomy as at
    spec = json.loads(Path(spec_path).read_text())['workloads']
    out, unreadable = defaultdict(list), 0
    for path in sorted(Path(cases_dir).glob('*.json')):
        try:
            case = json.loads(path.read_text())
            kind, trigger, _ = at.classify(case)
        except (ValueError, KeyError, StopIteration):
            unreadable += 1
            continue
        execs, probes = at.probe_flags(case, set((spec.get(trigger.get('workload_key')) or {}).get('entry_binaries', ())))
        held = kind == 'exec_in_window' and execs > 0 and probes == execs
        out[tuple(str(trigger.get(f)) for f in CASE_FIELDS)].append((float(trigger['window_end']), held))
    for v in out.values():
        v.sort()
    return dict(out), unreadable


def _held(cases, lo, hi):
    """(matched, held): cases with window_end in [lo, hi]; held when there is one and all are probe-only."""
    if not cases:
        return False, False
    ends = [c[0] for c in cases]
    i, j = np.searchsorted(ends, lo, 'left'), np.searchsorted(ends, hi, 'right')
    flags = [c[1] for c in cases[i:j]]
    return bool(flags), bool(flags) and all(flags)


def paged_metrics(alarm, a, trials, triage, case_key):
    """Paged-level metrics after the probe triage tier; ``case_key[ident index]`` = (node, pod_uid, container)."""
    idx = np.flatnonzero(alarm & a['normal'])
    per = defaultdict(lambda: dict(episodes=0, matched=0, held=0))
    if len(idx):
        ident, end = a['ident'][idx], a['end'][idx]
        first = np.ones(len(idx), bool)
        first[1:] = (ident[1:] != ident[:-1]) | (end[1:] - end[:-1] >= bl.EPISODE_QUIET)
        starts = np.flatnonzero(first); stops = np.append(starts[1:], len(idx))
        for s0, s1 in zip(starts, stops):
            k = int(ident[s0]); w = int(a['workload'][idx[s0]])
            matched, held = _held(triage.get(case_key[k]), end[s0] - TRIAGE_MATCH, end[s1 - 1] + TRIAGE_MATCH)
            per[w]['episodes'] += 1; per[w]['matched'] += matched; per[w]['held'] += held
    hours = a['hours']
    episodes = sum(v['episodes'] for v in per.values()); held = sum(v['held'] for v in per.values())
    matched = sum(v['matched'] for v in per.values())
    estimate = sum(v['episodes'] - v['held'] - (v['episodes'] - v['matched']) * (v['held'] / v['matched'] if v['matched'] else 0)
                   for v in per.values())
    hit, _ = trials.outcome(alarm, a['end'])
    held_trial = np.array([_held(triage.get(case_key[int(a['ident'][lo])]), ts, ts + TRIAL_CASE_SPAN)[1]
                           for lo, ts in zip(trials.lo, trials.start)], dtype=bool)
    paged = hit & ~held_trial
    out = dict(episodes=episodes, episodes_with_case=matched, held_back=held,
               paged_failopen=(episodes - held) / hours, paged_estimate=estimate / hours)
    for label in ('attack', 'benign', 'control'):
        m = trials.label == label
        out[label] = float(paged[m].mean()) if m.any() else None
        out[f'{label}_held_back'] = int((hit & held_trial)[m].sum())
    tp, fp = int(paged[trials.label == 'attack'].sum()), int(paged[trials.label == 'control'].sum())
    out['precision'] = tp / (tp + fp) if tp + fp else None
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--run', action='append', required=True,
                    help='name=<n>,table=<npz>,since=<unix>,campaign=<dir>[,campaign=<dir>],cases=<RCA cases dir>')
    ap.add_argument('--calibration', required=True)
    ap.add_argument('--calibration-table', required=True)
    ap.add_argument('--ml-results', required=True, help='BURDEN-LEVERS.json (ML configurations to put the tier on)')
    ap.add_argument('--probe-spec', required=True, help='exec-probe-spec.json (declared exec probes per workload)')
    ap.add_argument('--output', required=True)
    args = ap.parse_args()
    ml = json.loads(Path(args.ml_results).read_text())
    configs = {'reference': ml['reference']}
    configs.update({tier: c['choice'] for tier, c in ml['selection'].items() if c.get('choice')})
    tree, support = bl.load_calibration(args.calibration)
    classes, _ = bl.calibration_classes(args.calibration_table, tree, support)
    runs = {}
    for spec in args.run:
        kv = defaultdict(list)
        for part in spec.split(','):
            k, v = part.split('=', 1); kv[k].append(v)
        name = kv['name'][0]
        a, p, trials, _ = bl.prepare(kv['table'][0], float(kv['since'][0]), kv['campaign'], tree, support, classes)
        pos = [a['identity_fields'].index(f) for f in CASE_FIELDS]
        case_key = [tuple(i[j] for j in pos) for i in a['identities']]
        triage, unreadable = load_triage(kv['cases'][0], args.probe_spec)
        out = dict(rca_cases=dict(dir=kv['cases'][0], containers=len(triage), cases=sum(map(len, triage.values())),
                                  unreadable=unreadable), configs={})
        for label, config in configs.items():
            variant, mode, rule = config.split('|')
            (_, alarm), = bl.rules(variant, p[variant], a['alpha'], bl.discount_mask(a, mode), a['new'], only=rule)
            out['configs'][label] = dict(config=config, ml=bl.metrics(alarm, a, trials),
                                         ml_as_chosen=ml['candidates'][name][config],
                                         paged=paged_metrics(alarm, a, trials, triage, case_key))
        runs[name] = out
        print(name, json.dumps({k: {m: v['paged'].get(m) for m in ('paged_failopen', 'paged_estimate', 'attack', 'control')}
                                for k, v in out['configs'].items()}), flush=True)
    result = dict(schema='pulse-rule-tier-v1', protocol='sentinel_pulse/protocol/rule-integration-v1.json',
                  ml_results=args.ml_results, probe_spec=args.probe_spec, configs=configs, runs=runs,
                  computed_at_unix=time.time())
    Path(args.output).write_text(json.dumps(result, indent=1, default=str))


if __name__ == '__main__':
    main()
