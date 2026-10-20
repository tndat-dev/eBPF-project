#!/usr/bin/env python3
"""Second-stage confirmation by signal persistence (hypothesis from pulse-stable-candidate 5.8a).

Stage 1 is the live preview (k-of-n on per-window joint p-values, < 2 s). Stage 2 waits T seconds after
the first preview and confirms only if at least a fraction f of the windows in [first, first + T] are
positive. Attacks keep firing; a benign new process mostly fires around its launch.

Per (T, f): stage-2 rate for attack / benign-launch / idle-control intervals, separation
(attack - benign), and p95 of (first + T - kernel event). Flags are recomputed from the stored joint
p-values with ``--policy`` so development and test use the same stage-1 rule.

Selection rule, fixed in code before any run (``select``): on the development campaigns only, take the
(T, f) with the largest separation among those with attack stage-2 rate >= 0.90 and T <= 5 s; ties go to
the smaller T, then the larger f. The chosen pair is then applied unchanged to the test campaigns.
"""
import argparse, collections, glob, json, sys, time
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from sentinel_pulse.detector.confirmation import SCORED, ConfirmationPolicy, apply  # noqa: E402

T_GRID = (2.5, 5.0, 7.5, 10.0)
F_GRID = (0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9)


def intervals(campaigns, policy):
    """[(label, scenario, start, kernel_event_at or None, [(window_end, positive)])]"""
    out = []
    for campaign in campaigns:
        for path in sorted(glob.glob(campaign.rstrip('/') + '/trials/*/EVALUATION_INPUT.json')):
            d = json.loads(Path(path).read_text())
            rows = apply([r for r in d['decisions'] if r.get('status') == SCORED and r.get('joint_p') is not None], policy)
            for label in ('control', 'benign', 'attack'):
                t = d.get(label)
                if not t:
                    continue
                s = float(t['start_at'])
                w = [(float(r['window_end']), bool(r['candidate_alert_preview'])) for r in rows
                     if s <= float(r['window_start']) and float(r['window_end']) <= s + 15
                     and (r['node_name'], str(r['pod_uid']), r['container_name']) == (t['node_name'], str(t['pod_uid']), t['container_name'])]
                if len(w) >= 20:
                    out.append((label, d['attack'].get('scenario'), s, t.get('kernel_event_at'), sorted(w)))
    return out


def stage2(items, T, f):
    rates = collections.defaultdict(lambda: [0, 0]); delays = []
    for label, scenario, start, kernel, w in items:
        rates[label][1] += 1
        positives = [e for e, p in w if p]
        if not positives:
            continue
        first = positives[0]
        span = [p for e, p in w if first <= e <= first + T]
        if span and sum(span) / len(span) >= f and w[-1][0] >= first + T - 0.5:
            rates[label][0] += 1
            if label == 'attack' and kernel is not None:
                delays.append(first + T - float(kernel))
    r = {k: v[0] / v[1] if v[1] else None for k, v in rates.items()}
    return dict(attack=r.get('attack'), benign=r.get('benign'), control=r.get('control'),
                separation=(r.get('attack') or 0) - (r.get('benign') or 0),
                p95_stage2_delay=float(np.percentile(delays, 95)) if delays else None,
                n={k: v[1] for k, v in rates.items()})


def table(items):
    return {f'T{T:g}_f{f:g}': dict(T=T, f=f, **stage2(items, T, f)) for T in T_GRID for f in F_GRID}


def select(grid):
    ok = [v for v in grid.values() if (v['attack'] or 0) >= 0.90 and v['T'] <= 5.0]
    if not ok:
        return None
    return max(ok, key=lambda v: (round(v['separation'], 6), -v['T'], v['f']))


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--dev-campaign', action='append', required=True)
    p.add_argument('--test-campaign', action='append', default=[])
    p.add_argument('--policy', default='2,2,10', help='k,n,alpha_scale of stage 1 (default k2of2_a10)')
    p.add_argument('--output', required=True)
    a = p.parse_args()
    k, n, scale = a.policy.split(',')
    policy = ConfirmationPolicy(int(k), int(n), float(scale))
    dev = intervals(a.dev_campaign, policy)
    dev_grid = table(dev); chosen = select(dev_grid)
    stage1 = lambda items: stage2(items, 0.0, 0.0)
    result = dict(schema='pulse-persistence-stage-v1', policy=policy.name, dev_campaigns=a.dev_campaign,
                  test_campaigns=a.test_campaign, rule=__doc__.split('Selection rule')[1].strip(),
                  development=dict(stage1=stage1(dev), grid=dev_grid, chosen=chosen))
    if a.test_campaign and chosen:
        test = intervals(a.test_campaign, policy)
        result['test'] = dict(stage1=stage1(test), chosen=stage2(test, chosen['T'], chosen['f']), grid=table(test),
                              note='test campaign aggregate persistence was seen before this rule was written (5.8a); not blind')
    result['computed_at_unix'] = time.time()
    Path(a.output).write_text(json.dumps(result, indent=2))
    print(json.dumps(dict(dev_stage1=result['development']['stage1'], chosen=chosen,
                          test_stage1=result.get('test', {}).get('stage1'), test_chosen=result.get('test', {}).get('chosen'))))


if __name__ == '__main__':
    main()
