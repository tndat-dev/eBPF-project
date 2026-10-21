#!/usr/bin/env python3
"""Offline screen of two literature ideas on campaign intervals (Pulse 5.11 R4, R5/A2), registered 21/10.

Every method uses the same per-window scores, recomputed with one calibration (default: the refreshed
calibration chosen by rule v2), on the trial files of the campaigns (control / benign launch / attack):

- ``joint``  : Pulse today, joint_p = min(1, 2 min(tree_p, support_p)) + k2of2, alpha x scale;
- ``cauchy`` : Cauchy combination of tree_p and support_p (Liu & Xie 2020) + k2of2, alpha x scale;
- ``cusum``  : CUSUM on s_t = -ln(joint_p) - b per container, alarm when S_t >= h (S reset to 0 after a gap
               > 1 s, as the k-of-n history); no consecutive-window requirement.

Rule fixed before running (``select``): the reference is joint + k2of2 at alpha x10. For each other method,
choose on the development campaigns the parameter with the highest attack rate among those whose idle-control
positive rate is <= the reference's on development (ties: lower p95). Apply it unchanged to the test campaign
and report attack / benign / control rates and p95 (first alarm window_end - kernel event) next to the reference.
Interval rates only: whole-normal burden is measured later on full decisions. Test campaign aggregates were
seen (5.8a); not blind.
"""
import argparse, collections, glob, json, math, sys, time
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from sentinel_pulse.detector.recalibration import Recalibrator  # noqa: E402

SCORED = 'candidate-raw-score-only'
SCALES = (3.0, 5.0, 7.0, 10.0, 15.0, 20.0)
CUSUM_B = (2.0, 3.0, 4.0, 5.0)
CUSUM_H = (1.0, 2.0, 3.0, 4.0, 6.0, 8.0)


def load_calibration(path):
    z = np.load(path, allow_pickle=False)
    tree = {f.split('::', 1)[1]: z[f] for f in z.files if f.startswith('tree::')}
    support = {f.split('::', 1)[1]: z[f] for f in z.files if f.startswith('support::')}
    return Recalibrator(tree, support)


def cauchy(ps):
    ps = np.clip(np.asarray(ps, dtype=np.float64), 1e-15, 1 - 1e-15)
    t = np.mean(np.tan((0.5 - ps) * math.pi), axis=0)
    return 0.5 - np.arctan(t) / math.pi


def trials(campaigns, recal):
    """[(label, scenario, start, kernel or None, rows)] with rows = per-window dict for the trial container."""
    out = []
    for campaign in campaigns:
        for path in sorted(glob.glob(campaign.rstrip('/') + '/trials/*/EVALUATION_INPUT.json')):
            d = json.loads(Path(path).read_text())
            for label in ('control', 'benign', 'attack'):
                t = d.get(label)
                if not t:
                    continue
                ident = (t['node_name'], str(t['pod_uid']), t['container_name'])
                rows = []
                for r in d['decisions']:
                    if r.get('status') != SCORED or (r['node_name'], str(r['pod_uid']), r['container_name']) != ident:
                        continue
                    rr = recal.rewrite(r)
                    if rr is None:
                        continue
                    rows.append(dict(start=float(r['window_start']), end=float(r['window_end']), tree_p=rr['tree_p'],
                                     support_p=rr['support_p'], joint_p=rr['joint_p'], alpha=float(r['candidate_policy_alpha'])))
                rows.sort(key=lambda x: x['end'])
                out.append((label, d['attack'].get('scenario'), float(t['start_at']), t.get('kernel_event_at'), rows))
    return out


def alarms_kofn(rows, pkey, scale, k=2, n=2):
    hist, last, flags = [], None, []
    for r in rows:
        if last is None or r['start'] - last > 1.0 or r['start'] < last - 0.25:
            hist = []
        p = r[pkey] if pkey != 'cauchy' else float(cauchy([r['tree_p'], r['support_p']]))
        passed = p <= r['alpha'] * scale
        hist = (hist + [passed])[-n:]
        flags.append(passed and sum(hist) >= k)
        last = r['end']
    return flags


def alarms_cusum(rows, b, h):
    s, last, flags = 0.0, None, []
    for r in rows:
        if last is None or r['start'] - last > 1.0 or r['start'] < last - 0.25:
            s = 0.0
        s = max(0.0, s + (-math.log(max(r['joint_p'], 1e-12)) - b))
        flags.append(s >= h)
        last = r['end']
    return flags


def evaluate(items, method, param):
    rates = collections.defaultdict(lambda: [0, 0]); delays = []
    for label, scenario, start, kernel, rows in items:
        if len(rows) < 20:
            continue
        flags = (alarms_kofn(rows, 'joint_p', param) if method == 'joint' else
                 alarms_kofn(rows, 'cauchy', param) if method == 'cauchy' else alarms_cusum(rows, *param))
        hits = [r['end'] for r, f in zip(rows, flags) if f and start <= r['start'] and r['end'] <= start + 15]
        rates[label][1] += 1
        if hits:
            rates[label][0] += 1
            if label == 'attack' and kernel is not None and hits[0] >= float(kernel):
                delays.append(hits[0] - float(kernel))
    r = {k: v[0] / v[1] for k, v in rates.items() if v[1]}
    return dict(attack=r.get('attack'), benign=r.get('benign'), control=r.get('control'),
                p95=float(np.percentile(delays, 95)) if delays else None,
                p50=float(np.percentile(delays, 50)) if delays else None, n={k: v[1] for k, v in rates.items()})


def grid(items):
    g = {f'joint_a{s:g}': ('joint', s) for s in SCALES}
    g.update({f'cauchy_a{s:g}': ('cauchy', s) for s in SCALES})
    g.update({f'cusum_b{b:g}_h{h:g}': ('cusum', (b, h)) for b in CUSUM_B for h in CUSUM_H})
    return {name: dict(method=m, param=p, **evaluate(items, m, p)) for name, (m, p) in g.items()}


def select(dev):
    ref = dev['joint_a10']; chosen = {'joint': 'joint_a10'}
    for method in ('cauchy', 'cusum'):
        ok = [(n, v) for n, v in dev.items() if v['method'] == method and v['control'] is not None
              and v['control'] <= ref['control'] + 1e-12 and v['attack'] is not None]
        if ok:
            chosen[method] = max(ok, key=lambda nv: (nv[1]['attack'], -(nv[1]['p95'] or 99)))[0]
    return chosen


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--dev-campaign', action='append', required=True)
    p.add_argument('--test-campaign', action='append', required=True)
    p.add_argument('--calibration', required=True, help='npz written by confirmation_study calibrate')
    p.add_argument('--output', required=True)
    a = p.parse_args()
    recal = load_calibration(a.calibration)
    dev, test = grid(trials(a.dev_campaign, recal)), grid(trials(a.test_campaign, recal))
    chosen = select(dev)
    result = dict(schema='pulse-ideas-screen-v1', calibration=a.calibration, dev_campaigns=a.dev_campaign,
                  test_campaigns=a.test_campaign, rule=__doc__.split('Rule fixed before running')[1].strip(),
                  chosen=chosen, development={n: dev[n] for n in chosen.values()}, test={n: test[n] for n in chosen.values()},
                  development_grid=dev, test_grid=test, computed_at_unix=time.time())
    Path(a.output).write_text(json.dumps(result, indent=2, default=str))
    for m, n in chosen.items():
        d, t = dev[n], test[n]
        print(f"{m:7s} {n:18s} dev a/b/c {d['attack']:.3f}/{d['benign']:.3f}/{d['control']:.3f} p95 {d['p95']:.2f} | "
              f"test a/b/c {t['attack']:.3f}/{t['benign']:.3f}/{t['control']:.3f} p95 {t['p95']:.2f} p50 {t['p50']:.2f}")


if __name__ == '__main__':
    main()
