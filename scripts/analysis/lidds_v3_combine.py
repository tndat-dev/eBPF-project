#!/usr/bin/env python3
"""Combination rules over the v2 branches (protocol lidds-evaluation-v3), from lidds_evaluate_v2.py outputs.

Every v2 output keeps, per scenario and arm, one outcome per test recording:
``(split, detected, latency, false_episodes, windows, subset, name)``. A rule with threshold k over a set of branches
detects an attack recording when at least k branches detected it after the exploit (latency = the k-th smallest),
and marks a normal recording as a false alarm when at least k branches alarmed in it; k = 1 is OR.

Development = the v2 development attacks plus a seeded 30 % of each scenario's test/normal recordings; official = the
rest. The rule is selected on the development data of the selection dataset (LID-DS 2021) only, then reported on its
official data and, unchanged, on every other dataset given.

    python3 lidds_v3_combine.py --select lidds-evaluation-v2.json [--confirm NAME=other-v2.json ...] --output v3.json
"""
from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
import zlib

import numpy as np

NORMAL_SEED, DEV_SHARE = 20261031, 0.3
CORE = ('system', 'path', 'errno', 'bytes', 'ngram')
CANDIDATES = {
    'C0_step3': (('step3',), 1, None),
    'C1_union_core': (CORE, 1, None),
    'C2_vote2_core': (CORE, 2, None),
    'C3_system_or_vote2': (('path', 'errno', 'bytes', 'ngram'), 2, 'system'),
    'C4_system_or_ngram': (('system', 'ngram'), 1, None),
    'C5_vote2_all': (('ml', 'tripwire', 'path', 'errno', 'bytes', 'ngram'), 2, None),
}
DEV_FA_LIMIT, H1_RECALL, H1_FA, H2_SCENARIO_FA = 0.02, 0.95, 0.03, 0.05


def wilson(k, n, z=1.96):
    if not n:
        return None
    p = k / n; den = 1 + z * z / n
    c = (p + z * z / (2 * n)) / den; h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / den
    return [c - h, c + h]


def normal_dev(scenario, names):
    names = sorted(names)
    order = np.random.default_rng(NORMAL_SEED + zlib.crc32(scenario.encode())).permutation(len(names))
    return {names[i] for i in order[:round(DEV_SHARE * len(names))]}


def combine(arms, rule):
    """arms: {arm: [outcome]} of one scenario -> {name: (split, detected, latency, false_alarm, subset)}."""
    branches, k, extra = rule
    by = {}
    for arm in branches + ((extra,) if extra else ()):
        for o in arms[arm]:
            by.setdefault(o[6], {})[arm] = o
    out = {}
    for name, per in by.items():
        any_o = next(iter(per.values()))
        split, subset = any_o[0], any_o[5]
        lat = sorted(per[a][2] for a in branches if a in per and per[a][1] and per[a][2] is not None)
        votes_det = sum(1 for a in branches if a in per and per[a][1])
        votes_fa = sum(1 for a in branches if a in per and per[a][3] > 0)
        det, fa = votes_det >= k, votes_fa >= k
        latency = lat[k - 1] if det and len(lat) >= k else None
        if extra and extra in per:
            e = per[extra]
            if e[1]:
                latency = e[2] if latency is None or (e[2] is not None and e[2] < latency) else latency
            det, fa = det or bool(e[1]), fa or e[3] > 0
        out[name] = (split, det, latency, fa, subset)
    return out


def subset_of(scenario, rows, part):
    """part: 'development' | 'official' -> rows of that part (attacks by the v2 subset, normals by normal_dev)."""
    dev_normals = normal_dev(scenario, [n for n, r in rows.items() if r[0] == 'test-normal'])
    keep = {}
    for name, r in rows.items():
        if r[0] == 'test-normal':
            inside = (name in dev_normals) == (part == 'development')
        else:
            inside = r[4] == part
        if part == 'all' or inside:
            keep[name] = r
    return keep


def metrics(rows):
    att = [r for r in rows if r[0] == 'test-normal_and_attack']; nor = [r for r in rows if r[0] == 'test-normal']
    det = sum(r[1] for r in att); fa = sum(r[3] for r in nor)
    lat = [r[2] for r in att if r[2] is not None]
    out = dict(attack_recordings=len(att), detected=det, recall=det / len(att) if att else None,
               recall_ci95=wilson(det, len(att)), normal_recordings=len(nor), false_alarm_recordings=fa,
               false_alarm_rate=fa / len(nor) if nor else None, false_alarm_ci95=wilson(fa, len(nor)),
               latency_p50=float(np.percentile(lat, 50)) if lat else None,
               latency_p95=float(np.percentile(lat, 95)) if lat else None)
    rr, fr = out['recall'], out['false_alarm_rate']
    out['precision_1to1'] = rr / (rr + fr) if rr is not None and fr is not None and rr + fr else None
    out['precision_base_rate'] = det / (det + fa) if det + fa else None
    return out


def evaluate(doc, part):
    """{candidate: dict(pooled=metrics, scenarios={s: metrics})} on one part of one v2 output."""
    res = {}
    for cand, rule in CANDIDATES.items():
        pooled, per = [], {}
        for scenario, arms in doc['recordings'].items():
            rows = subset_of(scenario, combine(arms, rule), part)
            per[scenario] = metrics(list(rows.values()))
            pooled.extend(rows.values())
        res[cand] = dict(pooled=metrics(pooled), scenarios=per)
    return res


def select(dev):
    ok = [c for c in CANDIDATES if dev[c]['pooled']['false_alarm_rate'] <= DEV_FA_LIMIT]
    order = list(CANDIDATES)
    if ok:
        return max(ok, key=lambda c: (dev[c]['pooled']['recall'], -dev[c]['pooled']['false_alarm_rate'], -order.index(c))), True
    high = [c for c in CANDIDATES if dev[c]['pooled']['recall'] >= H1_RECALL] or list(CANDIDATES)
    return min(high, key=lambda c: (dev[c]['pooled']['false_alarm_rate'], order.index(c))), False


def criteria(result):
    p = result['pooled']
    h1 = p['recall'] >= H1_RECALL and p['false_alarm_rate'] <= H1_FA
    worst = max((m['false_alarm_rate'] or 0) for m in result['scenarios'].values())
    return dict(H1=h1, H2=h1 and worst <= H2_SCENARIO_FA, worst_scenario_false_alarm_rate=worst)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--select', type=Path, required=True, help='merged LID-DS 2021 v2 output')
    ap.add_argument('--confirm', action='append', default=[], help='NAME=path of another v2 output (LID-DS 2019, CB-DS)')
    ap.add_argument('--output', type=Path, required=True)
    a = ap.parse_args()
    base = json.loads(a.select.read_text())
    dev, official = evaluate(base, 'development'), evaluate(base, 'official')
    chosen, qualified = select(dev)
    out = dict(schema='pulse-lidds-evaluation-v3', protocol='sentinel_pulse/protocol/lidds-evaluation-v3.json',
               candidates={c: dict(branches=list(r[0]), k=r[1], or_with=r[2]) for c, r in CANDIDATES.items()},
               selected=chosen, selection_qualified=qualified, development=dev, official=official,
               criteria=criteria(official[chosen]), confirmations={})
    for item in a.confirm:
        name, path = item.split('=', 1)
        other = json.loads(Path(path).read_text())
        res = evaluate(other, 'all')
        out['confirmations'][name] = dict(results=res, selected=res[chosen], criteria=criteria(res[chosen]))
    a.output.write_text(json.dumps(out, indent=1, default=float))
    print(json.dumps(dict(selected=chosen, qualified=qualified, dev=dev[chosen]['pooled'], official=official[chosen]['pooled'],
                          criteria=out['criteria'], confirmations={k: v['criteria'] for k, v in out['confirmations'].items()}),
                     default=float, indent=1))


if __name__ == '__main__':
    main()
