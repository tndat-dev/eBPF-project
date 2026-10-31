#!/usr/bin/env python3
"""Choose the extended Pulse configuration on LID-DS 2021 development and CB-DS (protocol lidds-evaluation-v4).

A configuration fires at a window end t when at least k branches of a voting set S have an alarm window ending in
(t - H, t], or, with ``tripwire_alone``, when the tripwire alarms (it fires on its own, as in the stable system).
Search space: S any subset of {system, path, errno, bytes, ngram} with at least two branches, k = 1..|S|,
H in HORIZONS, tripwire_alone in {False, True}.

Selection, from lidds_evaluate_v2.py outputs that keep alarm times: among configurations with LID-DS 2021
development false-alarm recordings <= 2.0 %, development latency p95 <= 3.0 s, CB-DS recall >= 95 % and CB-DS
false-alarm recordings <= 2.0 %, the highest development recall; ties to fewer development false alarms, then fewer
new probe hooks (path, errno, bytes, ngram each need one; system none), then the shorter horizon, then the smaller k,
then without tripwire_alone. The selected configuration is then scored once on LID-DS 2021 official.

    python3 lidds_v4_select.py --lidds2021 v2-alarms.json --cbds v2-cbds-alarms.json [--workers 8] --output v4.json
"""
from __future__ import annotations

import argparse
from bisect import bisect_right
from itertools import combinations
import json
import multiprocessing
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lidds_v3_combine as v3  # noqa: E402
import lidds_v3_window as v3w  # noqa: E402

POOL = ('system', 'path', 'errno', 'bytes', 'ngram')
HOOKED = {'path', 'errno', 'bytes', 'ngram'}
HORIZONS = (0.5, 2.0, 5.0, 10.0, 30.0)
DEV_FA, DEV_P95, CB_RECALL, CB_FA = 0.02, 3.0, 0.95, 0.02
OWNER_RECALL, OWNER_FA = 0.975, 0.0147          # owner priority: keep the v3 LID-DS 2021 official result or better
DOCS = {}


def configurations():
    for n in range(2, len(POOL) + 1):
        for s in combinations(POOL, n):
            for k in range(1, n + 1):
                for h in HORIZONS:
                    for alone in (False, True):
                        yield (s, k, h, alone)


def name(c):
    s, k, h, alone = c
    return f"{'+'.join(s)}|k{k}|H{h:g}s" + ('|tripwire' if alone else '')


def firings(arms, c):
    s, k, h, alone = c
    fire = set(v3w.firings(arms, h, s, k))
    if alone:
        fire.update(arms.get('tripwire', []))
    return sorted(fire)


def rows(doc, c):
    out = {}
    for scenario, res in doc['scenarios'].items():
        per = {}
        for nm, rec in res.get('alarms', {}).items():
            fire, exploit = firings(rec['arms'], c), rec['exploit']
            after = [t for t in fire if exploit is not None and t > exploit]
            per[nm] = (rec['split'], bool(after), after[0] - exploit if after else None,
                       bool(fire) if exploit is None else any(t <= exploit for t in fire), rec['subset'])
        out[scenario] = per
    return out


def score(doc, c, part):
    pooled, per = [], {}
    for scenario, r in rows(doc, c).items():
        keep = list(v3.subset_of(scenario, r, part).values())
        per[scenario] = v3.metrics(keep)
        pooled.extend(keep)
    return v3.metrics(pooled), per


def screen(c):
    dev, _ = score(DOCS['lidds2021'], c, 'development')
    cb, _ = score(DOCS['cbds'], c, 'all')
    ok = (dev['false_alarm_rate'] <= DEV_FA and dev['latency_p95'] is not None and dev['latency_p95'] <= DEV_P95
          and cb['recall'] >= CB_RECALL and cb['false_alarm_rate'] <= CB_FA)
    return dict(config=name(c), branches=list(c[0]), k=c[1], horizon_seconds=c[2], tripwire_alone=c[3],
                hooks=len(HOOKED & set(c[0])), eligible=ok,
                development={x: dev[x] for x in ('recall', 'detected', 'attack_recordings', 'false_alarm_rate',
                                                 'false_alarm_recordings', 'latency_p50', 'latency_p95')},
                cbds={x: cb[x] for x in ('recall', 'detected', 'attack_recordings', 'false_alarm_rate',
                                         'false_alarm_recordings')})


def rank(r):
    return (-r['development']['detected'], r['development']['false_alarm_recordings'], r['hooks'],
            r['horizon_seconds'], r['k'], r['tripwire_alone'])


def select(results):
    eligible = sorted((r for r in results if r['eligible']), key=rank)
    return eligible[0] if eligible else None


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--lidds2021', required=True)
    ap.add_argument('--cbds', required=True)
    ap.add_argument('--workers', type=int, default=8)
    ap.add_argument('--output', type=Path, required=True)
    a = ap.parse_args()
    DOCS['lidds2021'], DOCS['cbds'] = v3w.load(a.lidds2021), v3w.load(a.cbds)
    configs = list(configurations())
    with multiprocessing.get_context('fork').Pool(a.workers) as pool:
        results = pool.map(screen, configs, chunksize=4)
    chosen = select(results)
    out = dict(schema='pulse-lidds-v4-selection', protocol='sentinel_pulse/protocol/lidds-evaluation-v4.json',
               configurations=len(configs), eligible=sum(r['eligible'] for r in results), selected=chosen,
               top10=sorted((r for r in results if r['eligible']), key=rank)[:10], all=results)
    if chosen:
        c = (tuple(chosen['branches']), chosen['k'], chosen['horizon_seconds'], chosen['tripwire_alone'])
        off, per = score(DOCS['lidds2021'], c, 'official')
        worst = max((m['false_alarm_rate'] or 0) for m in per.values())
        out['official'] = dict(pooled=off, scenarios=per)
        out['criteria'] = dict(H1=off['recall'] >= v3.H1_RECALL and off['false_alarm_rate'] <= v3.H1_FA,
                               H2=off['recall'] >= v3.H1_RECALL and off['false_alarm_rate'] <= v3.H1_FA
                               and worst <= v3.H2_SCENARIO_FA,
                               owner_keep_or_better=off['recall'] >= OWNER_RECALL and off['false_alarm_rate'] <= OWNER_FA,
                               worst_scenario_false_alarm_rate=worst)
        cb, _ = score(DOCS['cbds'], c, 'all')
        out['cbds'] = cb
    a.output.write_text(json.dumps(out, indent=1, default=float))
    print(json.dumps(dict(configurations=out['configurations'], eligible=out['eligible'], selected=chosen,
                          official=out.get('official', {}).get('pooled'), criteria=out.get('criteria')),
                     indent=1, default=float))


if __name__ == '__main__':
    main()
