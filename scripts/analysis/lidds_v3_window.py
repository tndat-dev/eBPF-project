#!/usr/bin/env python3
"""Time-horizon vote over the v2 branches (protocol lidds-evaluation-v3, amendment 1), from lidds_evaluate_v2.py
outputs that keep the alarm window ends of every branch (``scenarios[s]['alarms']``).

The v3 rule (at least 2 of {system, path, errno, bytes, ngram}) was counted per recording: a recording was positive
when two branches alarmed anywhere in it. A live detector has no recordings, so here the rule fires at a window end t
when at least K branches have an alarm window ending in (t - H, t]. H is chosen on the development data of LID-DS
2021 among HORIZONS (H = inf is the per-recording rule, the reference), then the official data is scored once.

An attack recording is detected when the rule fires after the first exploit time (latency = that window end minus
the exploit time); a normal recording with any firing is a false alarm. Development/official parts, metrics and
criteria are those of lidds_v3_combine.py.

    python3 lidds_v3_window.py --select lidds-evaluation-v2-alarms.json [--confirm NAME=other.json ...] --output out.json
"""
from __future__ import annotations

import argparse
from bisect import bisect_right
import gzip
import json
import math
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lidds_v3_combine as v3  # noqa: E402

BRANCHES, K = v3.CORE, 2
HORIZONS = (0.5, 2.0, 5.0, 10.0, 30.0, math.inf)
FAST_SECONDS = 3.0


def firings(arms, horizon, branches=BRANCHES, k=K):
    """Window ends at which at least k branches have an alarm ending in (t - horizon, t]."""
    lists = {b: sorted(arms.get(b, [])) for b in branches}
    out = []
    for t in sorted({t for b in branches for t in lists[b]}):
        n = sum(1 for b in branches
                if bisect_right(lists[b], t) - bisect_right(lists[b], t - horizon) > 0)
        if n >= k:
            out.append(t)
    return out


def rows(doc, horizon):
    """{scenario: {name: (split, detected, latency, false_alarm, subset)}} under one horizon."""
    out = {}
    for scenario, res in doc['scenarios'].items():
        per = {}
        for name, rec in res.get('alarms', {}).items():
            fire, exploit = firings(rec['arms'], horizon), rec['exploit']
            after = [t for t in fire if exploit is not None and t > exploit]
            per[name] = (rec['split'], bool(after), after[0] - exploit if after else None,
                         bool(fire) if exploit is None else any(t <= exploit for t in fire), rec['subset'])
        out[scenario] = per
    return out


def evaluate(doc, part):
    res = {}
    for h in HORIZONS:
        pooled, per = [], {}
        for scenario, r in rows(doc, h).items():
            keep = list(v3.subset_of(scenario, r, part).values())
            per[scenario] = v3.metrics(keep)
            pooled.extend(keep)
        m = v3.metrics(pooled)
        att = [x for x in pooled if x[0] == 'test-normal_and_attack']
        m['detected_within_3s'] = sum(1 for x in att if x[2] is not None and x[2] <= FAST_SECONDS)
        res[label(h)] = dict(horizon_seconds=None if math.isinf(h) else h, pooled=m, scenarios=per)
    return res


def label(h):
    return 'per_recording' if math.isinf(h) else f'H{h:g}s'


def select(dev):
    """Highest development recall with development false alarms <= 2 %; ties to the shorter horizon."""
    order = [label(h) for h in HORIZONS]
    ok = [c for c in order if dev[c]['pooled']['false_alarm_rate'] <= v3.DEV_FA_LIMIT]
    if ok:
        return max(ok, key=lambda c: (dev[c]['pooled']['recall'], -order.index(c))), True
    return min(order, key=lambda c: (dev[c]['pooled']['false_alarm_rate'], order.index(c))), False


def load(path):
    p = Path(path)
    with (gzip.open(p, 'rt') if p.suffix == '.gz' else open(p)) as f:
        return json.load(f)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--select', required=True, help='LID-DS 2021 v2 output with alarm times')
    ap.add_argument('--confirm', action='append', default=[], help='NAME=path of another v2 output with alarm times')
    ap.add_argument('--output', type=Path, required=True)
    a = ap.parse_args()
    base = load(a.select)
    dev, official = evaluate(base, 'development'), evaluate(base, 'official')
    chosen, qualified = select(dev)
    out = dict(schema='pulse-lidds-v3-window', protocol='sentinel_pulse/protocol/lidds-evaluation-v3-amendment-1.json',
               branches=list(BRANCHES), k=K, horizons=[label(h) for h in HORIZONS], selected=chosen,
               selection_qualified=qualified, development=dev, official=official,
               criteria=v3.criteria(official[chosen]), confirmations={})
    for item in a.confirm:
        name, path = item.split('=', 1)
        res = evaluate(load(path), 'all')
        out['confirmations'][name] = dict(results=res, selected=res[chosen], criteria=v3.criteria(res[chosen]))
    a.output.write_text(json.dumps(out, indent=1, default=float))
    brief = lambda m: {k: m[k] for k in ('recall', 'false_alarm_rate', 'latency_p50', 'latency_p95', 'detected_within_3s')}
    print(json.dumps(dict(selected=chosen, qualified=qualified, development={c: brief(v['pooled']) for c, v in dev.items()},
                          official=brief(official[chosen]['pooled']), criteria=out['criteria']), default=float, indent=1))


if __name__ == '__main__':
    main()
