#!/usr/bin/env python3
"""lidds-ml-v4 (sentinel_pulse/protocol/lidds-ml-v4.json): lidds-ml-v3 with a cross-fitted token branch and levels 0.9 / 0.05 /
0.05 of alpha 0.0002. Token matrices from lidds_ml_token_crossfit.py (held-out maxima as val/<name>), tree and support from
lidds_ml_scores.py --all-windows. Without --official nothing of the official split is read; with it the output file must
not exist, so the official split is scored once, after the development and CB-DS numbers registered in the protocol are
reproduced.

    python3 lidds_ml_v4.py --scores DIR --tokens DIR --lidds-alarms a.json.gz --cbds-alarms c.json.gz --output out.json [--official]
"""
import argparse
import json
from pathlib import Path
import sys

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lidds_ml_v2 as m  # noqa: E402
import lidds_v3_combine as v3  # noqa: E402

ALPHA = 0.0002
SHARES = dict(T=.9, tree=.05, support=.05)
TOP_DROP = .01
GATE = dict(detected=530, false_alarm_recordings=12)
GATE_CB = dict(detected=891, false_alarm_recordings=3)


def trimmed_gumbel(maxima, drop=TOP_DROP):
    """Moment Gumbel without the top share of the maxima (at least one): rule R4 of the protocol."""
    x = np.sort(np.asarray(maxima, float))
    return m.gumbel(x[:max(2, len(x) - max(1, int(round(len(x) * drop))))])


class Scenario(m.Scenario):
    def __init__(self, name, dirs):
        super().__init__(name, dirs)
        z, col, i, end, _ = self.branch['T']
        maxima = [m.transform(col, z[k][:, i]).max() for k in z.files if k.startswith('val/') and len(z[k])]
        self.branch['T'] = (z, col, i, end, trimmed_gumbel(maxima))

    def firings(self, branches, alpha, name):
        out = []
        for b in branches:
            z, col, i, end, fit = self.branch[b]
            if name in z.files and len(z[name]):
                a = z[name]
                level = alpha * (SHARES[b] if len(branches) > 1 else 1.0)
                out.extend(a[m.transform(col, a[:, i]) > m.threshold(fit, level), end].tolist())
        return sorted(out)


def run(a):
    m.set_token_column('xfit')
    lidds, cbds = m.load(a.lidds_alarms), m.load(a.cbds_alarms)
    dirs = dict(scores=a.scores, tokens=a.tokens)
    lid = {s: Scenario(s, dirs) for s in sorted(lidds['scenarios'])}
    cb = {'CB-DS': Scenario('CB-DS', dirs)}
    dev, dev_per = m.score(lid, lidds, m.CORE, ALPHA, 'development')
    c, _ = m.score(cb, cbds, m.CORE, ALPHA, 'all')
    out = dict(schema='pulse-lidds-ml-v4', protocol='sentinel_pulse/protocol/lidds-ml-v4.json', alpha=ALPHA, shares=SHARES,
               development=dev, development_scenarios=dev_per, cbds=c)
    for name, got, want in (('development', dev, GATE), ('CB-DS', c, GATE_CB)):
        for k, v in want.items():
            if got[k] != v:
                raise SystemExit(f'gate: {name} {k} = {got[k]}, registered {v}')
    if a.official:
        p, per = m.score(lid, lidds, m.CORE, ALPHA, 'official')
        out['official'] = dict(pooled=p, scenarios=per)
        out['criteria'] = dict(recall=p['recall'] >= m.CRITERIA['recall'], precision_base_rate=(p['precision_base_rate'] or 0) >= m.CRITERIA['precision_base_rate'],
                               latency_p95=p['latency_p95'] is not None and p['latency_p95'] <= m.CRITERIA['latency_p95'])
        t, _ = m.score(lid, lidds, ('T',), ALPHA * SHARES['T'], 'official')
        out['token_alone_official_reported'] = t
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    for k in ('scores', 'tokens', 'lidds-alarms', 'cbds-alarms', 'output'):
        ap.add_argument('--' + k, required=True)
    ap.add_argument('--official', action='store_true')
    a = ap.parse_args()
    if a.official and Path(a.output).exists():
        raise SystemExit(f'{a.output} exists: the official split is scored once')
    out = run(a)
    Path(a.output).write_text(json.dumps(out, indent=1, default=float))
    print(json.dumps({k: {x: out[k][x] for x in ('recall', 'detected', 'attack_recordings', 'false_alarm_rate', 'false_alarm_recordings', 'latency_p95', 'detected_within_3s')}
                      for k in ('development', 'cbds')}, indent=1, default=float))
    if a.official:
        print(json.dumps(dict(official=out['official']['pooled'], criteria=out['criteria'], token_alone=out['token_alone_official_reported']), indent=1, default=float))


if __name__ == '__main__':
    main()
