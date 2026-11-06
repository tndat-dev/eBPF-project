#!/usr/bin/env python3
"""Pulse's ML with the enriched token language model (protocol lidds-ml-v2), from raw scores.

Branches: the token model (lidds_ml_tokens.py, every window with events) and the current ML's reference tree and
support model (lidds_ml_scores.py --all-windows). A branch's threshold is the moment-Gumbel quantile of the per-recording
maximum score over the validation recordings, at alpha / number of branches; one window above it fires, with no
tripwire, novelty gate or vote. An attack recording is detected when a window ending after the exploit fires (latency
= its end minus the exploit time); a normal recording with any firing is a false alarm.

Selection reads development only. Without --official nothing of the official split is computed; with it the output
file must not exist yet, so the official split is scored once.

    python3 lidds_ml_v2.py --scores DIR --tokens DIR --lidds-alarms a.json.gz --cbds-alarms c.json.gz --output out.json [--official]

lidds-ml-v3 is the same rule with another token alphabet: --tokens points at lidds_ml_token_alphabets.py output and
--token-column names the alphabet (select1f), --protocol names the registered protocol.
"""
import argparse
import gzip
import json
import math
from pathlib import Path
import sys

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lidds_v3_combine as v3  # noqa: E402

BRANCH = {'T': ('tokens', 'top10'), 'tree': ('scores', 'tree_plain'), 'support': ('scores', 'support')}
LOGIT = {'tree_plain'}
CORE = ('T', 'tree', 'support')
ALPHAS = (0.001, 0.0005, 0.0002)
CANDIDATES = {f"T+tree+support|a{a:g}": (CORE, a) for a in ALPHAS}
COMPARATORS = {'token model alone (reported only)': (('T',), 0.002), 'current ML branches (reported only)': (('tree', 'support'), 0.001)}
DEV_FA, DEV_P95, CB_RECALL, CB_FA = 0.006, 3.0, 0.95, 0.02
CRITERIA = dict(recall=0.95, precision_base_rate=0.95, latency_p95=3.0)


def transform(column, x):
    x = np.asarray(x, float)
    if column in LOGIT:
        c = np.clip(x, 1e-4, 1 - 1e-4)
        return np.log(c / (1 - c))
    return x


def gumbel(maxima):
    beta = max(float(np.std(maxima)) * math.sqrt(6) / math.pi, 1e-6)
    return float(np.mean(maxima)) - 0.5772 * beta, beta


def threshold(fit, alpha):
    return fit[0] - fit[1] * math.log(-math.log(1 - alpha))


class Scenario:
    def __init__(self, name, dirs):
        self.branch = {}
        for b, (src, col) in BRANCH.items():
            meta = json.loads((Path(dirs[src]) / f'{name}.json').read_text())
            i, end = meta['columns'].index(col), meta['columns'].index('window_end')
            z = np.load(Path(dirs[src]) / f'{name}.npz')
            maxima = [transform(col, z[k][:, i]).max() for k in z.files if k.startswith('val/') and len(z[k])]
            self.branch[b] = (z, col, i, end, gumbel(maxima))

    def firings(self, branches, alpha, name):
        """Window ends at which any branch exceeds its threshold."""
        out = []
        for b in branches:
            z, col, i, end, fit = self.branch[b]
            if name in z.files and len(z[name]):
                a = z[name]
                out.extend(a[transform(col, a[:, i]) > threshold(fit, alpha / len(branches)), end].tolist())
        return sorted(out)


def rows(scn, recs, branches, alpha, wanted):
    """{name: (split, detected, latency, false_alarm, subset)} for the recordings ``wanted`` selects."""
    out = {}
    for name, r in recs.items():
        if not wanted(name, r):
            continue
        fire, ex = scn.firings(branches, alpha, name), r['exploit']
        after = [t for t in fire if ex is not None and t > ex]
        out[name] = (r['split'], bool(after), after[0] - ex if after else None, bool(fire) if ex is None else any(t <= ex for t in fire), r['subset'])
    return out


def part_filter(scenario, recs, part):
    """Same parts as lidds-evaluation-v3; official recordings are not even scored when only development is wanted."""
    dev_normals = v3.normal_dev(scenario, [n for n, r in recs.items() if r['split'] == 'test-normal'])

    def wanted(name, r):
        if part == 'all':
            return True
        if r['split'] == 'test-normal':
            return (name in dev_normals) == (part == 'development')
        return r['subset'] == part
    return wanted


def score(scenarios, docs, branches, alpha, part):
    pooled, per = [], {}
    for s, scn in scenarios.items():
        recs = docs['scenarios'][s]['alarms']
        r = list(rows(scn, recs, branches, alpha, part_filter(s, recs, part)).values())
        per[s] = v3.metrics(r)
        pooled.extend(r)
    m = v3.metrics(pooled)
    m['detected_within_3s'] = sum(1 for x in pooled if x[0] == 'test-normal_and_attack' and x[2] is not None and x[2] <= 3.0)
    return m, per


def select(results):
    ok = [r for r in results if r['eligible']]
    if ok:
        return max(ok, key=lambda r: (r['development']['detected'], -r['development']['false_alarm_recordings'])), True
    fallback = [r for r in results if r['development']['false_alarm_rate'] <= DEV_FA] or results
    return max(fallback, key=lambda r: (r['development']['detected'], -r['development']['false_alarm_recordings'])), False


def set_token_column(column):
    """The token branch reads this column of the token matrices (top10 for lidds-ml-v2, an alphabet name for v3)."""
    BRANCH['T'] = ('tokens', column)


def run(lidds, cbds, score_dir, token_dir, official, scenarios=None, cb_name='CB-DS', protocol='sentinel_pulse/protocol/lidds-ml-v2.json'):
    dirs = dict(scores=score_dir, tokens=token_dir)
    names = scenarios or sorted(lidds['scenarios'])
    lid = {s: Scenario(s, dirs) for s in names}
    cb = {cb_name: Scenario(cb_name, dirs)}
    results = []
    for cfg, (branches, alpha) in CANDIDATES.items():
        dev, per = score(lid, lidds, branches, alpha, 'development')
        c, _ = score(cb, cbds, branches, alpha, 'all')
        ok = (dev['false_alarm_rate'] <= DEV_FA and dev['latency_p95'] is not None and dev['latency_p95'] <= DEV_P95
              and c['recall'] >= CB_RECALL and c['false_alarm_rate'] <= CB_FA)
        results.append(dict(config=cfg, eligible=ok, development=dev, development_scenarios=per, cbds=c))
    chosen, qualified = select(results)
    out = dict(schema='pulse-lidds-ml-v2', protocol=protocol, token_branch=BRANCH['T'], qualified=qualified, selected=chosen, screening=results)
    if official:
        branches, alpha = CANDIDATES[chosen['config']]
        m, per = score(lid, lidds, branches, alpha, 'official')
        out['official'] = dict(pooled=m, scenarios=per)
        out['criteria'] = dict(recall=m['recall'] >= CRITERIA['recall'], precision_base_rate=(m['precision_base_rate'] or 0) >= CRITERIA['precision_base_rate'],
                               latency_p95=m['latency_p95'] is not None and m['latency_p95'] <= CRITERIA['latency_p95'])
        out['comparators_official'] = {k: score(lid, lidds, b, a, 'official')[0] for k, (b, a) in COMPARATORS.items()}
    return out


def write_once(path, doc):
    if Path(path).exists():
        raise FileExistsError(f'{path} exists: the official split is scored once')
    Path(path).write_text(json.dumps(doc, indent=1, default=float))


def load(path):
    return json.load(gzip.open(path, 'rt'))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--scores', required=True)
    ap.add_argument('--tokens', required=True)
    ap.add_argument('--lidds-alarms', required=True)
    ap.add_argument('--cbds-alarms', required=True)
    ap.add_argument('--output', required=True)
    ap.add_argument('--official', action='store_true')
    ap.add_argument('--token-column', default='top10')
    ap.add_argument('--protocol', default='sentinel_pulse/protocol/lidds-ml-v2.json')
    a = ap.parse_args()
    set_token_column(a.token_column)
    if a.official and Path(a.output).exists():
        raise SystemExit(f'{a.output} exists: the official split is scored once')
    out = run(load(a.lidds_alarms), load(a.cbds_alarms), a.scores, a.tokens, a.official, protocol=a.protocol)
    (write_once(a.output, out) if a.official else Path(a.output).write_text(json.dumps(out, indent=1, default=float)))
    brief = lambda m: {k: m[k] for k in ('recall', 'detected', 'attack_recordings', 'false_alarm_rate', 'false_alarm_recordings', 'precision_base_rate', 'latency_p50', 'latency_p95')}
    print(json.dumps(dict(qualified=out['qualified'], selected=out['selected']['config'], development=brief(out['selected']['development']),
                          cbds=brief(out['selected']['cbds']), screening={r['config']: (r['eligible'], brief(r['development'])) for r in out['screening']},
                          official=out.get('official') and brief(out['official']['pooled']), criteria=out.get('criteria')), indent=1, default=float))


if __name__ == '__main__':
    main()
