#!/usr/bin/env python3
"""burst-round-v1 metric: held-out 60 s block exceedance per regime on the blocks of capture
pulse-token-capture-diurnal2-1124 only (so added burst-heavy data does not dilute the pooled share), with t3 and A6
thresholds of a fit directory (token/MODELS.json, token/FIT.json, maxima/, a6-scale.json), Wilson 95 % intervals, and
the registered rules against a baseline output of this script.

    burst_round.py --fit-dir FIT --capture CAPTURE1124 --output OUT.json [--baseline BASE.json]
"""
# CHỈ SỐ VÒNG BURST: tỉ lệ khối 60 s giữ ra vượt ngưỡng theo chế độ tải, chỉ trên khối của capture 1124, so với baseline.
import argparse
import hashlib
import json
import math
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
ALPHA = 0.0003


def wilson(k, n, z=1.96):
    if not n:
        return [0.0, 0.0]
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return [max(0.0, c - h), min(1.0, c + h)]


def shares(blocks, thr, regime):
    """{regime: [blocks, above]} over blocks [(workload, block index, score)]."""
    per = {}
    for w, b, v in blocks:
        r = per.setdefault(regime(b * 60.0), [0, 0])
        r[0] += 1
        r[1] += v > thr[w]
    return per


def summary(per):
    n = sum(x[0] for x in per.values())
    k = sum(x[1] for x in per.values())
    return dict(pooled=k / n, pooled_ci=wilson(k, n), blocks=n, above=k,
                regimes={r: dict(blocks=x[0], above=x[1], share=x[1] / x[0], ci=wilson(x[1], x[0]))
                         for r, x in sorted(per.items())},
                burst_ratio=(per['burst'][1] / per['burst'][0]) / (k / n))


def rules(cur, base):
    """burst-round-v1 'must' on the A6 shares (cluster attacks are checked separately)."""
    a, b = cur['A6'], base['A6']
    burst = a['regimes']['burst']['share']
    other = {r: a['regimes'][r]['share'] <= b['regimes'][r]['share'] + 0.001
             for r in a['regimes'] if r != 'burst'}
    return dict(burst_ratio=a['burst_ratio'] <= 3.0, burst_below=burst < b['regimes']['burst']['share'],
                other_regimes=all(other.values()), other_by_regime=other, pooled=a['pooled'] <= b['pooled'])


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--fit-dir', type=Path, required=True)
    ap.add_argument('--capture', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--baseline', type=Path)
    a = ap.parse_args()
    from sentinel_pulse.detector.load_threshold import threshold
    models = json.loads((a.fit_dir / 'token' / 'MODELS.json').read_text())
    fits = json.loads((a.fit_dir / 'token' / 'FIT.json').read_text())['workloads']
    scale = json.loads((a.fit_dir / 'a6-scale.json').read_text())
    sched = json.loads((a.capture / 'CONFIG.json').read_text())['traffic_schedule'][:-1]
    lo, hi = sched[0]['start'], sched[-1]['end']
    regime = lambda t: next((p['regime'] for p in sched if p['start'] <= t < p['end']), None)
    blocks = []
    for w in models:
        doc = json.loads((a.fit_dir / 'maxima' / (hashlib.sha256(w.encode()).hexdigest()[:16] + '.maxima.json')).read_text())
        blocks += [(w, b, v) for _, _, b, v in doc['blocks'] if lo <= b * 60.0 < hi]
    thr = {'t3': {w: models[w]['threshold'] for w in models},
           'A6': {w: threshold(fits[w]['gumbel'], ALPHA * scale[w]) if scale[w] < 1 else models[w]['threshold']
                  for w in models}}
    out: dict = dict(schema='burst-round-v1-metric', fit=str(a.fit_dir), capture=str(a.capture))
    for name in ('t3', 'A6'):
        out[name] = summary(shares(blocks, thr[name], regime))
        s = out[name]
        print(name, 'pooled %.3f%%' % (100 * s['pooled']),
              {r: '%.2f%% (%d/%d)' % (100 * x['share'], x['above'], x['blocks']) for r, x in s['regimes'].items()},
              'burst/pooled %.2f' % s['burst_ratio'], flush=True)
    if a.baseline:
        out['rules'] = rules(out, json.loads(a.baseline.read_text()))
        print('rules', json.dumps(out['rules']))
    a.output.write_text(json.dumps(out, indent=1))


if __name__ == '__main__':
    main()
