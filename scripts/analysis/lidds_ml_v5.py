#!/usr/bin/env python3
"""lidds-ml-v5 (sentinel_pulse/protocol/lidds-ml-v5.json): lidds-ml-v4 with a gate on the token branch and optionally without the
tree and support branches. A token alarm then also needs the window's pool score above a threshold fitted on normal, and the
window more than `hold` seconds after the recording's last execve. Tree and support thresholds are as lidds-ml-v4.

Without --official nothing of the official split is read. --official NAME scores one registered candidate; the output
file must not exist.

    python3 lidds_ml_v5.py --scores DIR --tokens DIR --pool DIR --lidds-alarms a.json.gz --cbds-alarms c.json.gz --output out.json [--official NAME]
"""
import argparse
import json
from pathlib import Path
import sys

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lidds_ml_v2 as m  # noqa: E402
import lidds_ml_v4 as v4  # noqa: E402

ALPHA = v4.ALPHA
HOLDS = (0.0, 1.0, 2.0)
POOL_LEVELS = (None, 1e-2, 1e-3, ALPHA * v4.SHARES['T'])
SYSTEMS = dict(three=('T', 'tree', 'support'), token=('T',))
KEEP = dict(detected=530, false_alarm_recordings=12, latency_p95=1.52, cb_detected=891, cb_false_alarm_recordings=3)


def held_mask(ends, execve, hold):
    """True for windows at most `hold` seconds after the recording's last execve (the window itself included)."""
    held, last = np.zeros(len(ends), bool), -np.inf
    if not hold:
        return held
    for i in np.argsort(ends):
        if execve[i]:
            last = ends[i]
        held[i] = ends[i] - last <= hold
    return held


def pool_fit(z, hold):
    maxima = []
    for k in z.files:
        if k.startswith('val/') and len(z[k]):
            a = z[k]
            kept = a[~held_mask(a[:, 0], a[:, 2], hold), 1]
            if len(kept):
                maxima.append(kept.max())
    return v4.trimmed_gumbel(maxima)


class Scenario(v4.Scenario):
    def __init__(self, name, dirs):
        super().__init__(name, dirs)
        self.pool = np.load(Path(dirs['pool']) / f'{name}.npz')
        self.fits = {}
        self.gate = (None, 0.0)

    def set_gate(self, level, hold):
        self.gate = (level, hold)
        if level is not None and hold not in self.fits:
            self.fits[hold] = pool_fit(self.pool, hold)

    def firings(self, branches, alpha, name):
        out = []
        level, hold = self.gate
        for b in branches:
            z, col, i, end, fit = self.branch[b]
            if name not in z.files or not len(z[name]):
                continue
            a = z[name]
            share = v4.SHARES[b] if len(branches) > 1 else 1.0
            fire = m.transform(col, a[:, i]) > m.threshold(fit, alpha * share)
            if b == 'T' and (level is not None or hold):
                g = self.pool[name]
                if len(g) != len(a) or not np.array_equal(g[:, 0], a[:, end]):
                    raise ValueError(f'{name}: pool and token windows differ')
                fire = fire & ~held_mask(g[:, 0], g[:, 2], hold)
                if level is not None:
                    fire = fire & (g[:, 1] > m.threshold(self.fits[hold], level))
            out.extend(a[fire, end].tolist())
        return sorted(out)


def candidates():
    for system, branches in SYSTEMS.items():
        for hold in HOLDS:
            for level in POOL_LEVELS:
                yield f"{system}-hold{hold:g}-pool{'none' if level is None else f'{level:g}'}", branches, hold, level


def alpha_of(branches):
    return ALPHA * (v4.SHARES['T'] if len(branches) == 1 else 1.0)


def apply(scenarios, hold, level):
    for s in scenarios.values():
        s.set_gate(level, hold)


def run(a):
    m.set_token_column('xfit')
    lidds, cbds = m.load(a.lidds_alarms), m.load(a.cbds_alarms)
    dirs = dict(scores=a.scores, tokens=a.tokens, pool=a.pool)
    lid = {s: Scenario(s, dirs) for s in sorted(lidds['scenarios'])}
    cb = {'CB-DS': Scenario('CB-DS', dirs)}
    rows = {}
    for name, branches, hold, level in candidates():
        apply(lid, hold, level)
        apply(cb, hold, level)
        dev, _ = m.score(lid, lidds, branches, alpha_of(branches), 'development')
        c, _ = m.score(cb, cbds, branches, alpha_of(branches), 'all')
        keeps = (dev['detected'] >= KEEP['detected'] and dev['false_alarm_recordings'] <= KEEP['false_alarm_recordings']
                 and (dev['latency_p95'] or 0) <= KEEP['latency_p95'] and c['detected'] >= KEEP['cb_detected']
                 and c['false_alarm_recordings'] <= KEEP['cb_false_alarm_recordings'])
        rows[name] = dict(development=dev, cbds=c, keeps_v4=keeps)
        print(f"{name:32s} dev {dev['detected']}/{dev['attack_recordings']} fa {dev['false_alarm_recordings']} p95 {dev['latency_p95']:.2f} "
              f"3s {dev['detected_within_3s']} | cb {c['detected']}/{c['attack_recordings']} fa {c['false_alarm_recordings']} | keeps {keeps}", flush=True)
    base = rows['three-hold0-poolnone']['development']
    if (base['detected'], base['false_alarm_recordings']) != (v4.GATE['detected'], v4.GATE['false_alarm_recordings']):
        raise SystemExit(f"gate: without a gate the scorer gives {base['detected']}, {base['false_alarm_recordings']}, not lidds-ml-v4")
    out = dict(schema='pulse-lidds-ml-v5', protocol='sentinel_pulse/protocol/lidds-ml-v5.json', candidates=rows)
    if a.official:
        branches, hold, level = next((b, h, l) for n, b, h, l in candidates() if n == a.official)
        apply(lid, hold, level)
        p, per = m.score(lid, lidds, branches, alpha_of(branches), 'official')
        out['official'] = dict(candidate=a.official, pooled=p, scenarios=per)
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    for k in ('scores', 'tokens', 'pool', 'lidds-alarms', 'cbds-alarms', 'output'):
        ap.add_argument('--' + k, required=True)
    ap.add_argument('--official')
    a = ap.parse_args()
    if a.official and Path(a.output).exists():
        raise SystemExit(f'{a.output} exists')
    out = run(a)
    Path(a.output).write_text(json.dumps(out, indent=1, default=float))
    if a.official:
        print(json.dumps(out['official']['pooled'], indent=1, default=float))


if __name__ == '__main__':
    main()
