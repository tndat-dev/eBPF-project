#!/usr/bin/env python3
"""How little budget can tree and support get? LID-DS 2021 development and CB-DS only. Token branch alone found 530/544
with 8 false alarms on development (compare-xfit.txt): tree and support add alarms, not detections, there; on the
cluster they are the branches that see mprotect / seccomp patterns, so they stay. Token column select1f (R1) and xfit
(R1, R4); shares fixed in the grid below; 'T only' reported for comparison. Nothing selected here."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ml_v4_rules as r  # noqa: E402

m = r.m
GRID = {'T.8': (.8, .1, .1), 'T.9': (.9, .05, .05), 'T.95': (.95, .025, .025), 'T.98': (.98, .01, .01), 'T.99': (.99, .005, .005),
        'T.998': (.998, .001, .001), 'T only': (1.0, 1e-300, 1e-300)}
ALPHAS = (0.0005, 0.0002, 0.0001, 0.00005, 0.00002)
SETS = [('select1f', '/var/tmp/lid-ds-2021/ml-v3-tokens', 'R1'), ('xfit', '/var/tmp/lid-ds-2021/ml-xfit-tokens', 'R1'),
        ('xfit', '/var/tmp/lid-ds-2021/ml-xfit-tokens', 'R4')]


def main():
    lidds, cbds = m.load(r.E / 'lidds-evaluation-v2-alarms.json.gz'), m.load(r.E / 'lidds-evaluation-v2-cbds-alarms.json.gz')
    print('token rule share alpha | dev detected/544 FA/3403 p95 within3 | CB-DS det/891 FA/1410 | dev (missed, FA) where nonzero')
    for col, path, rule in SETS:
        m.set_token_column(col)
        dirs = dict(scores='/var/tmp/lid-ds-2021/ml-scores-allwin', tokens=path)
        lid = {s: m.Scenario(s, dirs) for s in sorted(lidds['scenarios'])}
        cb = {'CB-DS': m.Scenario('CB-DS', dirs)}
        for name, sh in GRID.items():
            for alpha in ALPHAS:
                levels = dict(zip(m.CORE, (alpha * x for x in sh)))
                d, per = r.evaluate(lid, lidds, rule, levels, 'development')
                c, _ = r.evaluate(cb, cbds, rule, levels, 'all')
                detail = {s: (v['attack_recordings'] - v['detected'], v['false_alarm_recordings']) for s, v in per.items()
                          if v['attack_recordings'] != v['detected'] or v['false_alarm_recordings']}
                print(f"{col:8s} {rule} {name:6s} {alpha:<7g} | {d['detected']:3d} {d['false_alarm_recordings']:3d} {d['latency_p95']:.2f} {d['within3']:3d} "
                      f"| {c['detected']:3d} {c['false_alarm_recordings']:3d} | {detail}", flush=True)


if __name__ == '__main__':
    main()
