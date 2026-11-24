#!/usr/bin/env python3
"""improvement-round-2 (sentinel_pulse/protocol/improvement-round-2.json): dataset step of the scoring candidates.

t3 (reference, must reproduce 529/544 with 5, CB-DS 891/3, 2019 development 310/321 with 9), A2_mask, A3_distinct,
A2_A3 (new score caches from the fact caches), A4_persist (the t3 score caches, persistence score min(s_t, s_t-1) of
consecutive 0.5 s windows), A5_kneser_ney (the kn-n4 score caches); all at top 3, trim 0.005, alpha' 0.0003.

    python3 improvement_round2.py datasets --out /var/tmp/lid-ds-2019-v2/development \
        --caches21 /var/tmp/lid-ds-2021/token-study/cache --lidds-alarms A --cbds-alarms C --output datasets.json [--jobs 4]
"""
# Vòng cải thiện 2, phần dataset: chấm các ứng viên đổi cách tính điểm trên development (LID-DS 2021, CB-DS, 2019).
import argparse
import json
from pathlib import Path
import sys
from types import SimpleNamespace

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import lidds2019_dev as d19  # noqa: E402
import lidds2019_token as l19  # noqa: E402
import lidds_ml_v2 as m  # noqa: E402
import lidds_token_study as st  # noqa: E402

ALPHA, TRIM, TOP = 0.0003, 0.005, 3
MASK = ['futex', 'sched_yield', 'rt_sigreturn', 'sigreturn']
SPECS = {'r2-mask': dict(mask_calls=MASK), 'r2-distinct': dict(distinct=True), 'r2-mask-distinct': dict(mask_calls=MASK, distinct=True)}
WINDOW = 0.5


class Persist(st.TokenScenario):
    """A4: the score of a window is min(its score, the previous window's) when the two are consecutive, else 0."""

    def __init__(self, path, column, columns, trim):
        super().__init__(path, column, columns, trim)
        for k, a in self.a.items():
            if not len(a):
                continue
            a = a[np.argsort(a[:, 0], kind='stable')].copy()
            s = a[:, self.i]
            prev = np.r_[0.0, s[:-1]]
            consecutive = np.r_[False, np.abs(np.diff(a[:, 0]) - WINDOW) < 1e-3]
            a[:, self.i] = np.where(consecutive, np.minimum(s, prev), 0.0)
            self.a[k] = a
        self.maxima = np.asarray([a[:, self.i].max() for k, a in self.a.items() if k.startswith('val/') and len(a)])
        self.fit = st.fit_gumbel(self.maxima, trim)


def make(scores_dir, cls=st.TokenScenario):
    cols = json.loads((Path(scores_dir) / 'SPEC.json').read_text())['columns']
    return lambda s: cls(Path(scores_dir) / f'{s}.npz', f'top{TOP}', cols, TRIM)


def lidds2021(out21, sid, alarms, cls=st.TokenScenario):
    a = SimpleNamespace(out=str(out21), docs=(m.load(alarms[0]), m.load(alarms[1])))
    s = st.Scored(a, sid, f'top{TOP}', TRIM)
    mk = make(Path(out21) / 'scores' / sid, cls)
    s.lid = {k: mk(k) for k in s.lid}
    s.cb = {k: mk(k) for k in s.cb}
    r = s.metrics(ALPHA)
    return dict(detected=r['detected'], false_alarm_recordings=r['false_alarm_recordings'], latency_p95=r['latency_p95'],
                cb_detected=r['cb_detected'], cb_false_alarm_recordings=r['cb_false_alarm_recordings'])


def lidds2019(caches, scores_dir, cls=st.TokenScenario):
    docs = d19.inventory(caches)
    mk = make(scores_dir, cls)
    scen = {s: d19.Fixed(mk(s), ALPHA) for s in sorted(docs['scenarios'])}
    t, _ = d19.evaluate(scen, l19.shifted(docs, d19.TOLERANCE))
    return dict(detected=t['detected'], false_alarm_recordings=t['false_alarm_recordings'], latency_p95=t['latency_p95'])


def must(r21, r19):
    return bool(r21['detected'] >= 529 and r21['false_alarm_recordings'] <= 5 and round(r21['latency_p95'], 1) <= 1.6
                and r21['cb_detected'] >= 891 and r21['cb_false_alarm_recordings'] <= 3
                and r19['detected'] >= 310 and r19['false_alarm_recordings'] <= 9)


def datasets(a):
    out = Path(a.out)
    a21 = SimpleNamespace(caches=a.caches21, out=str(out / 'lidds2021'), jobs=a.jobs)
    a19 = SimpleNamespace(caches=str(out / 'caches'), out=str(out), jobs=a.jobs)
    specs = {sid: st.base_spec(tops=[TOP], **opts) for sid, opts in SPECS.items()}
    st.ensure(a21, specs)
    st.ensure(a19, specs)
    alarms = (a.lidds_alarms, a.cbds_alarms)
    plan = dict(t3=('g-n4', st.TokenScenario), A2_mask=('r2-mask', st.TokenScenario), A3_distinct=('r2-distinct', st.TokenScenario),
                A2_A3=('r2-mask-distinct', st.TokenScenario), A4_persist=('g-n4', Persist), A5_kneser_ney=('kn-n4', st.TokenScenario))
    rows = {}
    for cid, (sid, cls) in plan.items():
        r21 = lidds2021(out / 'lidds2021', sid, alarms, cls)
        r19 = lidds2019(out / 'caches', out / 'scores' / sid, cls)
        rows[cid] = dict(lidds2021_development=r21, lidds2019_development=r19, must=must(r21, r19))
        print(cid, json.dumps(rows[cid], default=float), flush=True)
    t = rows['t3']
    gate = (t['lidds2021_development']['detected'], t['lidds2021_development']['false_alarm_recordings'],
            t['lidds2021_development']['cb_detected'], t['lidds2021_development']['cb_false_alarm_recordings'],
            t['lidds2019_development']['detected'], t['lidds2019_development']['false_alarm_recordings']) == (529, 5, 891, 3, 310, 9)
    if not gate:
        raise SystemExit(f't3 is not reproduced: {t}')
    Path(a.output).write_text(json.dumps(dict(schema='improvement-round-2-datasets', gate_t3=gate, mask=MASK, candidates=rows),
                                          indent=1, default=float))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest='cmd', required=True)
    d = sub.add_parser('datasets')
    for k in ('out', 'caches21', 'lidds-alarms', 'cbds-alarms', 'output'):
        d.add_argument('--' + k, required=True)
    d.add_argument('--jobs', type=int, default=4)
    a = ap.parse_args()
    dict(datasets=datasets)[a.cmd](a)


if __name__ == '__main__':
    main()
