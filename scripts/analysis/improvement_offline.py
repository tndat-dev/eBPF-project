#!/usr/bin/env python3
"""Offline directions of protocol improvement-round-v1 (D4 ensemble, D14 Kneser-Ney, D15 CUSUM, D16 pooled-shape GEV).

Every candidate is a decision system over stored window scores (columns of lidds_token_study.score_scenario: window_end,
top3, top5, top10, ...) and is judged on three sets, as the protocol registers:
  - LID-DS 2021 development (token-design-study caches) and CB-DS: must keep >= 529/544 with <= 6 false alarms (p95 <= 1.60 s)
    and CB-DS >= 891 with <= 3 (amendment 1 of lidds2019-development-v1, the rule lidds-ml-v5-t3 was chosen under);
  - LID-DS 2019 development (lidds2019_dev.py caches), registered exploit time and the 1 s label tolerance;
  - the reference is lidds-ml-v5-t3 (top 3, trim 0.005, alpha' 0.0003) on the same scores.
A threshold is always fitted on the held-out learning recordings of the scenario (val/<name>, 5-fold cross-fit), never on
test recordings.

    python3 improvement_offline.py score-kn --caches DIR --out DIR [--jobs 4]          # Kneser-Ney scores (spec kn-n4)
    python3 improvement_offline.py evaluate --scores2021 DIR --scores2019 DIR --caches2019 DIR \
        --lidds-alarms a.json.gz --cbds-alarms c.json.gz --output out.json
"""
# CÁC HƯỚNG OFFLINE CỦA VÒNG CẢI THIỆN: ghép top 3 + top 10 (D4), làm mượt Kneser-Ney (D14), CUSUM tích luỹ bằng chứng
# yếu (D15), ngưỡng GEV gộp hình dạng (D16). Mỗi hệ đều chấm trên LID-DS 2021 development + CB-DS và 2019 development.
import argparse
from collections import Counter, defaultdict
import json
import math
from multiprocessing import Pool
from pathlib import Path
import sys

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
import lidds2019_dev as dev  # noqa: E402
import lidds2019_token as l19  # noqa: E402
import lidds_ml_v2 as m  # noqa: E402
import lidds_ml_v4 as v4  # noqa: E402
import lidds_token_study as st  # noqa: E402
import lidds_v3_combine as v3  # noqa: E402
from sentinel_pulse.detector.token_model import CountTokenLM  # noqa: E402

T3 = dict(col='top3', trim=0.005, alpha=0.0003)                 # lidds-ml-v5-t3
MUST21 = dict(detected=529, false_alarm_recordings=6, latency_p95=1.60, cb_detected=891, cb_false_alarm_recordings=3)


# ------------------------------------------------------------------ D14: interpolated Kneser-Ney

class KNTokenLM(CountTokenLM):
    """CountTokenLM with interpolated Kneser-Ney in place of Witten-Bell: absolute discount D_k = n1 / (n1 + 2 n2) per
    order, continuation counts for every order below the highest, the same base P0 (name x variant, add-half)."""

    def finalize(self):
        super().finalize()
        top = self.n - 1
        self.cont = [None] * self.n
        for k in range(1, top):
            cont = defaultdict(Counter)
            for h, nexts in self.count[k + 1].items():
                for w in nexts:
                    cont[h[1:]][w] += 1                    # distinct left extensions of (h[1:], w)
            self.cont[k] = cont
        self.disc, self.kstats = [0.0] * self.n, [None] * self.n
        for k in range(1, self.n):
            table = self.count[k] if k == top else self.cont[k]
            coc = Counter(c for nexts in table.values() for c in nexts.values())
            n1, n2 = coc.get(1, 0), coc.get(2, 0)
            self.disc[k] = n1 / (n1 + 2 * n2) if n1 + n2 else 0.5
            self.kstats[k] = {h: (sum(c.values()), len(c)) for h, c in table.items()}
        return self

    def prob(self, g) -> float:
        g = tuple(g[-self.n:])
        hit = self.memo.get(g)
        if hit is not None:
            return hit
        w = g[-1]
        p = self.base(w)
        top = self.n - 1
        for k in range(1, min(self.n, len(g))):
            h = g[-1 - k:-1]
            # the highest order of THIS gram uses raw counts (a short gram at a thread start is its own highest order)
            raw = k == top or k == len(g) - 1
            table, stats = (self.count[k], self.stats[k]) if raw else (self.cont[k], self.kstats[k])
            st_ = stats.get(h)
            if not st_ or not st_[0]:
                continue
            tot, types = st_
            d = self.disc[k]
            p = max(table[h].get(w, 0) - d, 0.0) / tot + d * types / tot * p
        if len(self.memo) < 2_000_000:
            self.memo[g] = p
        return p


def kn_task(job):
    st.CountTokenLM = KNTokenLM                            # build() of lidds_token_study takes the class from its module
    return st.task(job)


def score_kn(caches, out, jobs):
    spec = st.base_spec(tops=[3, 5, 10])
    spec['smoothing'] = 'kneser-ney'
    d = Path(out) / 'scores' / 'kn-n4'
    d.mkdir(parents=True, exist_ok=True)
    (d / 'SPEC.json').write_text(json.dumps(dict(spec, columns=st.columns_of(spec)), indent=1))
    todo = [(str(c), spec, str(d / c.name)) for c in sorted(Path(caches).glob('*.npz'), key=lambda p: -p.stat().st_size)
            if not (d / c.name).exists()]
    with Pool(min(jobs, max(1, len(todo)))) as pool:
        for target, seconds in pool.imap_unordered(kn_task, todo, chunksize=1):
            print(f'scored {target} {seconds:.0f} s', flush=True)


# ------------------------------------------------------------------ decision systems over stored scores

class Arrays:
    """One scenario's stored scores of one spec: {'val/<name>' | '<name>': array}, columns from SPEC.json."""

    def __init__(self, path, columns):
        z = np.load(path)
        self.a = {k: z[k] for k in z.files}
        self.cols = columns

    def col(self, key, name):
        x = self.a.get(key)
        if x is None or not len(x):
            return np.zeros(0), np.zeros(0)
        return x[:, 0], x[:, self.cols.index(name)]

    def held_out(self):
        return [k for k in self.a if k.startswith('val/')]


def gumbel_threshold(maxima, trim, alpha):
    return m.threshold(v4.trimmed_gumbel(maxima, trim) if trim else m.gumbel(maxima), alpha)


def cusum(x, k):
    s, out = 0.0, np.empty(len(x))
    for i, v in enumerate(x):
        s = max(0.0, s + v - k)
        out[i] = s
    return out


class System:
    """A decision system; fit(arrays) per scenario, then firings(name) -> alarm window ends."""

    def __init__(self, kind, **kw):
        self.kind, self.kw = kind, kw

    def fit(self, arr, shape=None):
        kw, self.arr = self.kw, arr
        if self.kind == 'single':
            mx = [arr.col(k, kw['col'])[1].max() for k in arr.held_out() if len(arr.col(k, kw['col'])[1])]
            self.thr = gumbel_threshold(mx, kw['trim'], kw['alpha'])
        elif self.kind == 'or':
            for s in kw['parts']:
                s.fit(arr, shape)
        elif self.kind == 'cusum':
            vals = np.concatenate([arr.col(k, kw['col'])[1] for k in arr.held_out()])
            mx = [arr.col(k, kw['col'])[1].max() for k in arr.held_out() if len(arr.col(k, kw['col'])[1])]
            self.thr = gumbel_threshold(mx, kw['trim'], kw['alpha_shewhart'])
            self.ref = float(np.quantile(vals, kw['ref_quantile']))
            cm = [cusum(arr.col(k, kw['col'])[1], self.ref).max() for k in arr.held_out() if len(arr.col(k, kw['col'])[1])]
            self.h = gumbel_threshold(cm, kw['trim'], kw['alpha_cusum'])
        elif self.kind == 'gev':
            mx = np.sort([arr.col(k, kw['col'])[1].max() for k in arr.held_out() if len(arr.col(k, kw['col'])[1])])
            self.thr = gev_threshold(mx, shape, kw['censor'], kw['alpha'])
        return self

    def firings(self, branches, alpha, name):
        kw = self.kw
        if self.kind == 'or':
            return sorted({t for s in kw['parts'] for t in s.firings(branches, alpha, name)})
        t, x = self.arr.col(name, kw['col'])
        if not len(x):
            return []
        if self.kind in ('single', 'gev'):
            return sorted(t[x > self.thr].tolist())
        hit = (x > self.thr) | (cusum(x, self.ref) > self.h)
        return sorted(t[hit].tolist())


def gev_fit_location_scale(x, xi):
    """Location and scale of a GEV with fixed shape xi by moments (mean and variance), as the moment Gumbel at xi = 0."""
    from scipy.special import gamma as G
    mean, sd = float(np.mean(x)), float(np.std(x))            # as lidds_ml_v2.gumbel (ddof 0), so xi = 0 is that rule
    if abs(xi) < 1e-6:
        return m.gumbel(x)
    g1, g2 = G(1 - xi), G(1 - 2 * xi)
    sigma = sd * abs(xi) / math.sqrt(g2 - g1 * g1)
    return mean - sigma * (g1 - 1) / xi, sigma


def gev_threshold(maxima, xi, censor, alpha):
    x = np.sort(np.asarray(maxima, float))[:max(2, len(maxima) - censor)]
    mu, sigma = gev_fit_location_scale(x, xi)
    y = -math.log(1 - alpha)
    return mu - sigma * math.log(y) if abs(xi) < 1e-6 else mu + sigma * (y ** (-xi) - 1) / xi


def pooled_shape(arrays_by_scenario, col, censor):
    """GEV shape of the pooled per-scenario standardized held-out maxima (scipy genextreme, sign c = -xi)."""
    from scipy.stats import genextreme
    z = []
    for arr in arrays_by_scenario.values():
        mx = np.sort([arr.col(k, col)[1].max() for k in arr.held_out() if len(arr.col(k, col)[1])])
        mx = mx[:max(2, len(mx) - censor)]
        if len(mx) > 2 and np.std(mx) > 0:
            z.extend((mx - mx.mean()) / mx.std(ddof=1))
    c, _, _ = genextreme.fit(np.asarray(z))
    return float(-c)


# ------------------------------------------------------------------ evaluation

def load_dir(d):
    spec = json.loads((Path(d) / 'SPEC.json').read_text())
    return {p.stem: Arrays(p, spec['columns']) for p in sorted(Path(d).glob('*.npz'))}


def evaluate_2021(systems_of, arrays, docs, cb_docs):
    lid = {s: systems_of(s) for s in sorted(docs['scenarios']) if s in arrays}
    cb = {s: systems_of(s) for s in sorted(cb_docs['scenarios']) if s in arrays}
    dev_, _ = m.score(lid, docs, ('T',), None, 'development')
    cbm, _ = m.score(cb, cb_docs, ('T',), None, 'all')
    return dict(detected=dev_['detected'], false_alarm_recordings=dev_['false_alarm_recordings'], latency_p95=dev_['latency_p95'],
                cb_detected=cbm['detected'], cb_false_alarm_recordings=cbm['false_alarm_recordings'])


def evaluate_2019(systems_of, arrays, docs):
    sc = {s: systems_of(s) for s in sorted(docs['scenarios']) if s in arrays}
    p, _ = dev.evaluate(sc, docs)
    t, tper = dev.evaluate(sc, l19.shifted(docs, dev.TOLERANCE))
    keep = lambda r: {k: r[k] for k in ('detected', 'attack_recordings', 'false_alarm_recordings', 'normal_recordings', 'latency_p95')}
    return dict(primary=keep(p), tolerance=keep(t), scenarios={s: [v['detected'], v['attack_recordings'], v['false_alarm_recordings']] for s, v in tper.items()})


def must(r21, r19):
    return (r21['detected'] >= MUST21['detected'] and r21['false_alarm_recordings'] <= MUST21['false_alarm_recordings']
            and (r21['latency_p95'] or 0) <= MUST21['latency_p95'] and r21['cb_detected'] >= MUST21['cb_detected']
            and r21['cb_false_alarm_recordings'] <= MUST21['cb_false_alarm_recordings']
            and r19['tolerance']['false_alarm_recordings'] <= 0.01 * r19['tolerance']['normal_recordings'])


def candidates(shapes):
    c = {'t3': lambda: System('single', **T3),
         't10': lambda: System('single', col='top10', trim=0.01, alpha=0.00018)}
    for a3, a10 in ((0.00015, 0.00015), (0.0002, 0.0001), (0.0001, 0.0002), (0.0003, 0.00018), (0.0002, 0.00005)):
        c[f'D4-or-top3-{a3:g}-top10-{a10:g}'] = (lambda a3=a3, a10=a10: System('or', parts=[
            System('single', col='top3', trim=0.005, alpha=a3), System('single', col='top10', trim=0.01, alpha=a10)]))
    for q in (0.99, 0.999):
        for split in (0.5, 0.8):
            c[f'D15-cusum-q{q:g}-shewhart{split:g}'] = (lambda q=q, split=split: System(
                'cusum', col='top3', trim=0.005, ref_quantile=q, alpha_shewhart=0.0003 * split, alpha_cusum=0.0003 * (1 - split)))
    for censor in (1, 2, 3):
        for alpha in (0.0003, 0.00018):
            c[f'D16-gev-censor{censor}-alpha{alpha:g}'] = (lambda censor=censor, alpha=alpha: System(
                'gev', col='top3', censor=censor, alpha=alpha))
    return c


def evaluate(a):
    docs21, cb21 = m.load(a.lidds_alarms), m.load(a.cbds_alarms)
    docs19 = dev.inventory(a.caches2019)
    out = {}
    for spec_id in ('g-n4', 'kn-n4'):
        d21, d19 = Path(a.scores2021) / spec_id, Path(a.scores2019) / spec_id
        if not (d21 / 'SPEC.json').exists() or not (d19 / 'SPEC.json').exists():
            continue
        arr21, arr19 = load_dir(d21), load_dir(d19)
        shapes = {censor: (pooled_shape(arr21, 'top3', censor), pooled_shape(arr19, 'top3', censor)) for censor in (1, 2, 3)}
        for cid, make in candidates(shapes).items():
            if spec_id == 'kn-n4' and not cid.startswith(('t3', 't10')):
                continue                                 # D14 is judged on the plain t3 / t10 decisions
            def systems_of(arrays, which):
                def f(s):
                    sysm = make()
                    shape = shapes.get(sysm.kw.get('censor'), (None, None))[which] if sysm.kind == 'gev' else None
                    return sysm.fit(arrays[s], shape)
                return f
            r21 = evaluate_2021(systems_of(arr21, 0), arr21, docs21, cb21)
            r19 = evaluate_2019(systems_of(arr19, 1), arr19, docs19)
            name = ('D14-kn-' if spec_id == 'kn-n4' else '') + cid
            out[name] = dict(lidds2021_development=r21, lidds2019_development=r19, must=must(r21, r19))
            print(name, r21, r19['tolerance'], out[name]['must'], flush=True)
        out[f'shapes-{spec_id}'] = {str(k): v for k, v in shapes.items()}
    ref = out['t3']
    better = sorted(k for k, r in out.items() if not k.startswith('shapes') and k != 't3' and r['must'] and (
        r['lidds2019_development']['tolerance']['detected'] > ref['lidds2019_development']['tolerance']['detected']
        or (r['lidds2019_development']['tolerance']['detected'] == ref['lidds2019_development']['tolerance']['detected']
            and r['lidds2019_development']['tolerance']['false_alarm_recordings'] < ref['lidds2019_development']['tolerance']['false_alarm_recordings'])))
    doc = dict(schema='improvement-round-v1-offline', protocol='sentinel_pulse/protocol/improvement-round-v1.json (+ amendments 1, 2)',
               reference='t3 = lidds-ml-v5-t3', must=MUST21, candidates=out, better_than_t3=better)
    Path(a.output).write_text(json.dumps(doc, indent=1, default=float))
    print(json.dumps(dict(better_than_t3=better)))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest='step', required=True)
    p = sub.add_parser('score-kn')
    p.add_argument('--caches', required=True)
    p.add_argument('--out', required=True)
    p.add_argument('--jobs', type=int, default=4)
    p = sub.add_parser('evaluate')
    for k in ('--scores2021', '--scores2019', '--caches2019', '--lidds-alarms', '--cbds-alarms', '--output'):
        p.add_argument(k, required=True)
    p = sub.add_parser('official')
    for k in ('--scores', '--lidds-alarms', '--cbds-alarms', '--output'):
        p.add_argument(k, required=True)
    a = ap.parse_args()
    if a.step == 'official':
        official(a.scores, a.lidds_alarms, a.cbds_alarms, a.output)
    elif a.step == 'score-kn':
        score_kn(a.caches, a.out, a.jobs)
    else:
        evaluate(a)


if __name__ == '__main__':
    main()


def official(scores_dir, lidds_alarms, cbds_alarms, output):
    """An adopted offline candidate on LID-DS 2021 official (scores of the amendment-1 run, spec tops 3 and 10)."""
    docs21 = m.load(lidds_alarms)
    arr = load_dir(scores_dir)
    shape = pooled_shape(arr, 'top3', 1)
    systems = {'t3': lambda: System('single', **T3),
               'D16-gev-censor1-alpha0.00018': lambda: System('gev', col='top3', censor=1, alpha=0.00018),
               'D16-gev-censor1-alpha0.0003': lambda: System('gev', col='top3', censor=1, alpha=0.0003)}
    out = {}
    for name, make in systems.items():
        sc = {s: make().fit(arr[s], shape) for s in sorted(docs21['scenarios']) if s in arr}
        r, per = m.score(sc, docs21, ('T',), None, 'official')
        out[name] = dict({k: r[k] for k in ('detected', 'attack_recordings', 'false_alarm_recordings', 'normal_recordings',
                                            'latency_p50', 'latency_p95', 'recall_ci95')},
                         scenarios={s: [v['detected'], v['false_alarm_recordings']] for s, v in per.items()})
        print(name, {k: out[name][k] for k in ('detected', 'false_alarm_recordings', 'latency_p95')}, flush=True)
    doc = dict(schema='improvement-round-v1-official2021', pooled_shape_official=shape, candidates=out)
    m.write_once(output, doc)
