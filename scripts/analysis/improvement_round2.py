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


# ------------------------------------------------------------------ cluster: intervals of a live run (S1a variants)

def read_windows(job):
    """Interval windows (spans extended 1 s back for persistence) of one tokens.jsonl: [(key, end, grams, session)]."""
    path, spans = job
    import live_attribution as la
    from sentinel_pulse.common import open_sealed
    pods, out = {k[0] for k in spans}, []
    with open_sealed(Path(path)) as stream:
        for line in stream:
            pod = la._field(line, 'pod_uid')
            if pod not in pods:
                continue
            key = (pod, la._field(line, 'container_name'))
            end = float(la._field(line, 'window_end'))
            if any(a - 1.0 <= end <= b for a, b in spans.get(key, ())):
                row = json.loads(line)
                out.append((key, end, row['grams'], row.get('session') or []))
    return out


def collect(run_root, trials, jobs):
    import live_attribution as la
    from multiprocessing import Pool
    spans = la.spans_of(trials)
    files = [str(p) for p in sorted(Path(run_root).glob('workers/*/segments/*/tokens.jsonl*'))]
    windows = {}
    with Pool(jobs) as pool:
        for rows in pool.imap_unordered(read_windows, [(f, spans) for f in files], chunksize=1):
            for key, end, g, sess in rows:
                windows.setdefault(key, []).append((end, g, sess))
    for v in windows.values():
        v.sort(key=lambda x: x[0])
    return windows


def eligible(trials):
    """The trials S1a is judged on (their pair has an attack) and the attack trial of each pair."""
    attack_pairs = {t['pair']: t for t in trials if t['label'] == 'attack'}
    return [(i, t) for i, t in enumerate(trials) if t['pair'] in attack_pairs], attack_pairs


def native_hits(trials, windows, native, persist=False):
    """{trial index: end of the first window from the trial start (up to HORIZON) whose native part exceeds the
    workload's threshold, or None}; with persist the score is min(s_t, s_t-1) of consecutive windows. Trials of a
    workload without a native model are left out (as before). It does not depend on the session model, so B1 computes
    it once."""
    import live_attribution as la
    from native_stream import native_of
    out = {}
    for i, t in eligible(trials)[0]:
        if t['workload'] not in native:
            continue
        lm, thr = native[t['workload']]
        prev_end, prev, first = None, 0.0, None
        for end, g, sess in windows.get(t['key'], ()):
            if end > t['start'] + la.HORIZON:
                break
            nat = native_of(g, sess)
            s = lm.window_score(nat) if nat else 0.0
            p = (min(s, prev) if prev_end is not None and abs(end - prev_end - 0.5) < 1e-3 else 0.0) if persist else s
            prev_end, prev = end, s
            if end >= t['start'] and p > thr:
                first = end
                break
        out[i] = first
    return out


def session_hit(t, windows, session_lm, session_thr, before=None):
    """End of the first window from the trial start (up to HORIZON, and before `before`) whose session part exceeds
    the session threshold, or None."""
    import live_attribution as la
    for end, g, sess in windows.get(t['key'], ()):
        if end > t['start'] + la.HORIZON or (before is not None and end >= before):
            break
        if end >= t['start'] and sess and session_lm.window_score(sess) > session_thr:
            return end
    return None


def tally(trials, firsts):
    """(counts per label set, primary attack latencies) from {trial index: first alarm end or None}."""
    import live_attribution as la
    attack_pairs = eligible(trials)[1]
    counts, latency = {}, []
    for i, first in sorted(firsts.items()):
        t = trials[i]
        pair = attack_pairs[t['pair']]
        pad = pair.get('pad') or 0
        sets = [f"{t['label']}-pad{pad}"] if pad else [t['label']] + ([f"{t['label']}-primary"] if pair['rate'] in la.PRIMARY else [])
        if not pad and t['label'] == 'attack':
            sets.append(f"attack-rate-{pair['rate']}")
        for name in sets:
            c = counts.setdefault(name, [0, 0])
            c[0] += first is not None
            c[1] += 1
        if first is not None and t['label'] == 'attack' and not pad and pair['rate'] in la.PRIMARY:
            latency.append(first - (t.get('kernel') or t['start']))
    return counts, latency


def with_session(trials, windows, nhits, session_lm, session_thr, keep=None):
    """{trial index: first alarm} of S1a: the native hit, or an earlier session hit. keep(t) limits the trials."""
    out = {}
    for i, nat in nhits.items():
        t = trials[i]
        if keep and not keep(t):
            continue
        sess = session_hit(t, windows, session_lm, session_thr, before=nat)
        out[i] = sess if sess is not None else nat
    return out


def evaluate_system(trials, windows, native, session_lm, session_thr, persist=False):
    """S1a flags per label set: native part by native[w] = (lm, threshold) OR session part by the session model;
    with persist the native score is min(s_t, s_t-1) of consecutive windows. Returns (sets, attack latencies)."""
    nhits = native_hits(trials, windows, native, persist)
    return tally(trials, with_session(trials, windows, nhits, session_lm, session_thr))


class OverlayLM:
    """B1: the pooled session model plus extra counts, without copying or re-finalizing the pooled model. Gives the
    same probabilities as a CountTokenLM that learnt the base's windows and the extra ones (tests/test_improvement_offline.py).
    base: a finalized CountTokenLM; extra: an unfinalized CountTokenLM of the extra windows."""

    def __init__(self, base, extra):
        from sentinel_pulse.detector.token_model import CountTokenLM
        self.b, self.d, self.n = base, extra, base.n
        self.default_top, self.default_mask, self.default_distinct = base.default_top, base.default_mask, base.default_distinct
        self.total = base.total + extra.total
        self.stats = []
        for k, level in enumerate(extra.count):
            merged = {}
            for h, c in level.items():
                bc = base.count[k].get(h) or {}
                tot, types = base.stats[k].get(h, (0, 0))
                merged[h] = (tot + sum(c.values()), types + sum(1 for w in c if w not in bc))
            self.stats.append(merged)
        self.n_names = len(set(base.names) | set(extra.names))
        self.given_total, self.given_types = {}, {}
        for name in set(base.given) | set(extra.given):
            bg, dg = base.given.get(name) or {}, extra.given.get(name) or {}
            self.given_total[name] = sum(bg.values()) + sum(dg.values())
            self.given_types[name] = len(set(bg) | set(dg))
        unseen = [0.5 / (self.given_total[n] + 0.5 * (self.given_types[n] + 1)) for n in self.given_total]
        self.unseen_given = sum(unseen) / len(unseen) if unseen else 1.0
        self.memo = {}
        self.window_score = CountTokenLM.window_score.__get__(self)

    def base(self, w):
        from sentinel_pulse.detector.token_model import call_of
        name = call_of(w)
        p_name = (self.b.names.get(name, 0) + self.d.names.get(name, 0) + 0.5) / (self.total + 0.5 * (self.n_names + 1))
        if not self.given_types.get(name):
            return p_name * self.unseen_given
        c = (self.b.given.get(name) or {}).get(w, 0) + (self.d.given.get(name) or {}).get(w, 0)
        return p_name * (c + 0.5) / (self.given_total[name] + 0.5 * (self.given_types[name] + 1))

    def prob(self, g):
        g = tuple(g[-self.n:])
        hit = self.memo.get(g)
        if hit is not None:
            return hit
        w = g[-1]
        p = self.base(w)
        for k in range(1, min(self.n, len(g))):
            h = g[-1 - k:-1]
            st = self.stats[k].get(h) or self.b.stats[k].get(h)
            if not st:
                continue
            tot, types = st
            c = (self.b.count[k].get(h) or {}).get(w, 0) + (self.d.count[k].get(h) or {}).get(w, 0)
            p = (c + types * p) / (tot + types)
        if len(self.memo) < 2_000_000:
            self.memo[g] = p
        return p


def attack_criteria(counts, latency):
    r = lambda k: counts[k][0] / counts[k][1] if counts.get(k, [0, 0])[1] else None
    p95 = float(np.percentile(latency, 95)) if latency else None
    checks = dict(primary=r('attack-primary'), pad300=r('attack-pad300'), on_off=r('attack-pad-10'), rate01=r('attack-rate-0.1'),
                  rate05=r('attack-rate-0.5'), lotl=r('lotl'), eventgen=r('eventgen'), control=r('control'), p95=p95)
    ok = all((checks[k] or 0) >= 0.95 for k in ('primary', 'pad300', 'on_off', 'rate01', 'rate05', 'lotl', 'eventgen'))
    return dict(checks, passes=bool(ok and (checks['control'] or 0) <= 0.05 and p95 is not None and p95 <= 3.0))


def native_models(models_path, alpha_scale=None, fit_path=None):
    """{workload: (lm, threshold)}; alpha_scale {workload: factor} recomputes thresholds from the fit's Gumbel (A6)."""
    import live_attribution as la
    from sentinel_pulse.detector.load_threshold import threshold
    models = la.load_models(models_path)
    fits = json.loads(Path(fit_path).read_text())['workloads'] if fit_path else {}
    out = {}
    for w, (p, thr) in models.items():
        if alpha_scale and w in alpha_scale and alpha_scale[w] < 1:
            thr = threshold(fits[w]['gumbel'], ALPHA * alpha_scale[w])
        out[w] = (la.load_lm(p), thr)
    return out


def intervals(a):
    import live_attribution as la
    trials = la.live.load_trials(Path(a.run_root) / la.CAMPAIGN)
    windows = collect(a.run_root, trials, a.jobs)
    sess_models = la.load_models(a.session)
    (sp, sthr), = sess_models.values()
    session_lm = la.load_lm(sp)
    doc = dict(schema='improvement-round-2-intervals', run=a.run_root, session=a.session, systems={})
    for spec in a.system:                                     # name=MODELS.json[:persist][:a6]
        name, path, *flags = spec.split('=', 1)[0], *spec.split('=', 1)[1].split(':')
        scale = None
        if 'a6' in flags:
            scale = json.loads(Path(a.alpha_scale).read_text())
        native = native_models(path, scale, a.fit)
        counts, lat = evaluate_system(trials, windows, native, session_lm, sthr, persist='persist' in flags)
        doc['systems'][name] = dict(models=path, flags=flags, counts=counts, criteria=attack_criteria(counts, lat))
        print(name, json.dumps(doc['systems'][name]['criteria'], default=float), flush=True)
    if a.b1_runs:                                             # B1: leave-one-command-out operator sessions in the session model
        admin_grams = {}
        for run in [a.run_root] + a.b1_runs:
            tr = la.live.load_trials(Path(run) / la.CAMPAIGN)
            ws = windows if run == a.run_root else collect(run, [t for t in tr if t['label'] == 'admin'], a.jobs)
            for t in tr:
                if t['label'] != 'admin':
                    continue
                for end, g, sess in ws.get(t['key'], ()):
                    if t['start'] <= end <= t['start'] + la.HORIZON and sess:
                        admin_grams.setdefault(t['command'], []).append(sess)
        base_spec = a.system[0].split('=', 1)[1].split(':')
        scale = json.loads(Path(a.alpha_scale).read_text()) if 'a6' in base_spec[1:] else None
        native = native_models(base_spec[0], scale, a.fit)
        nhits = native_hits(trials, windows, native, persist='persist' in base_spec[1:])   # once: no session model in it
        from sentinel_pulse.detector.token_model import CountTokenLM, strip
        per = {}
        for cmd in sorted(admin_grams):
            extra = CountTokenLM(session_lm.n)
            for c, gs in admin_grams.items():
                if c != cmd:
                    for grams in gs:
                        for *g, n in grams:
                            extra.learn(strip(g), int(n))
            lm = OverlayLM(session_lm, extra)
            counts, lat = tally(trials, with_session(trials, windows, nhits, lm, sthr,
                                                     keep=lambda t: t['label'] != 'admin' or t['command'] == cmd))
            per[cmd] = dict(admin=counts.get('admin'), criteria=attack_criteria(counts, lat))
            print('B1', cmd, json.dumps(per[cmd], default=float), flush=True)
        doc['b1'] = per
    Path(a.output).write_text(json.dumps(doc, indent=1, default=float))


# ------------------------------------------------------------------ A6: per-workload alpha' from the held-out maxima

def a6(a):
    import hashlib
    from sentinel_pulse.detector.load_threshold import threshold
    fit = Path(a.fit_dir)
    models = json.loads((fit / 'token' / 'MODELS.json').read_text())
    fits = json.loads((fit / 'token' / 'FIT.json').read_text())['workloads']
    schedule = json.loads((Path(a.capture) / 'CONFIG.json').read_text())['traffic_schedule'][:-1]
    regime = lambda t: next((p['regime'] for p in schedule if p['start'] <= t < p['end']), 'outside-capture')
    blocks = {}
    for w in models:
        doc = json.loads((fit / 'maxima' / (hashlib.sha256(w.encode()).hexdigest()[:16] + '.maxima.json')).read_text())
        blocks[w] = [(b, v) for _, _, b, v in doc['blocks']]
    share = {w: sum(v > models[w]['threshold'] for _, v in bl) / len(bl) for w, bl in blocks.items()}
    pooled = sum(sum(v > models[w]['threshold'] for _, v in bl) for w, bl in blocks.items()) / sum(len(bl) for bl in blocks.values())
    scale = {w: min(1.0, pooled / s) if s else 1.0 for w, s in share.items()}
    out = {}
    for name, thr_of in (('t3', lambda w: models[w]['threshold']),
                         ('A6', lambda w: threshold(fits[w]['gumbel'], ALPHA * scale[w]) if scale[w] < 1 else models[w]['threshold'])):
        per = {}
        for w, bl in blocks.items():
            t = thr_of(w)
            for b, v in bl:
                r = per.setdefault(regime(b * 60.0), [0, 0])
                r[0] += 1
                r[1] += v > t
        n, k = sum(x[0] for x in per.values()), sum(x[1] for x in per.values())
        out[name] = dict(pooled=k / n, regimes={r: x[1] / x[0] for r, x in sorted(per.items())})
        print(name, round(100 * k / n, 3), {r: round(100 * x[1] / x[0], 2) for r, x in sorted(per.items())}, flush=True)
    Path(a.output).write_text(json.dumps(dict(schema='improvement-round-2-a6', scale=scale, workload_share=share,
                                              pooled_share=pooled, exceedance=out), indent=1))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest='cmd', required=True)
    d = sub.add_parser('datasets')
    for k in ('out', 'caches21', 'lidds-alarms', 'cbds-alarms', 'output'):
        d.add_argument('--' + k, required=True)
    d.add_argument('--jobs', type=int, default=4)
    i = sub.add_parser('intervals')
    i.add_argument('--run-root', required=True); i.add_argument('--session', required=True, help='pooled session MODELS.json')
    i.add_argument('--fit', help='FIT.json of the base t3 fit (A6 thresholds)'); i.add_argument('--alpha-scale', help='A6 {workload: factor}')
    i.add_argument('--system', action='append', required=True, help='name=MODELS.json[:persist][:a6]; the first is the base')
    i.add_argument('--b1-runs', nargs='*', default=[], help='B1: other runs whose operator sessions are learnt (leave-one-command-out)')
    i.add_argument('--output', required=True); i.add_argument('--jobs', type=int, default=4)
    x = sub.add_parser('a6')
    x.add_argument('--fit-dir', required=True); x.add_argument('--capture', required=True); x.add_argument('--output', required=True)
    a = ap.parse_args()
    dict(datasets=datasets, intervals=intervals, a6=a6)[a.cmd](a)


if __name__ == '__main__':
    main()
