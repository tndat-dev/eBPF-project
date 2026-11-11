#!/usr/bin/env python3
"""Token design study (protocol token-design-study-v1 + amendment 1) on the fact-gram caches of lidds_token_cache.py.

An alphabet is a *spec*: which syscall names keep their errno, their open information, their size bucket. A fact of the
cache maps to a token of the spec on its own, so the grams, the cross-fitted models (lidds_ml_token_crossfit.py) and the
window scores of any spec follow from the cache without reading the dataset again. Decisions reuse the registered code:
lidds_ml_v2.score / threshold and lidds_ml_v4.trimmed_gumbel.

    gate   base spec = select1f: scores equal the stored cross-fit scores, decision reproduces lidds-ml-v5 development
    q1     39 hooked syscalls: leave-one-out, one-pass backward elimination to a smallest subset, add-one candidates
    q2     parameters one at a time: n, top, alpha', folds, trim
    q3     is the Gumbel threshold right: calibration, goodness of fit, alternatives
    q4     model against the unseen-gram rule, and the seen-only attack simulation

    python3 lidds_token_study.py STEP --caches DIR --out DIR --lidds-alarms a.json.gz --cbds-alarms c.json.gz [--jobs 12]
                                 [--reference ml-xfit-tokens]   (gate)
"""
import argparse
from collections import Counter
import hashlib
import json
import math
from multiprocessing import Pool
from pathlib import Path
import struct
import sys
import time

import numpy as np

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from sentinel_pulse.detector.token_model import TOK_NONE, CountTokenLM, call_of  # noqa: E402
import lidds_ml_token_alphabets as al  # noqa: E402
import lidds_ml_v2 as m  # noqa: E402
import lidds_ml_v4 as v4  # noqa: E402
import lidds_token_cache as tc  # noqa: E402

signals = al.signals
ALPHA = v4.ALPHA * v4.SHARES['T']                      # 0.00018, the registered level of the token model alone
TRIM, FOLDS, N, TOP = v4.TOP_DROP, 5, 4, 10
KEEP = dict(detected=530, false_alarm_recordings=6, latency_p95=1.52, cb_detected=891, cb_false_alarm_recordings=3)
IMPROVE = 533
ALIASES = ({'pread', 'pread64'}, {'pwrite', 'pwrite64'}, {'recv', 'recvfrom'}, {'send', 'sendto'})
GRID = dict(n=(2, 3, 4, 5, 6), top=(1, 3, 5, 10, 20), alpha=(0.01, 0.003, 0.001, 0.0005, ALPHA, 0.0001, 0.00005),
            folds=(3, 5, 10), trim=(0, 0.005, 0.01, 0.02, 0.05))
BUDGETS = (3, 6, 12, 20, 34)


# ------------------------------------------------------------------ specs

def base_spec(**extra):
    """select1f: errno of 27 syscalls, open information, returned size of the I/O calls."""
    spec = dict(err=sorted(al.SELECT_ERR | {'futex'}), open=sorted(signals.OPENS), size=sorted(signals.READS | signals.WRITES),
                n=N, folds=FOLDS, tops=[TOP], seen_only=False)
    spec.update(extra)
    return spec


def units():
    """{unit: names}: the hooked syscalls of the probe, dataset aliases as one unit (39 units)."""
    names, out = set(al.HOOKED), {}
    for group in ALIASES:
        out['+'.join(sorted(group))] = frozenset(group)
        names -= group
    out.update({name: frozenset({name}) for name in names})
    return dict(sorted(out.items()))


def without(spec, names):
    return dict(spec, **{k: sorted(set(spec[k]) - set(names)) for k in ('err', 'open', 'size')})


def with_detail(spec, kind, name):
    return dict(spec, **{kind: sorted(set(spec[kind]) | {name})})


def token_map(vocab, spec):
    """uint32 token of every fact under the spec (CountTokenLM layout: name id << 23 | variant); [-1] is the empty slot."""
    names = sorted({f[0] for f in vocab})
    if len(names) >= call_of(TOK_NONE):
        raise ValueError('too many syscall names for the token layout')
    nid = {name: i for i, name in enumerate(names)}
    keep = dict(e=set(spec['err']), o=set(spec['open']), s=set(spec['size']))
    variants, out = {}, np.empty(len(vocab) + 1, np.uint32)
    for i, (name, kind, value) in enumerate(vocab):
        v = variants.setdefault((name, kind, value), len(variants) + 1) if kind and name in keep[kind] else 0
        out[i] = nid[name] << 23 | v
    out[-1] = TOK_NONE
    return out


# ------------------------------------------------------------------ scores of one spec on one scenario

def void(a):
    return np.ascontiguousarray(a).view(np.dtype((np.void, a.dtype.itemsize * a.shape[1]))).ravel()


def gram_of(key, n):
    g = struct.unpack(f'{n}I', key)
    start = 0
    while start < n - 1 and g[start] == TOK_NONE:
        start += 1
    return g[start:]


def fold_of(name, folds):
    return int(hashlib.sha256(name.encode()).hexdigest(), 16) % folds


def build(counters, n):
    lm = CountTokenLM(n)
    for counts in counters:
        for key, c in counts.items():
            lm.learn(gram_of(key, n), c)
    return lm.finalize()


def surprisal_of(lm, n):
    """key -> (-ln p, full gram unseen, token unseen, novel at its own length): one model's table, filled on demand."""
    memo = {}

    def get(key):
        r = memo.get(key)
        if r is None:
            g = gram_of(key, n)
            w = g[-1]
            token = lm.given.get(call_of(w), {}).get(w, 0)
            own = lm.count[len(g) - 1].get(g[:-1], {}).get(w, 0) if len(g) > 1 else token
            r = memo[key] = (-math.log(lm.prob(g)), float(len(g) == n and own == 0), float(token == 0), float(own == 0 or token == 0))
        return r
    return get


def window_table(w, s, c, tops, sums=()):
    """Per window: mean of the top highest s with multiplicity c (CountTokenLM.window_score), events, sums of c * x."""
    order = np.lexsort((-s, w))
    w, s, c = w[order], s[order], c[order].astype(np.int64)
    idx = np.flatnonzero(np.r_[True, w[1:] != w[:-1]])
    before = np.cumsum(c) - c
    prev = before - np.repeat(before[idx], np.diff(np.r_[idx, len(c)]))
    total = np.add.reduceat(c, idx)
    scores = [np.add.reduceat(np.clip(k - prev, 0, c) * s, idx) / np.minimum(k, total) for k in tops]
    return w[idx], scores, total, [np.add.reduceat(c * x[order], idx) for x in sums]


def columns_of(spec):
    return ['window_end'] + [f'top{k}' for k in spec['tops']] + ['events', 'unseen_grams', 'unseen_any'] + (['seen_top'] if spec['seen_only'] else [])


def score_recording(w, g, c, tokmap, get, spec):
    cols = columns_of(spec)
    if not len(c):
        return np.zeros((0, len(cols)))
    n = spec['n']
    u, inv = np.unique(void(tokmap[g[:, g.shape[1] - n:]]), return_inverse=True)
    tab = np.asarray([get(k) for k in u.tolist()], float).reshape(-1, 4)[inv]
    s, any_new = tab[:, 0], np.maximum(tab[:, 1], tab[:, 2])
    ends, scores, total, (ug, ua) = window_table(w, s, c, spec['tops'], (tab[:, 1], any_new))
    out = [ends, *scores, total, ug, ua]
    if spec['seen_only']:                                  # the attacker avoided every unseen sequence: those rows are gone
        keep = tab[:, 3] == 0
        seen = np.zeros(len(ends))
        if keep.any():
            e2, (s2,), _, _ = window_table(w[keep], s[keep], c[keep], (spec['tops'][-1],))
            seen[np.searchsorted(ends, e2)] = s2
        out.append(seen)
    return np.column_stack(out)


def score_scenario(cache, spec):
    """{'val/<name>': held-out windows of a learning recording, '<name>': windows of a test recording}, columns_of(spec)."""
    z = np.load(cache)
    meta = json.loads(Path(cache).with_suffix('.json').read_text())
    n, folds = spec['n'], spec['folds']
    if n > meta['n']:
        raise ValueError(f"the cache holds {meta['n']}-grams")
    tokmap = token_map([tuple(f) for f in meta['vocab']], spec)
    rec = lambda key: (z[f'{key}/w'], z[f'{key}/g'], z[f'{key}/c'])
    learning = sorted(name for name, r in meta['recordings'].items() if r['split'] in ('training', 'validation'))
    counts = [Counter() for _ in range(folds)]
    for name in learning:
        _, g, c = rec(f'fit/{name}')
        if len(c):
            u, inv = np.unique(void(tokmap[g[:, g.shape[1] - n:]]), return_inverse=True)
            fold = counts[fold_of(name, folds)]
            for key, k in zip(u.tolist(), np.bincount(inv, weights=c).astype(np.int64).tolist()):
                fold[key] += k
    out = {}
    for k in range(folds):
        members = [name for name in learning if fold_of(name, folds) == k]
        if members:
            get = surprisal_of(build([counts[j] for j in range(folds) if j != k], n), n)
            for name in members:
                out[f'val/{name}'] = score_recording(*rec(f'fit/{name}'), tokmap, get, spec)
    get = surprisal_of(build(counts, n), n)
    for name, r in sorted(meta['recordings'].items()):
        if r['split'] not in ('training', 'validation'):
            out[name] = score_recording(*rec(name), tokmap, get, spec)
    return out


def task(job):
    cache, spec, target = job
    target = Path(target)
    if target.exists():
        return str(target), 0.0
    t0 = time.time()
    out = score_scenario(cache, spec)
    target.parent.mkdir(parents=True, exist_ok=True)
    part = target.with_name(target.name + '.part.npz')
    np.savez_compressed(part, **out)
    part.rename(target)
    return str(target), time.time() - t0


def ensure(a, specs):
    """Score every (spec, scenario) not yet on disk; specs: {id: spec}. Largest caches first."""
    caches = sorted(Path(a.caches).glob('*.npz'), key=lambda p: -p.stat().st_size)
    jobs = []
    for sid, spec in specs.items():
        d = Path(a.out) / 'scores' / sid
        d.mkdir(parents=True, exist_ok=True)
        (d / 'SPEC.json').write_text(json.dumps(dict(spec, columns=columns_of(spec)), indent=1))
        jobs += [(str(c), spec, str(d / c.name)) for c in caches if not (d / c.name).exists()]
    if jobs:
        with Pool(min(a.jobs, len(jobs))) as pool:
            for target, seconds in pool.imap_unordered(task, jobs, chunksize=1):
                print(f'scored {target} {seconds:.0f} s', flush=True)


# ------------------------------------------------------------------ decisions

class TokenScenario:
    """One scenario's scores of one spec, with the registered threshold rule (moment Gumbel on the trimmed held-out maxima)."""

    def __init__(self, path, column, columns, trim=TRIM):
        z = np.load(path)
        self.a = {k: z[k] for k in z.files}
        self.i = columns.index(column)
        self.maxima = np.asarray([a[:, self.i].max() for k, a in self.a.items() if k.startswith('val/') and len(a)])
        self.fit = fit_gumbel(self.maxima, trim)

    def firings(self, branches, alpha, name):
        a = self.a.get(name)
        if a is None or not len(a):
            return []
        return sorted(a[a[:, self.i] > m.threshold(self.fit, alpha), 0].tolist())


def fit_gumbel(maxima, trim):
    return v4.trimmed_gumbel(maxima, trim) if trim else m.gumbel(maxima)


class Scored:
    """A scored spec: its scenarios and the labels, for the development part of LID-DS and for CB-DS."""

    def __init__(self, a, sid, column=None, trim=TRIM):
        d = Path(a.out) / 'scores' / sid
        spec = json.loads((d / 'SPEC.json').read_text())
        column = column or f"top{TOP if TOP in spec['tops'] else spec['tops'][-1]}"
        self.lidds, self.cbds = a.docs
        load = lambda s: TokenScenario(d / f'{s}.npz', column, spec['columns'], trim)
        self.lid = {s: load(s) for s in sorted(self.lidds['scenarios']) if (d / f'{s}.npz').exists()}
        self.cb = {s: load(s) for s in sorted(self.cbds['scenarios']) if (d / f'{s}.npz').exists()}

    def metrics(self, alpha=ALPHA):
        dev, per = m.score(self.lid, self.lidds, ('T',), alpha, 'development')
        cb, _ = m.score(self.cb, self.cbds, ('T',), alpha, 'all')
        return dict(detected=dev['detected'], false_alarm_recordings=dev['false_alarm_recordings'], latency_p95=dev['latency_p95'],
                    latency_p50=dev['latency_p50'], attack_recordings=dev['attack_recordings'], normal_recordings=dev['normal_recordings'],
                    cb_detected=cb['detected'], cb_false_alarm_recordings=cb['false_alarm_recordings'],
                    scenarios={s: [v['detected'], v['false_alarm_recordings']] for s, v in per.items()})

    def maxima(self):
        """{scenario: (normal maxima, attack maxima after the exploit)} of the development recordings, raw scores."""
        out = {}
        for s, scn in self.lid.items():
            recs = self.lidds['scenarios'][s]['alarms']
            wanted = m.part_filter(s, recs, 'development')
            nor, att = [], []
            for name, r in recs.items():
                if not wanted(name, r):
                    continue
                arr = scn.a.get(name)
                x = arr[:, [0, scn.i]] if arr is not None and len(arr) else np.zeros((0, 2))
                if r['exploit'] is None:
                    nor.append(x[:, 1].max() if len(x) else -np.inf)
                else:
                    after = x[x[:, 0] > r['exploit'], 1]
                    att.append(after.max() if len(after) else -np.inf)
            out[s] = (np.asarray(nor), np.asarray(att))
        return out


def keeps(r):
    return (r['detected'] >= KEEP['detected'] and r['false_alarm_recordings'] <= KEEP['false_alarm_recordings']
            and (r['latency_p95'] or 0) <= KEEP['latency_p95'] and r['cb_detected'] >= KEEP['cb_detected']
            and r['cb_false_alarm_recordings'] <= KEEP['cb_false_alarm_recordings'])


def frontier(maxima, thresholds_of, levels):
    """[(level, detected, false-alarm recordings)]: thresholds_of(scenario, level) on raw maxima."""
    out = []
    for level in levels:
        det = fa = 0
        for s, (nor, att) in maxima.items():
            t = thresholds_of(s, level)
            det += int((att > t).sum())
            fa += int((nor > t).sum())
        out.append((level, det, fa))
    return out


def at_budgets(points, budgets=BUDGETS):
    return {b: max((p for p in points if p[2] <= b), key=lambda p: (p[1], -p[2]), default=None) for b in budgets}


LEVELS = tuple(float(x) for x in np.logspace(-8, np.log10(0.5), 400))


# ------------------------------------------------------------------ steps

def write(a, name, doc):
    path = Path(a.out) / name
    path.write_text(json.dumps(doc, indent=1, default=float))
    print('wrote', path, flush=True)


def gate(a):
    ensure(a, {'base': base_spec(tops=list(GRID['top']), seen_only=True)})
    worst = {}
    if a.reference:
        d = Path(a.out) / 'scores' / 'base'
        cols = json.loads((d / 'SPEC.json').read_text())['columns']
        i = cols.index(f'top{TOP}')
        for path in sorted(Path(a.reference).glob('*.npz')):
            ref, new = np.load(path), np.load(d / path.name)
            keys = [k for k in ref.files if k in new.files]
            diff = 0.0
            for k in keys:
                x, y = ref[k], new[k]
                if x.shape[0] != y.shape[0] or (len(x) and not np.array_equal(x[:, 0], y[:, 0])):
                    raise SystemExit(f'gate failed: {path.stem} {k}: windows differ')
                if len(x):
                    diff = max(diff, float(np.abs(x[:, 1] - y[:, i]).max()))
            worst[path.stem] = dict(compared=len(keys), reference_only=len(set(ref.files) - set(new.files)), largest_difference=diff)
            if diff > 1e-9 or not keys:
                raise SystemExit(f'gate failed: {path.stem} differs by {diff}')
    r = Scored(a, 'base').metrics()
    ok = (r['detected'], r['false_alarm_recordings'], r['cb_detected'], r['cb_false_alarm_recordings']) == (530, 6, 891, 3) \
        and round(r['latency_p95'], 2) == 1.52
    write(a, 'gate.json', dict(schema='token-design-study-gate-v1', passed=ok, base=r, score_equality=worst))
    if not ok:
        raise SystemExit(f'gate failed: base gives {r}')


def need_gate(a):
    g = Path(a.out) / 'gate.json'
    if not g.exists() or not json.loads(g.read_text())['passed']:
        raise SystemExit('run the gate first')


def vocab_names(a, kind=None):
    names = set()
    for p in Path(a.caches).glob('*.json'):
        names |= {f[0] for f in json.loads(p.read_text())['vocab'] if kind is None or f[1] == kind}
    return names


def eliminate(order, evaluate, start=()):
    """One-pass backward elimination, then leave-one-out passes until nothing more can go. evaluate(removed) -> metrics."""
    removed, log = list(start), []
    changed = True
    while changed:
        changed = False
        for u in order:
            if u in removed:
                continue
            r = evaluate(tuple(removed) + (u,))
            ok = keeps(r)
            log.append(dict(tried=u, removed_before=list(removed), keeps=ok,
                            **{k: r[k] for k in ('detected', 'false_alarm_recordings', 'latency_p95', 'cb_detected', 'cb_false_alarm_recordings')}))
            if ok:
                removed.append(u)
                changed = True
    return removed, log


def q1(a):
    need_gate(a)
    base, un = base_spec(), units()
    present = vocab_names(a)
    absent = sorted(u for u, names in un.items() if not names & present)
    live = {u: names for u, names in un.items() if u not in absent}
    ref = Scored(a, 'base').metrics()
    loo_specs = {f'loo-{u}': without(base, names) for u, names in live.items()}
    ensure(a, loo_specs)
    loo = {u: Scored(a, f'loo-{u}').metrics() for u in live}
    order = sorted(live, key=lambda u: (ref['detected'] - loo[u]['detected'], loo[u]['false_alarm_recordings'] - ref['false_alarm_recordings'], u))

    def evaluate(removed):
        sid = 'elim-' + hashlib.sha256('|'.join(sorted(removed)).encode()).hexdigest()[:12]
        ensure(a, {sid: without(base, set().union(*(un[u] for u in removed)))})
        return Scored(a, sid).metrics()
    removed, log = eliminate(order, evaluate)
    subset = sorted(set(un) - set(removed) - set(absent))
    hooked = set().union(*un.values())
    err_candidates = sorted(vocab_names(a, 'e') - set(base['err']))
    size_candidates = sorted((vocab_names(a, 's') & tc.EXTRA_SIZE) - set(base['size']))
    add_specs = {f'add-err-{name}': with_detail(base, 'err', name) for name in err_candidates}
    add_specs.update({f'add-size-{name}': with_detail(base, 'size', name) for name in size_candidates})
    ensure(a, add_specs)
    add = {sid: Scored(a, sid).metrics() for sid in add_specs}
    better = sorted(sid for sid, r in add.items() if r['detected'] >= IMPROVE and r['false_alarm_recordings'] <= KEEP['false_alarm_recordings']
                    and r['cb_detected'] >= KEEP['cb_detected'] and r['cb_false_alarm_recordings'] <= KEEP['cb_false_alarm_recordings'])
    union = None
    if better:
        spec = base
        for sid in better:
            kind, name = sid.split('-', 2)[1:]
            spec = with_detail(spec, kind, name)
        ensure(a, {'union': spec})
        union = Scored(a, 'union').metrics()
    write(a, 'q1.json', dict(schema='token-design-study-q1-v1', base=ref, units=len(un), absent_from_data=absent, hooked_names=sorted(hooked),
                             leave_one_out=loo, elimination_order=order, elimination=log, removed=removed, smallest_subset=subset,
                             smallest_subset_metrics=evaluate(tuple(removed)) if removed else ref,
                             add_one=add, improving=better, union=union,
                             union_qualifies=bool(union and union['detected'] >= IMPROVE and union['false_alarm_recordings'] <= KEEP['false_alarm_recordings']
                                                  and union['cb_detected'] >= KEEP['cb_detected']
                                                  and union['cb_false_alarm_recordings'] <= KEEP['cb_false_alarm_recordings'])))


def q2(a):
    need_gate(a)
    specs = {f'n{n}': base_spec(n=n) for n in GRID['n'] if n != N}
    specs.update({f'folds{f}': base_spec(folds=f) for f in GRID['folds'] if f != FOLDS})
    ensure(a, specs)
    out = dict(n={}, top={}, alpha={}, folds={}, trim={})
    for n in GRID['n']:
        out['n'][n] = Scored(a, 'base' if n == N else f'n{n}').metrics()
    for k in GRID['top']:
        out['top'][k] = Scored(a, 'base', f'top{k}').metrics()
    for f in GRID['folds']:
        out['folds'][f] = Scored(a, 'base' if f == FOLDS else f'folds{f}').metrics()
    scored = Scored(a, 'base')
    for alpha in GRID['alpha']:
        out['alpha'][alpha] = scored.metrics(alpha)
    for trim in GRID['trim']:
        out['trim'][trim] = Scored(a, 'base', trim=trim).metrics()
    write(a, 'q2.json', dict(schema='token-design-study-q2-v1', base=dict(n=N, top=TOP, alpha=ALPHA, folds=FOLDS, trim=TRIM), grid=out))


def anderson_darling(x, cdf):
    x = np.sort(x)
    n = len(x)
    f = np.clip(cdf(x), 1e-12, 1 - 1e-12)
    i = np.arange(1, n + 1)
    return float(-n - np.mean((2 * i - 1) * (np.log(f) + np.log(1 - f[::-1]))))


def gumbel_cdf(fit):
    return lambda x: np.exp(-np.exp(-(np.asarray(x) - fit[0]) / fit[1]))


def ad_gumbel(x, draws=2000, seed=1):
    """Anderson-Darling of the moment Gumbel, p-value by parametric bootstrap (the fit is repeated on every draw)."""
    fit = m.gumbel(x)
    stat = anderson_darling(x, gumbel_cdf(fit))
    rng = np.random.default_rng(seed)
    sims = fit[0] - fit[1] * np.log(-np.log(rng.uniform(size=(draws, len(x)))))
    worse = sum(anderson_darling(s, gumbel_cdf(m.gumbel(s))) >= stat for s in sims)
    return stat, (worse + 1) / (draws + 1)


def gev_shape(x):
    """Maximum-likelihood GEV shape xi (> 0: heavier tail than Gumbel) with a profile-likelihood 95 % interval."""
    from scipy import optimize, stats
    c, loc, scale = stats.genextreme.fit(x)
    best = stats.genextreme.logpdf(x, c, loc, scale).sum()

    def profile(xi):
        f = lambda p: -stats.genextreme.logpdf(x, -xi, p[0], abs(p[1]) + 1e-9).sum()
        return -optimize.minimize(f, [loc, scale], method='Nelder-Mead').fun
    grid = np.linspace(-0.6, 1.0, 81)
    inside = [xi for xi in grid if 2 * (best - profile(xi)) <= 3.841]
    return -float(c), (float(min(inside)), float(max(inside))) if inside else None, (float(c), float(loc), float(scale))


def holm(p):
    order = np.argsort(p)
    adj, running = np.empty(len(p)), 0.0
    for rank, i in enumerate(order):
        running = max(running, min(1.0, (len(p) - rank) * p[i]))
        adj[i] = running
    return adj


def q3(a):
    need_gate(a)
    from scipy import stats
    scored = Scored(a, 'base')
    maxima = scored.maxima()
    normal = sum(len(nor) for nor, _ in maxima.values())
    moment = lambda s, level: m.threshold(scored.lid[s].fit, level)
    calibration = []
    for alpha in GRID['alpha']:
        observed = sum(int((nor > moment(s, alpha)).sum()) for s, (nor, _) in maxima.items())
        lo = stats.beta.ppf(0.025, observed, normal - observed + 1) if observed else 0.0
        hi = stats.beta.ppf(0.975, observed + 1, normal - observed)
        calibration.append(dict(alpha=alpha, expected=alpha * normal, observed=observed, rate=observed / normal, rate_ci95=[float(lo), float(hi)],
                                ratio=observed / (alpha * normal), inside=bool(lo <= alpha <= hi),
                                scenarios={s: int((nor > moment(s, alpha)).sum()) for s, (nor, _) in maxima.items()}))
    fits, gev = {}, {}
    for s, scn in scored.lid.items():
        x = scn.maxima
        trimmed = np.sort(x)[:max(2, len(x) - max(1, int(round(len(x) * TRIM))))]
        stat, p = ad_gumbel(x)
        stat_t, p_t = ad_gumbel(trimmed)
        xi, ci, params = gev_shape(x)
        gev[s] = params
        fits[s] = dict(maxima=len(x), anderson_darling=stat, p=p, trimmed_anderson_darling=stat_t, trimmed_p=p_t, gev_shape=xi, gev_shape_ci95=ci,
                       mean=float(np.mean(trimmed)), std=float(np.std(trimmed)), threshold=m.threshold(scn.fit, ALPHA))
    adjusted = holm(np.asarray([fits[s]['p'] for s in fits]))
    for s, q in zip(fits, adjusted):
        fits[s]['p_holm'] = float(q)
    k_of = {alpha: math.sqrt(6) / math.pi * (-0.5772 - math.log(-math.log(1 - alpha))) for alpha in GRID['alpha']}
    held = {s: np.sort(scn.maxima) for s, scn in scored.lid.items()}
    mle = {s: stats.gumbel_r.fit(x) for s, x in held.items()}
    normal_fit = {s: (float(np.mean(x)), float(np.std(x))) for s, x in held.items()}

    def conformal(s, level):
        x = held[s]
        k = math.ceil((len(x) + 1) * (1 - level))
        return x[k - 1] if k <= len(x) else np.inf
    rules = {
        'gumbel moments, trimmed (registered)': moment,
        'gumbel moments, all maxima': lambda s, level: m.threshold(m.gumbel(held[s]), level),
        'gumbel maximum likelihood': lambda s, level: float(stats.gumbel_r.ppf(1 - level, *mle[s])),
        'gev maximum likelihood': lambda s, level: float(stats.genextreme.ppf(1 - level, *gev[s])),
        'normal': lambda s, level: float(stats.norm.ppf(1 - level, *normal_fit[s])),
        'split conformal order statistic': conformal}
    alternatives = {name: {str(b): p for b, p in at_budgets(frontier(maxima, f, LEVELS)).items()} for name, f in rules.items()}
    largest = frontier(maxima, lambda s, level: held[s][-1], (0,))[0]
    rejected = int((adjusted < 0.05).sum())
    write(a, 'q3.json', dict(schema='token-design-study-q3-v1', normal_recordings=normal, calibration=calibration, scenarios=fits,
                             rejected_after_holm=rejected, gumbel_holds=bool(all(c['inside'] for c in calibration) and rejected < 2),
                             k_sigma_of_alpha=k_of, alternatives_at_false_alarm_budgets=alternatives,
                             largest_held_out_maximum=dict(detected=largest[1], false_alarm_recordings=largest[2])))


def paired_bootstrap(maxima, t_model, t_rule, rule_maxima, draws=10000, seed=1):
    """Detected(model) - detected(rule) at fixed thresholds, attack recordings resampled within each scenario."""
    rng = np.random.default_rng(seed)
    total = np.zeros(draws)
    point = 0
    for s, (_, att) in maxima.items():
        d = (att > t_model[s]).astype(int) - (rule_maxima[s][1] > t_rule[s]).astype(int)
        point += int(d.sum())
        if len(d):
            total += d[rng.integers(0, len(d), size=(draws, len(d)))].sum(axis=1)
    return point, [float(np.percentile(total, 2.5)), float(np.percentile(total, 97.5))]


def q4(a):
    need_gate(a)
    model = Scored(a, 'base')
    arms = dict(model=model, unseen_grams=Scored(a, 'base', 'unseen_grams'), unseen_any=Scored(a, 'base', 'unseen_any'))
    maxima = {k: v.maxima() for k, v in arms.items()}
    thresholds = {k: (lambda s, level, v=v: m.threshold(v.lid[s].fit, level)) for k, v in arms.items()}
    fronts = {k: frontier(maxima[k], thresholds[k], LEVELS) for k in arms}
    budgets = {k: {str(b): p for b, p in at_budgets(f).items()} for k, f in fronts.items()}
    registered = {k: v.metrics() for k, v in arms.items()}
    compare = {}
    b = KEEP['false_alarm_recordings']
    for rule in ('unseen_grams', 'unseen_any'):
        pm, pr = at_budgets(fronts['model'])[b], at_budgets(fronts[rule])[b]
        if pm and pr:
            tm = {s: thresholds['model'](s, pm[0]) for s in maxima['model']}
            tr = {s: thresholds[rule](s, pr[0]) for s in maxima[rule]}
            point, ci = paired_bootstrap(maxima['model'], tm, tr, maxima[rule])
            compare[rule] = dict(budget=b, model=pm, rule=pr, difference=point, ci95=ci)
    seen = Scored(a, 'base', 'seen_top')
    full = model.maxima()
    stripped = seen.maxima()
    sim = {}
    for s in full:
        t = m.threshold(model.lid[s].fit, ALPHA)                 # the model's registered threshold, not refitted
        sim[s] = dict(attack_recordings=len(full[s][1]), detected=int((full[s][1] > t).sum()), detected_seen_only=int((stripped[s][1] > t).sum()),
                      normal_recordings=len(full[s][0]), false_alarms=int((full[s][0] > t).sum()), false_alarms_seen_only=int((stripped[s][0] > t).sum()))
    pooled = {k: sum(v[k] for v in sim.values()) for k in next(iter(sim.values()))}
    write(a, 'q4.json', dict(schema='token-design-study-q4-v1', registered_point=registered, at_false_alarm_budgets=budgets, paired=compare,
                             seen_only_simulation=dict(pooled=pooled, scenarios=sim,
                                                       note='rows whose gram is unseen at its own length or whose last token is unseen are removed; '
                                                            'the unseen-gram rules score 0 on what is left')))


STEPS = dict(gate=gate, q1=q1, q2=q2, q3=q3, q4=q4)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('step', choices=STEPS)
    ap.add_argument('--caches', type=Path, required=True)
    ap.add_argument('--out', type=Path, required=True)
    ap.add_argument('--lidds-alarms', type=Path, required=True)
    ap.add_argument('--cbds-alarms', type=Path, required=True)
    ap.add_argument('--reference', type=Path, help='gate: directory of the stored lidds_ml_token_crossfit.py scores')
    ap.add_argument('--jobs', type=int, default=12)
    a = ap.parse_args()
    a.out.mkdir(parents=True, exist_ok=True)
    a.docs = (m.load(a.lidds_alarms), m.load(a.cbds_alarms))
    STEPS[a.step](a)


if __name__ == '__main__':
    main()
