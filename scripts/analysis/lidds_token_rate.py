#!/usr/bin/env python3
"""Part D of protocol ml-final-study-v1: a rate signal over seen grams, for attacks that use only sequences normal knows.

Per gram g (select1f tokens, padded 4-gram key as the token model), m_g is the largest count of g in one 0.5 s window
over the learning recordings; held-out recordings use the m_g of the other folds (5-fold cross-fit, folds as the token
model). Window rate score = max over the window's grams seen in learning of log((n_g + 1) / (m_g + 1)); a window with no
seen gram never fires. Threshold: the registered rule (moment Gumbel on the trimmed held-out recording maxima, alpha').

Unseen grams do not enter the rate score, so the seen-only simulation of token-design-study q4 (remove every row whose
gram or last token is unseen) leaves the rate score of a recording unchanged: its detections are the seen-only result.

    python3 lidds_token_rate.py --caches DIR --out DIR --lidds-alarms a.json.gz --cbds-alarms c.json.gz [--jobs 6]
"""
import argparse
import json
from multiprocessing import Pool
from pathlib import Path
import sys

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lidds_token_study as st  # noqa: E402

m = st.m
COLUMNS = ['window_end', 'rate']
KEEP = dict(detected=530, false_alarm_recordings=12, cb_detected=891, cb_false_alarm_recordings=3)
SEEN_ONLY_MIN = 6


def window_keys(w, g, c, tokmap, n):
    """Distinct (window, gram key) with summed counts: (window ends, keys as void, counts)."""
    if not len(c):
        return np.zeros(0), np.zeros(0, st.void(np.zeros((1, n), np.uint32)).dtype), np.zeros(0, np.int64)
    keys = st.void(np.ascontiguousarray(tokmap[g[:, g.shape[1] - n:]]))
    wk = np.empty(len(c), dtype=[('w', 'f8'), ('k', keys.dtype)])
    wk['w'], wk['k'] = w, keys
    u, inv = np.unique(wk, return_inverse=True)
    return u['w'], u['k'], np.bincount(inv.ravel(), weights=c).astype(np.int64)


def max_table(parts):
    """Element-wise max over [(keys, values)] -> (sorted unique keys, max values)."""
    parts = [p for p in parts if len(p[0])]
    if not parts:
        return None
    keys = np.concatenate([p[0] for p in parts])
    vals = np.concatenate([p[1] for p in parts])
    u, inv = np.unique(keys, return_inverse=True)
    out = np.full(len(u), -1, np.int64)
    np.maximum.at(out, inv.ravel(), vals)
    return u, out


def per_key_max(keys, counts):
    t = max_table([(keys, counts)])
    return t if t else (keys[:0], counts[:0])


def rate_rows(ends, keys, counts, table):
    """[[window_end, rate score]] of one recording against a max table; windows without a seen gram are left out."""
    if table is None or not len(keys):
        return np.zeros((0, 2))
    u, mx = table
    i = np.searchsorted(u, keys)
    i[i >= len(u)] = 0
    seen = u[i] == keys
    if not seen.any():
        return np.zeros((0, 2))
    e, s = ends[seen], np.log((counts[seen] + 1) / (mx[i[seen]] + 1))
    order = np.lexsort((-s, e))
    e, s = e[order], s[order]
    first = np.r_[True, e[1:] != e[:-1]]
    return np.column_stack([e[first], s[first]])


def score_scenario(cache):
    """{'val/<name>' | '<name>': [[window_end, rate]]} as lidds_token_study.score_scenario (folds, spec select1f)."""
    spec = st.base_spec()
    z = np.load(cache)
    meta = json.loads(Path(cache).with_suffix('.json').read_text())
    n, folds = spec['n'], spec['folds']
    tokmap = st.token_map([tuple(f) for f in meta['vocab']], spec)
    rec = lambda key: window_keys(z[f'{key}/w'], z[f'{key}/g'], z[f'{key}/c'], tokmap, n)
    learning = sorted(k for k, r in meta['recordings'].items() if r['split'] in ('training', 'validation'))
    data = {name: rec(f'fit/{name}') for name in learning}
    fold_tables = [max_table([per_key_max(data[x][1], data[x][2]) for x in learning if st.fold_of(x, folds) == k])
                   for k in range(folds)]
    out = {}
    for k in range(folds):
        table = max_table([t for j, t in enumerate(fold_tables) if j != k and t is not None])
        for name in learning:
            if st.fold_of(name, folds) == k:
                out[f'val/{name}'] = rate_rows(*data[name], table)
    full = max_table([t for t in fold_tables if t is not None])
    for name, r in sorted(meta['recordings'].items()):
        if r['split'] not in ('training', 'validation'):
            out[name] = rate_rows(*rec(name), full)
    return out


def task(job):
    cache, out_dir = job
    target = Path(out_dir) / 'rate' / Path(cache).name
    model = Path(out_dir) / 'model' / Path(cache).name
    for path, fn in ((target, score_scenario), (model, lambda c: st.score_scenario(c, st.base_spec()))):
        if not path.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
            part = path.with_name(path.name + '.part.npz')
            np.savez_compressed(part, **fn(cache))
            part.rename(path)
    return Path(cache).stem


class Either:
    """Alarms of either scenario object (each with its own registered threshold)."""

    def __init__(self, *scns):
        self.scns = scns

    def firings(self, branches, alpha, name):
        return sorted({t for s in self.scns for t in s.firings(branches, alpha, name)})


def evaluate(out_dir, docs):
    lidds, cbds = docs
    model_cols = st.columns_of(st.base_spec())
    load = lambda kind, s, col, cols: st.TokenScenario(Path(out_dir) / kind / f'{s}.npz', col, cols)
    res = {}
    arms = {}
    for doc, part in ((lidds, 'development'), (cbds, 'all')):
        names = sorted(s for s in doc['scenarios'] if (Path(out_dir) / 'rate' / f'{s}.npz').exists())
        rate = {s: load('rate', s, 'rate', COLUMNS) for s in names}
        model = {s: load('model', s, 'top10', model_cols) for s in names}
        both = {s: Either(rate[s], model[s]) for s in names}
        for arm, scns in (('rate', rate), ('model', model), ('model_or_rate', both)):
            pooled, per = m.score(scns, doc, ('T',), st.ALPHA, part)
            arms.setdefault(arm, {})['lidds' if doc is lidds else 'cbds'] = dict(
                detected=pooled['detected'], attack_recordings=pooled['attack_recordings'],
                false_alarm_recordings=pooled['false_alarm_recordings'], normal_recordings=pooled['normal_recordings'],
                latency_p95=pooled['latency_p95'], scenarios={s: [v['detected'], v['false_alarm_recordings']] for s, v in per.items()})
    r, b = arms['model_or_rate'], arms['rate']
    res['arms'] = arms
    res['criteria'] = dict(keep=KEEP, seen_only_min=SEEN_ONLY_MIN)
    res['joins'] = bool(r['lidds']['detected'] >= KEEP['detected'] and r['lidds']['false_alarm_recordings'] <= KEEP['false_alarm_recordings']
                        and r['cbds']['detected'] >= KEEP['cb_detected'] and r['cbds']['false_alarm_recordings'] <= KEEP['cb_false_alarm_recordings']
                        and b['lidds']['detected'] >= SEEN_ONLY_MIN)
    res['seen_only_note'] = ('rate detections on the attack recordings equal its detections on the seen-only simulation, '
                             'since unseen grams never enter the rate score')
    return res


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--caches', type=Path, required=True)
    ap.add_argument('--out', type=Path, required=True)
    ap.add_argument('--lidds-alarms', type=Path, required=True)
    ap.add_argument('--cbds-alarms', type=Path, required=True)
    ap.add_argument('--jobs', type=int, default=6)
    a = ap.parse_args()
    caches = sorted(a.caches.glob('*.npz'), key=lambda p: -p.stat().st_size)
    with Pool(min(a.jobs, len(caches))) as pool:
        for s in pool.imap_unordered(task, [(str(c), str(a.out)) for c in caches], chunksize=1):
            print('scored', s, flush=True)
    doc = dict(schema='ml-final-study-v1-rate-signal', protocol='sentinel_pulse/protocol/ml-final-study-v1.json',
               **evaluate(a.out, (m.load(a.lidds_alarms), m.load(a.cbds_alarms))))
    (a.out / 'rate-signal.json').write_text(json.dumps(doc, indent=1, default=float))
    print(json.dumps(dict(joins=doc['joins'], **{k: {p: (v[p]['detected'], v[p]['false_alarm_recordings']) for p in v}
                                                  for k, v in doc['arms'].items()})))


if __name__ == '__main__':
    main()
