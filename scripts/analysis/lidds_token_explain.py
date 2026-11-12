#!/usr/bin/env python3
"""Worked examples of the token model (lidds-ml-v5, alphabet select1f) on the development caches of lidds_token_cache.py.

For one scenario: the registered threshold (moment Gumbel on the trimmed held-out maxima of the 5-fold cross-fit,
alpha' = 0.00018), then the first attack recording in name order that fires after its exploit (no choice by result),
its first firing window, the 10 events that make the score and the Witten-Bell backoff of the most surprising one, the
same recording's highest window before the exploit, and the highest window of all development normal test recordings.
Read only; nothing here feeds a decision.

    python3 lidds_token_explain.py --cache DIR/CVE-2019-5418.npz --out explain-CVE-2019-5418.json
"""
import argparse
from collections import Counter
import json
import math
from pathlib import Path
import sys

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lidds_token_study as st  # noqa: E402

m, v4 = st.m, st.v4


def label(fact, spec):
    """The select1f token of a fact, as text."""
    name, kind, value = fact
    if kind == 'e' and name in spec['err']:
        return f'{name}!{value}'
    if kind == 'o' and name in spec['open']:
        return f'{name}:{value}'
    if kind == 's' and name in spec['size']:
        return f'{name}#{value}'
    return name


def backoff(lm, g):
    """P_0 .. P_3 of the last token of g with c(h), T(h), c(h, w) at each context length."""
    w = g[-1]
    p = lm.base(w)
    steps = [dict(k=0, p=p)]
    for k in range(1, min(lm.n, len(g))):
        h = g[-1 - k:-1]
        s = lm.stats[k].get(h)
        if not s:
            steps.append(dict(k=k, context_seen=False, p=p))
            continue
        tot, types = s
        c = lm.count[k][h].get(w, 0)
        p = (c + types * p) / (tot + types)
        steps.append(dict(k=k, context_seen=True, c_h=tot, T_h=types, c_hw=c, p=p))
    for s in steps:
        s['nll'] = -math.log(s['p'])
    return steps


def explain(cache, spec=None):
    spec = spec or st.base_spec()
    z = np.load(cache)
    meta = json.loads(Path(cache).with_suffix('.json').read_text())
    vocab = [tuple(f) for f in meta['vocab']]
    tokmap = st.token_map(vocab, spec)
    n, folds = spec['n'], spec['folds']
    rec = lambda key: (z[f'{key}/w'], z[f'{key}/g'], z[f'{key}/c'])
    learning = sorted(k for k, r in meta['recordings'].items() if r['split'] in ('training', 'validation'))
    counts = [Counter() for _ in range(folds)]
    for name in learning:
        _, g, c = rec(f'fit/{name}')
        if len(c):
            u, inv = np.unique(st.void(tokmap[g[:, g.shape[1] - n:]]), return_inverse=True)
            fold = counts[st.fold_of(name, folds)]
            for key, k in zip(u.tolist(), np.bincount(inv, weights=c).astype(np.int64).tolist()):
                fold[key] += k
    maxima = []
    for k in range(folds):
        members = [x for x in learning if st.fold_of(x, folds) == k]
        get = st.surprisal_of(st.build([counts[j] for j in range(folds) if j != k], n), n)
        for name in members:
            a = st.score_recording(*rec(f'fit/{name}'), tokmap, get, spec)
            if len(a):
                maxima.append(float(a[:, 1].max()))
    fit = v4.trimmed_gumbel(maxima)
    tau = m.threshold(fit, st.ALPHA)
    kept = np.sort(maxima)[:max(2, len(maxima) - max(1, int(round(len(maxima) * st.TRIM))))]
    lm = st.build(counts, n)
    get = st.surprisal_of(lm, n)

    def window(name, end):
        w, g, c = rec(name)
        sel = w == end
        rows = []
        for gi, ci in zip(g[sel], c[sel]):
            ids = [int(i) for i in gi[gi.shape[0] - n:] if i >= 0]
            gram = st.gram_of(np.ascontiguousarray(tokmap[gi[gi.shape[0] - n:]]).tobytes(), n)
            nll = -math.log(lm.prob(gram))
            rows.append(dict(gram=[label(vocab[i], spec) for i in ids], count=int(ci), nll=nll,
                             gram_seen=bool(lm.count[len(gram) - 1].get(gram[:-1], {}).get(gram[-1], 0)) if len(gram) > 1 else None,
                             token_seen=bool(lm.given.get(st.call_of(gram[-1]), {}).get(gram[-1], 0)), _gram=gram))
        rows.sort(key=lambda r: -r['nll'])
        top, taken = [], 0
        for r in rows:
            use = min(r['count'], st.TOP - taken)
            if use <= 0:
                break
            top.append(dict(r, used=use))
            taken += use
        score = sum(r['nll'] * r['used'] for r in top) / taken if taken else 0.0
        trace = backoff(lm, top[0]['_gram']) if top else []
        for r in top:
            r.pop('_gram')
        return dict(window_end=float(end), events=int(c[sel].sum()), distinct_grams=len(rows), score=score,
                    top=top, backoff_of_first=trace)

    def scores(name):
        a = st.score_recording(*rec(name), tokmap, get, spec)
        return a[:, 0], a[:, 1]

    attacks = sorted(k for k, r in meta['recordings'].items() if r['exploit'] is not None)
    example, detected = None, 0
    for name in attacks:
        ex = meta['recordings'][name]['exploit']
        ends, s = scores(name)
        fired = ends[(s > tau) & (ends > ex)]
        detected += bool(len(fired))
        if len(fired) and example is None:
            before = (ends <= ex)
            example = dict(recording=name, exploit=ex, first_alarm_after_exploit_s=float(fired[0] - ex),
                           windows=len(ends), windows_over_threshold_after_exploit=int(((s > tau) & (ends > ex)).sum()),
                           alarm_window=window(name, fired[0]),
                           highest_before_exploit=window(name, ends[before][np.argmax(s[before])]) if before.any() else None)
    normals = sorted(k for k, r in meta['recordings'].items() if r['split'] == 'test-normal')
    best, false_alarms = None, 0
    for name in normals:
        ends, s = scores(name)
        false_alarms += bool(len(s) and s.max() > tau)
        if len(s) and (best is None or s.max() > best[2]):
            best = (name, ends[np.argmax(s)], float(s.max()))
    return dict(scenario=meta['scenario'], alpha=st.ALPHA, learning_recordings=len(learning),
                training_events=lm.total, distinct_tokens=sum(len(v) for v in lm.given.values()),
                held_out_maxima=dict(n=len(maxima), kept=len(kept), mean=float(np.mean(kept)), std=float(np.std(kept)),
                                     largest_dropped=float(np.sort(maxima)[-1])),
                gumbel=dict(mu=fit[0], beta=fit[1]), threshold=tau,
                k_sigma=(tau - float(np.mean(kept))) / float(np.std(kept)),
                attack_recordings=len(attacks), detected=detected, normal_recordings=len(normals),
                false_alarm_recordings=false_alarms, example=example,
                highest_normal=dict(recording=best[0], score=best[2], fires=best[2] > tau,
                                    window=window(best[0], best[1])) if best else None)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--cache', type=Path, required=True)
    ap.add_argument('--out', type=Path, required=True)
    a = ap.parse_args()
    doc = explain(a.cache)
    a.out.write_text(json.dumps(doc, indent=1, ensure_ascii=False))
    e = doc['example']
    print(doc['scenario'], 'tau', round(doc['threshold'], 2), 'example', e and (e['recording'], round(e['alarm_window']['score'], 2)))


if __name__ == '__main__':
    main()
