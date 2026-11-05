#!/usr/bin/env python3
"""A per-thread language model over syscalls enriched with their argument summary (before lidds-ml-v2).

The name-only language model cannot separate exploits that use ordinary calls on unusual data (CVE-2019-5418,
Heartbleed, Juice-Shop). Here every syscall exit is a token: the name, plus the errno of a failure ('openat!ENOENT'),
the mode and first directory of an open ('openat:r:/etc'), or the coarse log2 size of a read or write ('read#4').
The probability backs off through shorter thread contexts (Witten-Bell) to a structured base,
P(name) x P(token | name), both add-half, so a token never seen in training is graded by how usual its call is.

A window's score is the mean of its 10 highest per-event negative log-probabilities. ``unseen_grams`` (events whose
whole n-gram never occurred in training) is kept as the novelty baseline this model must beat to count as more than
a rule. Writes <scenario>.npz (test recordings by name, validation as val/<name>; columns in COLUMNS) and .json.
No decision or metric is computed here.

    python3 lidds_ml_tokens.py --archives DIR --scenario NAME --output out.npz
"""
import argparse
from collections import Counter, defaultdict, deque
import io
import json
import math
from pathlib import Path
import sys
import time
import zipfile

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import lidds_evaluate_v2 as v2  # noqa: E402
from sentinel_pulse.lidds import convert, signals  # noqa: E402

N, TOP = 4, 10
COLUMNS = ['window_end', 'top10', 'events', 'unseen_grams', 'unseen_tokens']


def token(name, args):
    """The syscall exit as a token: name, plus errno, open mode and first directory, or coarse I/O size."""
    err = signals.error_of(args)
    if err is not None:
        return f'{name}!{err}'
    if name in signals.OPENS:
        got = signals.open_path(args)
        if got:
            mode, path = got
            parts = [p for p in path.split('/') if p]
            top = '/' + parts[0] if path.startswith('/') and len(parts) > 1 else ('/' if path.startswith('/') else 'rel')
            return f"{name}:{'w' if name == 'creat' else mode}:{top}"
    if name in signals.READS or name in signals.WRITES:
        size = signals.byte_count(args)
        if size is not None:
            return f'{name}#{signals.bucket(size) // 2}'
    return name


def base_name(tok):
    cut = min((tok.index(sep) for sep in ('!', ':', '#') if sep in tok), default=len(tok))
    return tok[:cut].split('|', 1)[-1].split('@', 1)[0]   # process prefix and fd type of the alphabet variants


class TokenLM:
    """Witten-Bell over shorter contexts, down to the base P(name) x P(token | name)."""

    def __init__(self, n=N):
        self.n = n
        self.count = [defaultdict(Counter) for _ in range(n)]
        self.names = Counter()
        self.given = defaultdict(Counter)
        self.total = 0

    def learn(self, grams):
        for g in grams:
            g = tuple(g[-self.n:])
            w = g[-1]
            for k in range(1, min(self.n, len(g))):
                self.count[k][g[-1 - k:-1]][w] += 1
            self.names[base_name(w)] += 1
            self.given[base_name(w)][w] += 1
            self.total += 1

    def finalize(self):
        self.stats = [{h: (sum(c.values()), len(c)) for h, c in level.items()} for level in self.count]
        self.memo = {}
        self.seen_tokens = {t for c in self.given.values() for t in c}
        # a call never seen in training: its token is as unlikely as an unseen token of a known call, on average
        unseen = [0.5 / (sum(c.values()) + 0.5 * (len(c) + 1)) for c in self.given.values()]
        self.unseen_given = float(np.mean(unseen)) if unseen else 1.0
        self.seen_grams = set()
        for h, c in self.count[self.n - 1].items():
            self.seen_grams.update(h + (w,) for w in c)

    def base(self, w):
        name = base_name(w)
        p_name = (self.names.get(name, 0) + 0.5) / (self.total + 0.5 * (len(self.names) + 1))
        given = self.given.get(name)
        if not given:
            return p_name * self.unseen_given
        return p_name * (given.get(w, 0) + 0.5) / (sum(given.values()) + 0.5 * (len(given) + 1))

    def prob(self, g):
        g = tuple(g[-self.n:])
        hit = self.memo.get(g)
        if hit is not None:
            return hit
        w = g[-1]
        p = self.base(w)
        for k in range(1, min(self.n, len(g))):
            h = g[-1 - k:-1]
            st = self.stats[k].get(h)
            if not st:
                continue
            tot, types = st
            p = (self.count[k][h].get(w, 0) + types * p) / (tot + types)
        self.memo[g] = p
        return p


def window_tokens(lines, n=N):
    """{window_end: [token n-grams ending in that window]}, per thread, from syscall exit lines."""
    out = defaultdict(list)
    threads = defaultdict(lambda: deque(maxlen=n))
    for line in lines:
        parts = line.split(' ', 7)
        if len(parts) < 7 or parts[6] != '<':
            continue
        try:
            ts = int(parts[0])
        except ValueError:
            continue
        q = threads[parts[4]]
        q.append(token(parts[5], parts[7] if len(parts) > 7 else ''))
        out[signals.window_end(ts)].append(tuple(q))
    return dict(out)


def window_scores(per, lm):
    rows = []
    for w in sorted(per):
        grams = per[w]
        nll = sorted((-math.log(lm.prob(g)) for g in grams), reverse=True)[:TOP]
        rows.append((w, float(np.mean(nll)) if nll else 0.0, len(grams),
                     sum(len(g) == lm.n and g not in lm.seen_grams for g in grams),
                     sum(g[-1] not in lm.seen_tokens for g in grams)))
    return np.asarray(rows, dtype=float).reshape(-1, len(COLUMNS))


def meta_of(blob):
    z = zipfile.ZipFile(io.BytesIO(blob))
    m = json.loads(z.read(next(n for n in z.namelist() if n.endswith('.json'))))
    return m['time']['exploit'][0]['absolute'] if m.get('exploit') and m['time'].get('exploit') else None


def evaluate(archive):
    lm = TokenLM()
    for _, _, blob in v2.split_recordings(archive, {'training'}):
        for grams in window_tokens(convert.recording(blob)[1]).values():
            lm.learn(grams)
    lm.finalize()
    out, meta = {}, {}
    for _, name, blob in v2.split_recordings(archive, {'validation'}):
        out[f'val/{name}'] = window_scores(window_tokens(convert.recording(blob)[1]), lm)
    for split, name, blob in v2.split_recordings(archive, {'test-normal', 'test-normal_and_attack'}):
        out[name] = window_scores(window_tokens(convert.recording(blob)[1]), lm)
        meta[name] = dict(split=split, exploit=meta_of(blob))
    return out, meta


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--archives', type=Path, required=True)
    ap.add_argument('--scenario', required=True)
    ap.add_argument('--output', type=Path, required=True)
    a = ap.parse_args()
    t0 = time.time()
    out, meta = evaluate(a.archives / f'{a.scenario}.zip')
    np.savez_compressed(a.output, **out)
    a.output.with_suffix('.json').write_text(json.dumps(dict(scenario=a.scenario, columns=COLUMNS, n=N, recordings=meta,
                                                             seconds=time.time() - t0)))
    print(json.dumps(dict(scenario=a.scenario, seconds=round(time.time() - t0), matrices=len(out))))


if __name__ == '__main__':
    main()
