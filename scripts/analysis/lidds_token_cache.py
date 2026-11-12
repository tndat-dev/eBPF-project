#!/usr/bin/env python3
"""Fact-gram cache of a LID-DS / CB-DS scenario for the token design study (protocol token-design-study-v1).

One pass over the archive. Every syscall exit becomes a *fact*, the finest token any alphabet of the study uses:

    (name, 'e', errno)      the call failed
    (name, 'o', 'r:/etc')   an open succeeded: mode and first directory, as lidds_ml_token_alphabets.facts
    (name, 's', bucket)     a positive return value of a size-capable call: min(15, floor(log2 n)), not halved
    (name, '', '')          anything else

Per recording the cache holds the distinct (0.5 s window, n-gram of fact ids) rows with their counts, grams per thread
as lidds_ml_token_alphabets.alphabet_windows (exit order; a thread's first grams are shorter, padded with -1 in front).
Every alphabet of the study maps a fact to a token on its own, so its grams and their counts follow from these rows
(lidds_token_study.py). Learning recordings (training + validation) are stored as fit/<name>, test recordings by name;
with --alarms only the development test recordings are read (official is not touched), or with --part official only
the official ones (for a scoring the protocol declares).

    python3 lidds_token_cache.py --archives DIR --scenario NAME [--alarms alarms.json.gz [--part official]] --output out.npz [--n 6]
"""
import argparse
from collections import Counter, defaultdict, deque
import io
import json
from pathlib import Path
import sys
import time
import zipfile

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lidds_ml_token_alphabets as al  # noqa: E402

tk, signals, convert, v2 = al.tk, al.signals, al.convert, al.v2
N = 6
# return value read as a size bucket: the I/O calls of the registered alphabet plus the add-one candidates of the protocol
EXTRA_SIZE = frozenset({'getdents', 'getdents64', 'readlink', 'readlinkat', 'epoll_wait', 'epoll_pwait', 'poll', 'ppoll',
                        'select', 'pselect6'})
SIZE_NAMES = frozenset(signals.READS | signals.WRITES | EXTRA_SIZE)


def fact(name, args):
    """The fact of one exit line. At most one detail, in the priority of lidds_ml_token_alphabets.atoken."""
    err, opened, returned, _ = al.facts(name, args, None)
    if err is not None:
        return name, 'e', str(err)
    if opened:
        return name, 'o', opened.split(':', 1)[1]
    if returned is None and name in EXTRA_SIZE:
        size = signals.byte_count(args)
        returned = None if size is None else signals.bucket(size)
    if returned is not None:
        return name, 's', str(returned)
    return name, '', ''


def recording_rows(lines, vocab, n=N):
    """Counter {(window_end, id_0, ..., id_{n-1}): count}; ids index ``vocab`` (grown in place), -1 pads a short gram."""
    rows = Counter()
    threads = defaultdict(lambda: deque(maxlen=n))
    pad = (-1,) * n
    for line in lines:
        parts = line.split(' ', 7)
        if len(parts) < 7 or parts[6] != '<':
            continue
        try:
            ts = int(parts[0])
        except ValueError:
            continue
        f = fact(parts[5], parts[7] if len(parts) > 7 else '')
        i = vocab.get(f)
        if i is None:
            i = vocab[f] = len(vocab)
        q = threads[parts[4]]
        q.append(i)
        rows[(signals.window_end(ts),) + pad[len(q):] + tuple(q)] += 1
    return rows


def arrays(rows, n):
    if not rows:
        return np.zeros(0), np.zeros((0, n), np.int32), np.zeros(0, np.int32)
    keys = sorted(rows)
    return (np.asarray([k[0] for k in keys], float), np.asarray([k[1:] for k in keys], np.int32),
            np.asarray([rows[k] for k in keys], np.int32))


def save(z, key, rows, n):
    for part, a in zip('wgc', arrays(rows, n)):
        buf = io.BytesIO()
        np.save(buf, a)
        z.writestr(f'{key}/{part}.npy', buf.getvalue())


def build(archive, output, wanted, n=N):
    vocab, meta, events = {}, {}, 0
    with zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED, compresslevel=1) as z:
        for split, name, blob in v2.split_recordings(archive, {'training', 'validation', 'test-normal', 'test-normal_and_attack'}):
            learning = split in ('training', 'validation')
            if not learning and not wanted(name, split):
                continue
            rows = recording_rows(convert.recording(blob)[1], vocab, n)
            events += sum(rows.values())
            save(z, f'fit/{name}' if learning else name, rows, n)
            meta[name] = dict(split=split, exploit=None if learning else tk.meta_of(blob), rows=len(rows))
    return [list(f) for f in sorted(vocab, key=lambda f: vocab[f])], meta, events


def part_only(alarms, scenario, part):
    """wanted(name, split) for one part (development, official) of the registered split."""
    import lidds_ml_v2 as m
    recs = m.load(alarms)['scenarios'][scenario]['alarms']
    keep = m.part_filter(scenario, recs, part)
    return lambda name, split: name in recs and keep(name, recs[name])


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--archives', type=Path, required=True)
    ap.add_argument('--scenario', required=True)
    ap.add_argument('--alarms', type=Path, help='keep development test recordings only; without it every recording (CB-DS)')
    ap.add_argument('--part', choices=('development', 'official'), default='development')
    ap.add_argument('--n', type=int, default=N)
    ap.add_argument('--output', type=Path, required=True)
    a = ap.parse_args()
    t0 = time.time()
    wanted = part_only(a.alarms, a.scenario, a.part) if a.alarms else (lambda name, split: True)
    partial = a.output.with_suffix('.part')
    vocab, meta, events = build(a.archives / f'{a.scenario}.zip', partial, wanted, a.n)
    partial.rename(a.output)
    a.output.with_suffix('.json').write_text(json.dumps(dict(schema='lidds-token-cache-v1', scenario=a.scenario, n=a.n, vocab=vocab,
                                                             part=a.part if a.alarms else 'all',
                                                             recordings=meta, events=events, seconds=time.time() - t0)))
    print(json.dumps(dict(scenario=a.scenario, recordings=len(meta), facts=len(vocab), events=events,
                          rows=sum(m['rows'] for m in meta.values()), seconds=round(time.time() - t0))))


if __name__ == '__main__':
    main()
