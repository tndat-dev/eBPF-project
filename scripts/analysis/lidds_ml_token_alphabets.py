#!/usr/bin/env python3
"""Which tokens does lidds-ml-v2 need, given what a cheap probe can collect? Development comparison, no metric here.

A hook on every syscall exit failed the overhead criterion on 31/10 (+197 ns on mmap + munmap, limit 150), so each
alphabet below states what its information costs. All keep the per-thread 4-grams and the top-10 score of
lidds_ml_tokens.py; only the tokens change:

    full          errno of every call, open mode + first directory, returned I/O size: every exit
    noerr         no errno                                                           : exit of reads and writes
    nosize        no size                                                            : every exit
    noopen        no open information                                                : every exit
    req           as full with the requested size at entry instead of the returned   : every exit
    open_only     open mode + first directory only                                   : entry of the opens
    open_err      plus errno of the opens                                            : exit of the opens
    open_err_req  plus the requested I/O size at entry                               : exit of the opens
    name          the syscall name only                                              : none, the current probe's id
    select        errno of SELECT_ERR, open, returned I/O size                       : exit of SELECT_ERR, opens, reads, writes
    full1, select1  as full and select with log2 size not halved; select1f adds futex errno (futex is a hot syscall)

SELECT_ERR comes from the development inventory (lidds_ml_token_inventory.py: syscalls whose errno token is new in
many attack recordings and rare in normal ones), so `select` is chosen with attack labels and its numbers are optimistic.

Official recordings are not read at all when --alarms is given.

    python3 lidds_ml_token_alphabets.py --archives DIR --scenario NAME --alarms alarms.json.gz --output out.npz
"""
import argparse
from collections import defaultdict, deque
import json
import math
from pathlib import Path
import re
import sys
import time

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lidds_ml_tokens as tk  # noqa: E402

signals, convert, v2 = tk.signals, tk.convert, tk.v2
ALPHABETS = dict(full=dict(err='all', open=True, size='exit'),
                 noerr=dict(err=None, open=True, size='exit'),
                 nosize=dict(err='all', open=True, size=None),
                 noopen=dict(err='all', open=False, size='exit'),
                 req=dict(err='all', open=True, size='entry'),
                 open_only=dict(err=None, open=True, size=None),
                 open_err=dict(err='opens', open=True, size=None),
                 open_err_req=dict(err='opens', open=True, size='entry'),
                 name=dict(err=None, open=False, size=None))
SELECT_ERR = frozenset({'stat', 'lstat', 'fstat', 'newfstatat', 'access', 'faccessat', 'open', 'openat', 'creat', 'read', 'write',
                        'writev', 'ioctl', 'connect', 'execve', 'fcntl', 'close', 'rename', 'renameat', 'sendfile', 'unlink',
                        'unlinkat', 'mkdir', 'kill', 'recvfrom', 'shutdown'})
ALPHABETS['select'] = dict(err=SELECT_ERR, open=True, size='exit')
# the variant study (lidds_ml_token_variants.py, 6 weak scenarios) found log2 size without halving better: same alphabets at full size resolution
ALPHABETS['full1'] = dict(err='all', open=True, size='exit', halve=False)
ALPHABETS['select1'] = dict(err=SELECT_ERR, open=True, size='exit', halve=False)
ALPHABETS['select1f'] = dict(err=SELECT_ERR | {'futex'}, open=True, size='exit', halve=False)
REQUESTED = re.compile(r'\bsize=(\d+)')


def facts(name, args, requested):
    """The parts of one exit, parsed once; (errno, open token, returned size bucket, requested size bucket)."""
    err = signals.error_of(args)
    opened = returned = wanted = None
    if name in signals.OPENS:
        got = signals.open_path(args) if err is None else None
        if got:
            mode, path = got
            parts = [p for p in path.split('/') if p]
            top = '/' + parts[0] if path.startswith('/') and len(parts) > 1 else ('/' if path.startswith('/') else 'rel')
            opened = f"{name}:{'w' if name == 'creat' else mode}:{top}"
    elif err is None and (name in signals.READS or name in signals.WRITES):
        size = signals.byte_count(args)
        returned = None if size is None else signals.bucket(size)
    if name in signals.READS or name in signals.WRITES:
        wanted = None if requested is None else signals.bucket(requested)
    return err, opened, returned, wanted


def atoken(name, fact, a):
    err, opened, returned, wanted = fact
    if err is not None and (a['err'] == 'all' or (a['err'] == 'opens' and name in signals.OPENS)
                            or (isinstance(a['err'], frozenset) and name in a['err'])):
        return f'{name}!{err}'
    if a['open'] and opened:
        return opened
    size = returned if a['size'] == 'exit' else wanted if a['size'] == 'entry' else None
    if size is not None and a.get('halve', True):
        size //= 2                                  # log2 size / 2, as lidds_ml_tokens.token
    return name if size is None else f'{name}#{size}'


def alphabet_windows(lines, names, n=tk.N):
    out = {k: defaultdict(list) for k in names}
    threads = {k: defaultdict(lambda: deque(maxlen=n)) for k in names}
    requested = {}
    for line in lines:
        parts = line.split(' ', 7)
        if len(parts) < 7:
            continue
        args = parts[7] if len(parts) > 7 else ''
        if parts[6] == '>':
            m = REQUESTED.search(args)
            requested[parts[4]] = int(m.group(1)) if m and int(m.group(1)) > 0 else None    # as byte_count: no size token for 0
            continue
        if parts[6] != '<':
            continue
        try:
            ts = int(parts[0])
        except ValueError:
            continue
        fact = facts(parts[5], args, requested.get(parts[4]))
        w = signals.window_end(ts)
        for k in names:
            q = threads[k][parts[4]]
            q.append(atoken(parts[5], fact, ALPHABETS[k]))
            out[k][w].append(tuple(q))
    return out


def score_windows(lm, per):
    return {w: float(np.mean(sorted((-math.log(lm.prob(g)) for g in grams), reverse=True)[:tk.TOP])) for w, grams in per.items() if grams}


def evaluate(archive, names=tuple(ALPHABETS), wanted=lambda name, split: True):
    lms = {k: tk.TokenLM() for k in names}
    for _, _, blob in v2.split_recordings(archive, {'training'}):
        per = alphabet_windows(convert.recording(blob)[1], names)
        for k in names:
            for grams in per[k].values():
                lms[k].learn(grams)
    for lm in lms.values():
        lm.finalize()
    out, meta = {}, {}
    for split, name, blob in v2.split_recordings(archive, {'validation', 'test-normal', 'test-normal_and_attack'}):
        if split != 'validation' and not wanted(name, split):
            continue
        per = alphabet_windows(convert.recording(blob)[1], names)
        cols = {k: score_windows(lms[k], per[k]) for k in names}
        ends = sorted(set().union(*cols.values()))
        key = f'val/{name}' if split == 'validation' else name
        out[key] = np.asarray([[w] + [cols[k].get(w, 0.0) for k in names] for w in ends], dtype=float).reshape(-1, 1 + len(names))
        if split != 'validation':
            meta[name] = dict(split=split, exploit=tk.meta_of(blob))
    return out, meta


def development_only(alarms, scenario):
    import lidds_ml_v2 as m
    recs = m.load(alarms)['scenarios'][scenario]['alarms']
    keep = m.part_filter(scenario, recs, 'development')
    return lambda name, split: name in recs and keep(name, recs[name])


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--archives', type=Path, required=True)
    ap.add_argument('--scenario', required=True)
    ap.add_argument('--alarms', type=Path, help='keep development recordings only; without it every recording (CB-DS)')
    ap.add_argument('--alphabets', default=','.join(ALPHABETS), help='comma-separated subset')
    ap.add_argument('--output', type=Path, required=True)
    a = ap.parse_args()
    names = tuple(a.alphabets.split(','))
    t0 = time.time()
    out, meta = evaluate(a.archives / f'{a.scenario}.zip', names, wanted=development_only(a.alarms, a.scenario) if a.alarms else lambda n, s: True)
    np.savez_compressed(a.output, **out)
    a.output.with_suffix('.json').write_text(json.dumps(dict(scenario=a.scenario, columns=['window_end', *names], recordings=meta,
                                                             seconds=time.time() - t0)))
    print(json.dumps(dict(scenario=a.scenario, recordings=len(out), seconds=round(time.time() - t0))))


if __name__ == '__main__':
    main()
