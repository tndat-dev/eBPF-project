"""Argument, return-value and sequence signals of LID-DS 2021 recordings (protocol lidds-evaluation-v2).

Per 0.5 s window (window_end = floor(ts / 0.5) * 0.5 + 0.5, the grid of convert.py and of the v1 STIDE arm), from
the syscall lines of one recording:

- ``paths``:  every open / openat / openat2 / creat exit as (mode, prefix, path): path = the resolved path of a
  successful open (``fd=N(<f>PATH)``), else the absolute form sysdig prints in ``name=x(/abs/x)``, else ``name=``;
  normalised lexically; mode 'w' when the flags carry O_WRONLY, O_RDWR, O_CREAT, O_TRUNC or O_APPEND (creat: 'w');
  prefix = the first PREFIX_LEVELS components of the path's directory (ReplicaWatcher uses directory prefixes);
- ``errors``: every exit with a negative return value as (syscall, errno name);
- ``bytes``:  every read-like / write-like exit with res > 0 as (direction, min(15, floor(log2(res))));
- ``ngrams``: every completed per-thread n-gram of syscall entry names (STIDE, as the v1 arm).

Nothing here is specific to a scenario: novelty and ranges are learnt from each workload's own normal recordings.
"""
from __future__ import annotations

from collections import Counter, defaultdict, deque
import math
import posixpath
import re

WINDOW_NS = 500_000_000
PREFIX_LEVELS = 3
BYTE_BUCKETS = 16
NGRAM_N = 7
OPENS = {'open', 'openat', 'openat2', 'creat'}
WRITE_FLAGS = ('O_WRONLY', 'O_RDWR', 'O_CREAT', 'O_TRUNC', 'O_APPEND')
READS = {'read', 'pread', 'pread64', 'readv', 'preadv', 'recv', 'recvfrom', 'recvmsg', 'recvmmsg'}
WRITES = {'write', 'pwrite', 'pwrite64', 'writev', 'pwritev', 'send', 'sendto', 'sendmsg', 'sendmmsg', 'sendfile', 'splice'}

FD_PATH = re.compile(r'\bfd=(-?\d+)\(<f>([^)]*)\)')
FD_ERR = re.compile(r'\bfd=(-\d+)\((E[A-Z0-9]+)\)')
RES = re.compile(r'\bres=(-?\d+)(?:\((E[A-Z0-9]+)\))?')
NAME = re.compile(r'\bname=(\S+)')
FLAGS = re.compile(r'\bflags=\d+\(([^)]*)\)')


def window_end(ts_ns: int) -> float:
    return (ts_ns // WINDOW_NS + 1) * 0.5


def normal_path(raw: str) -> str:
    """'x(/abs/x)' -> '/abs/x'; lexical normalisation; relative names kept relative (cwd unknown)."""
    m = re.fullmatch(r'(.*)\((/.*)\)', raw)
    path = m.group(2) if m else raw
    return posixpath.normpath(path) if path else path


def prefix(path: str, levels: int = PREFIX_LEVELS) -> str:
    directory = posixpath.dirname(path)
    parts = [p for p in directory.split('/') if p]
    head = '/' if path.startswith('/') else 'rel:'
    return head + '/'.join(parts[:levels])


def open_path(args: str):
    """(mode, path) of an open-like exit, or None."""
    m = FD_PATH.search(args)
    if m and int(m.group(1)) >= 0 and m.group(2):
        path = posixpath.normpath(m.group(2))
    else:
        n = NAME.search(args)
        if not n:
            return None
        path = normal_path(n.group(1))
    f = FLAGS.search(args)
    mode = 'w' if f and any(flag in f.group(1).split('|') for flag in WRITE_FLAGS) else 'r'
    return mode, path


def error_of(args: str):
    m = RES.search(args)
    if m and int(m.group(1)) < 0:
        return m.group(2) or str(-int(m.group(1)))
    m = FD_ERR.search(args)
    return m.group(2) if m else None


def byte_count(args: str):
    m = RES.search(args)
    return int(m.group(1)) if m and int(m.group(1)) > 0 else None


def bucket(n: int) -> int:
    return min(BYTE_BUCKETS - 1, int(math.log2(n)))


def recording_signals(lines, n=NGRAM_N):
    """{window_end: dict(paths=[(mode, prefix, path)], errors=Counter, bytes=Counter, ngrams=[tuple])}."""
    out = defaultdict(lambda: dict(paths=[], errors=Counter(), bytes=Counter(), ngrams=[]))
    threads = defaultdict(lambda: deque(maxlen=n))
    for line in lines:
        parts = line.split(' ', 7)
        if len(parts) < 7:
            continue
        try:
            ts = int(parts[0])
        except ValueError:
            continue
        name, direction, args = parts[5], parts[6], parts[7] if len(parts) > 7 else ''
        w = window_end(ts)
        if direction == '>':
            q = threads[parts[4]]; q.append(name)
            if len(q) == n:
                out[w]['ngrams'].append(tuple(q))
            continue
        if direction != '<':
            continue
        if name in OPENS:
            got = open_path(args)
            if got:
                mode, path = got
                out[w]['paths'].append(('w' if name == 'creat' else mode, prefix(path), path))
        err = error_of(args)
        if err is not None:
            out[w]['errors'][(name, err)] += 1
        elif name in READS or name in WRITES:
            size = byte_count(args)
            if size is not None:
                out[w]['bytes'][('out' if name in WRITES else 'in', bucket(size))] += 1
    return dict(out)


class Reference:
    """What the normal training recordings of one workload showed."""

    def __init__(self):
        self.prefixes, self.paths, self.errors, self.ngrams = set(), set(), set(), set()
        self.error_max, self.byte_max = Counter(), Counter()

    def learn(self, windows):
        for s in windows.values():
            for mode, pre, path in s['paths']:
                self.prefixes.add((mode, pre)); self.paths.add((mode, path))
            self.errors.update(s['errors']); self.ngrams.update(s['ngrams'])
            self.widen(s)

    def widen(self, s):
        """Per-window maxima of error-pair and byte-bucket counts (normal ranges: training and validation)."""
        for k, v in s['errors'].items():
            self.error_max[k] = max(self.error_max[k], v)
        for k, v in s['bytes'].items():
            self.byte_max[k] = max(self.byte_max[k], v)

    def novelty(self, s):
        """Novelty counts of one window against the training reference."""
        return dict(prefix_w=sum(m == 'w' and (m, p) not in self.prefixes for m, p, _ in s['paths']),
                    prefix_r=sum(m == 'r' and (m, p) not in self.prefixes for m, p, _ in s['paths']),
                    path_w=sum(m == 'w' and (m, q) not in self.paths for m, _, q in s['paths']),
                    path_r=sum(m == 'r' and (m, q) not in self.paths for m, _, q in s['paths']),
                    error_new=sum(v for k, v in s['errors'].items() if k not in self.errors),
                    ngram_new=sum(g not in self.ngrams for g in s['ngrams']))

    def over_range(self, s):
        """Error pairs and byte buckets of one window above their normal per-window maximum (count of features)."""
        return dict(error_over=sum(v > self.error_max[k] for k, v in s['errors'].items() if k in self.errors),
                    bytes_over=sum(v > self.byte_max[k] for k, v in s['bytes'].items()))


BRANCHES = dict(path=('prefix_w', 'prefix_r', 'path_w', 'path_r'), errno=('error_new', 'error_over'),
                bytes=('bytes_over',), ngram=('ngram_new',))


def scores(reference, s):
    return {**reference.novelty(s), **reference.over_range(s)}


def thresholds(reference, validation_windows):
    """Max of every score over the validation windows (the LID-DS library's max-validation-score rule)."""
    out = Counter()
    for s in validation_windows:
        for k, v in scores(reference, s).items():
            out[k] = max(out[k], v)
    return out


def branch_alarms(reference, limits, windows):
    """{branch: {window_end: alarm}} of one recording: a branch alarms when any of its scores exceeds its limit."""
    out = {b: {} for b in BRANCHES}
    for w, s in windows.items():
        sc = scores(reference, s)
        for b, keys in BRANCHES.items():
            out[b][w] = any(sc[k] > limits[k] for k in keys)
    return out
