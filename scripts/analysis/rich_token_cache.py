#!/usr/bin/env python3
"""improvement-round-v1 D8 (richer tokens) and D17 (process context): fact-gram caches with more detail, in the layout of
lidds_token_cache.py so lidds_token_study.score_scenario scores them unchanged.

Variants (one cache directory each):
  path2    an open keeps two directory levels (openat:r:/usr/lib) instead of one (openat:r:/usr);
  connect  (also inside path2, used only when the spec lists connect) a successful connect keeps the socket family and the class of the remote port (well-known < 1024, registered,
           ephemeral >= 49152; unix sockets as 'u'): fact (connect, 'o', 'af:class'), so the open list of the spec holds it;
  exec     the thread history is cleared at a successful execve and the new program's name is pushed as a token
           (fact (comm, 'o', name)): grams carry the process, and a new program starts its own history.

    python3 rich_token_cache.py --variant path2 --archives DIR --scenario S --output caches/S.npz \
        [--alarms a.json.gz --part development | --split split.json --split-part development]
"""
# CACHE TOKEN GIÀU HƠN (vòng cải thiện D8, D17): đường dẫn hai cấp, đích connect, và ngữ cảnh process (reset khi execve).
import argparse
from collections import Counter, defaultdict, deque
import json
from pathlib import Path
import re
import sys
import time
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lidds_token_cache as tc  # noqa: E402

al, signals, convert, v2, tk = tc.al, tc.signals, tc.convert, tc.v2, tc.tk
VARIANTS = ('path2', 'connect', 'exec')
INET = re.compile(r'\(<(\w+)>[^)]*?->[^)]*?:(\d+)\)')
UNIX = re.compile(r'\(<u>')


def port_class(port):
    return 'wk' if port < 1024 else 'eph' if port >= 49152 else 'reg'


def fact(variant, name, args):
    base = tc.fact(name, args)
    if variant == 'path2' and base[1] == 'o':
        got = signals.open_path(args)
        if got:
            mode, path = got
            parts = [p for p in path.split('/') if p]
            if path.startswith('/') and len(parts) > 2:
                return name, 'o', f"{'w' if name == 'creat' else mode}:/{parts[0]}/{parts[1]}"
    if variant in ('connect', 'path2') and name == 'connect' and base[1] != 'e':      # path2 carries it too; the spec decides
        m = INET.search(args)
        if m:
            return name, 'o', f'{m.group(1)}:{port_class(int(m.group(2)))}'
        if UNIX.search(args):
            return name, 'o', 'u'
    return base


def recording_rows(variant, lines, vocab, n):
    rows = Counter()
    threads = defaultdict(lambda: deque(maxlen=n))
    pad = (-1,) * n

    def push(tid, f, ts):
        i = vocab.get(f)
        if i is None:
            i = vocab[f] = len(vocab)
        q = threads[tid]
        q.append(i)
        rows[(signals.window_end(ts),) + pad[len(q):] + tuple(q)] += 1

    for line in lines:
        parts = line.split(' ', 7)
        if len(parts) < 7 or parts[6] != '<':
            continue
        try:
            ts = int(parts[0])
        except ValueError:
            continue
        args = parts[7] if len(parts) > 7 else ''
        f = fact(variant, parts[5], args)
        push(parts[4], f, ts)
        if variant == 'exec' and parts[5] == 'execve' and f[1] != 'e':
            threads[parts[4]].clear()
            push(parts[4], ('comm', 'o', parts[3]), ts)
    return rows


def build(variant, archive, output, wanted, n):
    vocab, meta, events = {}, {}, 0
    with zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED, compresslevel=1) as z:
        for split, name, blob in v2.split_recordings(archive, {'training', 'validation', 'test-normal', 'test-normal_and_attack'}):
            learning = split in ('training', 'validation')
            if not learning and not wanted(name, split):
                continue
            rows = recording_rows(variant, convert.recording(blob)[1], vocab, n)
            events += sum(rows.values())
            tc.save(z, f'fit/{name}' if learning else name, rows, n)
            meta[name] = dict(split=split, exploit=None if learning else tk.meta_of(blob), rows=len(rows))
    return [list(f) for f in sorted(vocab, key=lambda f: vocab[f])], meta, events


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--variant', choices=VARIANTS, required=True)
    ap.add_argument('--archives', type=Path, required=True)
    ap.add_argument('--scenario', required=True)
    ap.add_argument('--alarms', type=Path, help='LID-DS 2021: keep one part of the registered split')
    ap.add_argument('--part', choices=('development', 'official'), default='development')
    ap.add_argument('--split', type=Path, help='LID-DS 2019: split.json of lidds2019_dev.py')
    ap.add_argument('--split-part', default='development')
    ap.add_argument('--n', type=int, default=4)
    ap.add_argument('--output', type=Path, required=True)
    a = ap.parse_args()
    if a.split:
        names = {k for k, v in json.loads(a.split.read_text())['scenarios'][a.scenario].items() if v == a.split_part}
        wanted = lambda name, split: name in names
        part = a.split_part
    elif a.alarms:
        wanted, part = tc.part_only(a.alarms, a.scenario, a.part), a.part
    else:
        wanted, part = (lambda name, split: True), 'all'
    t0 = time.time()
    partial = a.output.with_suffix('.part')
    vocab, meta, events = build(a.variant, a.archives / f'{a.scenario}.zip', partial, wanted, a.n)
    partial.rename(a.output)
    a.output.with_suffix('.json').write_text(json.dumps(dict(schema='lidds-token-cache-v1', variant=a.variant, scenario=a.scenario,
                                                            n=a.n, vocab=vocab, part=part, recordings=meta, events=events,
                                                            seconds=time.time() - t0)))
    print(json.dumps(dict(variant=a.variant, scenario=a.scenario, recordings=len(meta), facts=len(vocab), events=events,
                          seconds=round(time.time() - t0))))


if __name__ == '__main__':
    main()
