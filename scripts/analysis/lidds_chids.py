#!/usr/bin/env python3
"""CHIDS (El Khairi et al., CCSW 2022) on LID-DS 2021 (protocol lidds-dl-baseline-v1, arm ``chids``).

The published code (github.com/Asbatel/ContainerHIDS, commit recorded in the output) reads a .scap file with
``sysdig -r`` into a table (timestamp, syscall, args = the tokens of sysdig's %evt.info), chunks it into 1 s
sequences, encodes each as a syscall sequence graph and three features (fold increase, unseen syscalls, unseen
arguments), and trains an autoencoder whose threshold is theta x the largest training reconstruction error.
LID-DS 2021 recordings are sysdig text lines with the same %evt.info tokens, so this runner builds that table from
each recording (both event directions, the code's own noise filter) and calls the code's classes unchanged:
SeenSyscalls, SeenArgs, Trace (chunking), AnomalyVector (SSG features), Training (autoencoder, its config.py).

Ours: reading the recordings, the seed (20261030), and per-sequence errors so that alarms have a time (the code's
Testing only says whether a trace has an anomalous sequence; the error is the same mean squared error of the same
model). Arms:

- ``chids``: theta = 1.4 as published (protocol);
- ``chids_maxval``: threshold = largest error over the validation recordings' sequences (the rule of every other arm).

A sequence alarms at its interval end; an attack recording is detected by an alarm ending after the first exploit
time, as for Pulse's windows; rows as lidds_evaluate_v2.py, subsets from the v2 output.

    python3 lidds_chids.py --chids ContainerHIDS --archive Juice-Shop.zip --v2 lidds-evaluation-v2.json.gz \
        --workers 8 --output part.json
"""
import argparse
import gzip
import io
import json
import multiprocessing
import os
from pathlib import Path
import subprocess
import sys
import time
import zipfile

SEED, THETA, QUIET = 20261030, 1.4, 3.0
NOISE = ('container', 'json', 'expecting', 'falcosecurity-libs')    # chids.shared.constants.NOISY_SCAP_METADATA
STATE = {}


def members(archive, split):
    outer = zipfile.ZipFile(archive)
    for m in sorted(outer.namelist()):
        if m.endswith('.zip') and not m.startswith('__MACOSX') and '/'.join(m.split('/')[1:-1]).replace('/', '-') == split:
            yield m.rsplit('/', 1)[-1][:-4], m


def table(archive, member):
    """Recording -> (DataFrame timestamp/syscall/args as chids.helpers.sysdig.Sysdig.process_scap, exploit time)."""
    import pandas as pd
    blob = zipfile.ZipFile(archive).read(member)
    z = zipfile.ZipFile(io.BytesIO(blob))
    meta = json.loads(z.read(next(n for n in z.namelist() if n.endswith('.json'))))
    rows = []
    for line in z.read(next(n for n in z.namelist() if n.endswith('.sc'))).decode(errors='replace').splitlines():
        p = line.split(' ', 7)
        if len(p) < 7:
            continue
        # sysdig -r line: num time cpu proc (tid) dir type info; the code drops lines naming its noise words
        shown = f"0 {p[0]} 0 {p[3]} ({p[4]}) {p[6]} {p[5]} {p[7] if len(p) > 7 else ''}"
        if any(w in shown for w in NOISE) or len(shown) <= 20:
            continue
        rows.append((int(p[0]), p[5], (p[7] if len(p) > 7 else '').split()))
    df = pd.DataFrame(rows, columns=['timestamp', 'syscall', 'args'])
    df['timestamp'] = pd.to_datetime(df['timestamp'], unit='ns')
    exploit = meta['time']['exploit'][0]['absolute'] if meta.get('exploit') else None
    return df, exploit


def sequences(df):
    """chids Trace._chunk_scap on one recording -> [(interval end, unix s), sequence DataFrame]."""
    import pandas as pd
    from chids.conf.config import SEQUENCE_DURATION
    from chids.utils.trace import Trace
    seqs = Trace([df])._chunk_scap(df)
    t = pd.to_datetime(df['timestamp'])
    end = t.iloc[-1] if not pd.isnull(t.iloc[-1]) else t.iloc[-2]
    starts = pd.date_range(start=t.iloc[0], end=end, freq=SEQUENCE_DURATION)
    step = pd.Timedelta(SEQUENCE_DURATION)
    return [((s + step).value / 1e9, q) for s, q in zip(starts, seqs)]


def seen(member):
    from chids.utils.seen_args import SeenArgs
    from chids.utils.seen_syscalls import SeenSyscalls
    df, _ = table(STATE['archive'], member)
    lengths = [len(q) for _, q in sequences(df)]
    return set(SeenSyscalls([df])._syscalls_per_scap(df)), SeenArgs([df])._get_args(df), max(lengths) if lengths else 0


def vectors(member):
    """[(interval end, anomaly vector)] of one recording, empty sequences dropped as chids' _format_input does."""
    from chids.utils.anomaly_vector import AnomalyVector
    df, exploit = table(STATE['archive'], member)
    seqs = sequences(df)
    av = AnomalyVector([], STATE['seen_syscalls'], STATE['seen_args'], STATE['max_freq'])
    out = av.construct_anomaly_vector([q for _, q in seqs])
    return [(e, v) for (e, _), v in zip(seqs, out) if v], exploit


def errors(model, vecs):
    import numpy as np
    if not vecs:
        return np.zeros(0)
    x = np.array(vecs, dtype=float).reshape(len(vecs), 1, 3)
    pred = model.predict(x, verbose=0).reshape(len(vecs), 3)
    return np.mean(np.square(pred - x.reshape(len(vecs), 3)), axis=1)


def outcome(ends, errs, threshold, exploit, split, name, subset):
    alarms = sorted(e for e, x in zip(ends, errs) if x > threshold)
    after = [e for e in alarms if exploit is not None and e > exploit]
    before = [e for e in alarms if exploit is None or e <= exploit]
    episodes = (1 + sum(1 for a, b in zip(before, before[1:]) if b - a >= QUIET)) if before else 0
    return [split, bool(after), after[0] - exploit if after else None, episodes, len(ends), subset, name]


def pool(fn, items, workers):
    with multiprocessing.get_context('fork').Pool(workers) as p:
        return p.map(fn, items, chunksize=1)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--chids', type=Path, required=True, help='ContainerHIDS checkout')
    ap.add_argument('--archive', type=Path, required=True, help='LID-DS 2021 scenario zip')
    ap.add_argument('--v2', type=Path, required=True)
    ap.add_argument('--workers', type=int, default=8)
    ap.add_argument('--output', type=Path, required=True)
    a = ap.parse_args()
    sys.path.insert(0, str(a.chids))
    os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'
    import numpy as np
    STATE['archive'] = a.archive
    scenario = a.archive.stem
    t0 = time.time()
    train = [m for _, m in members(a.archive, 'training')]
    got = pool(seen, train, a.workers)
    STATE['seen_syscalls'] = sorted(set().union(*(g[0] for g in got)))
    STATE['seen_args'] = sorted(set().union(*(g[1] for g in got)))
    STATE['max_freq'] = max(g[2] for g in got)
    train_vecs = [v for vs, _ in pool(vectors, train, a.workers) for _, v in vs]
    import random
    import tensorflow as tf
    from chids.ML.train_model import Training
    random.seed(SEED); np.random.seed(SEED); tf.random.set_seed(SEED)
    thresh_list, model = Training([train_vecs]).train_model()       # its _format_input flattens one level
    t1 = time.time()
    val = [v for vs, _ in pool(vectors, [m for _, m in members(a.archive, 'validation')], a.workers) for _, v in vs]
    maxval = float(errors(model, val).max())
    published = float(thresh_list[int(round(THETA / 0.2)) - 1])
    t2 = time.time()
    subsets = {o[6]: o[5] for o in json.load(gzip.open(a.v2, 'rt'))['recordings'][scenario]['ngram']}
    rows = {'chids': [], 'chids_maxval': []}
    for split in ('test-normal', 'test-normal_and_attack'):
        names = list(members(a.archive, split))
        for (name, _), (vs, exploit) in zip(names, pool(vectors, [m for _, m in names], a.workers)):
            ends = [e for e, _ in vs]
            errs = errors(model, [v for _, v in vs])
            rows['chids'].append(outcome(ends, errs, published, exploit, split, name, subsets.get(name)))
            rows['chids_maxval'].append(outcome(ends, errs, maxval, exploit, split, name, subsets.get(name)))
    t3 = time.time()
    commit = subprocess.run(['git', '-C', str(a.chids), 'rev-parse', 'HEAD'], capture_output=True, text=True).stdout.strip()
    for arm, r in rows.items():
        out = dict(schema='pulse-lidds-dl-baseline-part-v1', protocol='sentinel_pulse/protocol/lidds-dl-baseline-v1.json',
                   scenario=scenario, arm=arm, chids_commit=commit, seed=SEED, theta=THETA if arm == 'chids' else None,
                   threshold=published if arm == 'chids' else maxval, thresholds_published=[float(x) for x in thresh_list],
                   seen_syscalls=len(STATE['seen_syscalls']), seen_args=len(STATE['seen_args']), max_freq=STATE['max_freq'],
                   training_vectors=len(train_vecs), seconds=dict(train=t1 - t0, threshold=t2 - t1, detect=t3 - t2),
                   recordings=r)
        path = a.output.with_name(a.output.name.replace('ARM', arm))
        path.write_text(json.dumps(out))
        att = [x for x in r if x[0] == 'test-normal_and_attack']; nor = [x for x in r if x[0] == 'test-normal']
        print(json.dumps(dict(scenario=scenario, arm=arm, threshold=out['threshold'], detected=sum(x[1] for x in att),
                              attacks=len(att), false_alarm_recordings=sum(x[3] > 0 for x in nor), normals=len(nor),
                              seconds=out['seconds'])))


if __name__ == '__main__':
    main()
