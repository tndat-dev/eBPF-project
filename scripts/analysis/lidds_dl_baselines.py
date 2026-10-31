#!/usr/bin/env python3
"""Deep-learning syscall HIDS baselines on LID-DS (protocol lidds-dl-baseline-v1): the LID-DS library's MLP and LSTM.

Each arm is the library's own pipeline with the configuration of its example main (algorithms/ids_mlp_main.py,
algorithms/ids_lstm_main.py at the commit recorded in the output), trained on the scenario's training recordings
by the library, thresholded by the library (MaxScoreThreshold: max anomaly score over the validation recordings,
stored as ``threshold``), and run over every test recording; ``--library-check`` also runs the library's own serial
``IDS.detect()`` and stores its results next to ours. Only the seed (protocol: 20261030) and the outcome bookkeeping are ours:

- an attack recording is detected when an alarm falls on a syscall after the first exploit time (latency = that
  syscall's time minus the exploit time); alarms before it count as false-alarm episodes;
- a normal recording with any alarm is a false-alarm recording;
- an episode is a run of alarming syscalls; a new episode starts after QUIET seconds without one (as Pulse).

Outcomes are written as the v2 rows ``(split, detected, latency, false_episodes, syscalls, subset, name)``, with the
subset (development / official) of the same recording in the lidds-evaluation-v2 output, so lidds_v3_combine.py
and the v2 summaries apply unchanged.

    python3 lidds_dl_baselines.py --lib LID-DS --scenario-dir DATA/LID-DS-2021/NAME --arm mlp \
        --v2 lidds-evaluation-v2.json.gz --models DIR --workers 8 --output part.json
    python3 lidds_dl_baselines.py --merge part.json ... --output lidds-dl-baselines.json
"""
import argparse
import gzip
import json
import multiprocessing
import os
from pathlib import Path
import subprocess
import sys
import time

SEED, QUIET = 20261030, 3.0
ARMS = ('mlp', 'lstm')
STATE = {}


def build(arm, dataloader, models):
    """The library's example pipeline of one arm -> (decider, config)."""
    from algorithms.features.impl.int_embedding import IntEmbedding
    from algorithms.features.impl.max_score_threshold import MaxScoreThreshold
    from algorithms.features.impl.ngram import Ngram
    from algorithms.features.impl.w2v_embedding import W2VEmbedding
    if arm == 'mlp':                                       # algorithms/ids_mlp_main.py
        from algorithms.decision_engines.mlp import MLP
        from algorithms.features.impl.one_hot_encoding import OneHotEncoding
        from algorithms.features.impl.select import Select
        from algorithms.features.impl.syscall_name import SyscallName
        cfg = dict(ngram_length=7, w2v_size=5, thread_aware=True, hidden_size=150, hidden_layers=4, batch_size=50,
                   learning_rate=0.003, w2v_epochs=50, direction='BOTH')
        ie = IntEmbedding(SyscallName())
        w2v = W2VEmbedding(word=ie, vector_size=cfg['w2v_size'], window_size=cfg['ngram_length'], epochs=cfg['w2v_epochs'])
        ngram = Ngram(feature_list=[w2v], thread_aware=True, ngram_length=cfg['ngram_length'] + 1)
        select = Select(ngram, start=0, end=cfg['ngram_length'] * cfg['w2v_size'])
        de = MLP(input_vector=select, output_label=OneHotEncoding(ie), hidden_size=cfg['hidden_size'],
                 hidden_layers=cfg['hidden_layers'], batch_size=cfg['batch_size'], learning_rate=cfg['learning_rate'])
        return MaxScoreThreshold(de), cfg
    from algorithms.decision_engines.lstm import LSTM            # algorithms/ids_lstm_main.py
    from algorithms.features.impl.concat import Concat
    from algorithms.features.impl.ngram_minus_one import NgramMinusOne
    cfg = dict(hidden_dim=64, hidden_layers=1, ngram_length=3, embedding_size=4, thread_aware=True, batch_size=1024,
               epochs=20, w2v_epochs=5000, return_value=False, time_delta=False, thread_change_flag=False,
               direction='CLOSE')
    ie = IntEmbedding()
    w2v = W2VEmbedding(word=ie, vector_size=cfg['embedding_size'], window_size=cfg['ngram_length'], epochs=cfg['w2v_epochs'])
    ngram = Ngram(feature_list=[w2v], thread_aware=True, ngram_length=cfg['ngram_length'] + 1)
    nm1 = NgramMinusOne(ngram=ngram, element_size=cfg['embedding_size'])
    de = LSTM(input_vector=Concat([ie, nm1]), distinct_syscalls=dataloader.distinct_syscalls_training_data(),
              input_dim=cfg['ngram_length'] * cfg['embedding_size'], epochs=cfg['epochs'],
              hidden_layers=cfg['hidden_layers'], hidden_dim=cfg['hidden_dim'], batch_size=cfg['batch_size'],
              force_train=False, model_path=str(models / 'lstm.model'))
    return MaxScoreThreshold(de), cfg


def worker_init():
    import torch
    torch.set_num_threads(1)


def outcome(i):
    """One test recording (index into STATE['tests']) -> v2 row; runs in a forked worker."""
    ids, rec = STATE['ids'], STATE['tests'][i]
    meta = rec.metadata()
    exploit = meta['time']['exploit'][0]['absolute'] if meta.get('exploit') else None
    first_after, before, n = None, [], 0
    for syscall in rec.syscalls():
        n += 1
        if ids._detect_syscall(syscall):
            t = syscall.timestamp_unix_in_ns() / 1e9
            if exploit is not None and t > exploit:
                if first_after is None:
                    first_after = t
            else:
                before.append(t)
    ids._data_preprocessor.new_recording()
    episodes = (1 + sum(1 for a, b in zip(before, before[1:]) if b - a >= QUIET)) if before else 0
    split = 'test-normal_and_attack' if exploit is not None else 'test-normal'
    return [split, first_after is not None, first_after - exploit if first_after is not None else None, episodes, n,
            None, rec.name]


def run(a):
    sys.path.insert(0, str(a.lib))
    os.chdir(a.lib)
    import torch
    from algorithms.ids import IDS
    from dataloader.dataloader_factory import dataloader_factory
    from dataloader.direction import Direction
    torch.manual_seed(SEED)
    import random
    import numpy as np
    random.seed(SEED); np.random.seed(SEED)
    scenario = a.scenario_dir.name
    a.models.mkdir(parents=True, exist_ok=True)
    direction = Direction.BOTH if a.arm == 'mlp' else Direction.CLOSE
    loader = dataloader_factory(str(a.scenario_dir), direction=direction)
    t0 = time.time()
    decider, cfg = build(a.arm, loader, a.models)
    ids = IDS(data_loader=loader, resulting_building_block=decider, create_alarms=False, plot_switch=False)
    t1 = time.time()
    ids.determine_threshold()
    t2 = time.time()
    STATE['ids'], STATE['tests'] = ids, list(loader.test_data())
    with multiprocessing.get_context('fork').Pool(a.workers, initializer=worker_init) as pool:
        rows = pool.map(outcome, range(len(STATE['tests'])), chunksize=1)
    t3 = time.time()
    check = None
    if a.library_check:                                    # the library's own serial detection, as a cross-check
        perf = ids.detect().get_results()
        check = {k: v for k, v in perf.items() if isinstance(v, (int, float, str))}
    subsets = {o[6]: o[5] for o in json.load(gzip.open(a.v2, 'rt'))['recordings'][scenario]['ngram']}
    for r in rows:
        r[5] = subsets.get(r[6])
    commit = subprocess.run(['git', '-C', str(a.lib), 'rev-parse', 'HEAD'], capture_output=True, text=True).stdout.strip()
    out = dict(schema='pulse-lidds-dl-baseline-part-v1', protocol='sentinel_pulse/protocol/lidds-dl-baseline-v1.json',
               scenario=scenario, arm=a.arm, library_commit=commit, seed=SEED, config=cfg, threshold=decider._threshold,
               seconds=dict(train=t1 - t0, threshold=t2 - t1, detect=t3 - t2), workers=a.workers, library_check=check,
               unmatched=sorted(r[6] for r in rows if r[5] is None and r[0] == 'test-normal_and_attack'),
               recordings=rows)
    a.output.write_text(json.dumps(out))
    print(json.dumps(dict(scenario=scenario, arm=a.arm, threshold=out['threshold'], seconds=out['seconds'], library_check=check,
                          attacks=sum(r[0] == 'test-normal_and_attack' for r in rows),
                          detected=sum(r[1] for r in rows), false_alarm_recordings=sum(r[0] == 'test-normal' and r[3] > 0 for r in rows))))


def merge(paths, output):
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import lidds_v3_combine as v3
    doc = dict(schema='pulse-lidds-dl-baselines-v1', protocol='sentinel_pulse/protocol/lidds-dl-baseline-v1.json',
               parts={}, recordings={})
    for p in paths:
        part = json.loads(Path(p).read_text())
        doc['parts'][f"{part['scenario']}/{part['arm']}"] = {k: part[k] for k in part if k != 'recordings'}
        doc['recordings'].setdefault(part['scenario'], {})[part['arm']] = part['recordings']
    doc['summary'] = {}
    for arm in ARMS:
        for sub in ('official', 'development'):
            pooled, per = [], {}
            for scenario, arms in doc['recordings'].items():
                if arm not in arms:
                    continue
                rows = {o[6]: (o[0], o[1], o[2], o[3] > 0, o[5]) for o in arms[arm]}
                keep = v3.subset_of(scenario, rows, sub)
                per[scenario] = v3.metrics(list(keep.values())); pooled.extend(keep.values())
            if per:
                doc['summary'].setdefault(arm, {})[sub] = dict(pooled=v3.metrics(pooled), scenarios=per)
    Path(output).write_text(json.dumps(doc, default=float))
    print(json.dumps({arm: v['official']['pooled'] for arm, v in doc['summary'].items()}, default=float, indent=1))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--lib', type=Path, help='LID-DS library checkout')
    ap.add_argument('--scenario-dir', type=Path, help='extracted LID-DS 2021 scenario (training/validation/test)')
    ap.add_argument('--arm', choices=ARMS)
    ap.add_argument('--v2', type=Path, help='lidds-evaluation-v2 output (development/official subsets)')
    ap.add_argument('--models', type=Path)
    ap.add_argument('--workers', type=int, default=8)
    ap.add_argument('--library-check', action='store_true', help="also run the library's serial detect() and store its results")
    ap.add_argument('--merge', nargs='+')
    ap.add_argument('--output', type=Path, required=True)
    a = ap.parse_args()
    if a.merge:
        merge(a.merge, a.output)
    else:
        run(a)


if __name__ == '__main__':
    main()
