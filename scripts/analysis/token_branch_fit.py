#!/usr/bin/env python3
"""Fit the lidds-ml-v3 token branch on a normal capture of the cluster (worker tokens.jsonl), for the worker's
``tokens.models``.

Per workload: the token model (sentinel_pulse/detector/token_model.py, = lidds_ml_tokens.TokenLM) learns every window
of the training span; the threshold is the moment-Gumbel of lidds-ml-v3 fitted not on recording maxima (the cluster
has no recordings) but on the maxima of fixed time blocks of each container over the validation span (design report
section 3), at alpha / 3 (one of three branches). A workload with fewer than --minimum-blocks validation blocks gets no
model. The spans and alpha come from the run's registered protocol; this script only applies them.

With --folds K the branch is lidds-ml-v4's (sentinel_pulse/protocol/pulse-live-v3-v1-amendment-2.json): the final model
learns training + validation, the two spans together are cut into contiguous chunks of --fold-seconds dealt to K folds
in turn, each chunk is scored by the model of the other folds, and the threshold is the moment-Gumbel of those held-out
block maxima without their top 1 % (rule R4 of lidds_ml_v4.py), at alpha x --share.

    python3 token_branch_fit.py --run-root ROOT --train START END --validation START END --alpha 0.0002 \
        --block 60 --output DIR [--jobs 8 --work /var/tmp/...] [--folds 5 --fold-seconds 1800 --share 0.9]
"""
# ==============================================================================================================
# token_branch_fit.py — HỌC MÔ HÌNH TOKEN VÀ ĐẶT NGƯỠNG CHO TỪNG WORKLOAD TRÊN CỤM (ra MODELS.json cho worker).
# Đầu vào: tokens.jsonl của một lượt thu normal (và tuỳ chọn normal của một lượt live trước, ngoài các trial).
# Các bước (chế độ --folds, dùng từ lidds-ml-v4):
#   1) split(): đọc mọi tokens.jsonl, tách dòng theo workload_key ra file riêng (bỏ cửa sổ nằm trong khoảng trial).
#   2) crossfit_one() cho từng workload: cắt thời gian thành đoạn 30 phút liền nhau, chia lần lượt vào 5 fold; mỗi fold được
#      chấm bằng mô hình học 4 fold kia → điểm "giữ ra"; lấy điểm lớn nhất của mỗi (container, khối 60 s) → cực đại.
#   3) fit_crossfit(): Gumbel theo moment trên các cực đại sau khi bỏ --trim phần lớn nhất (trimmed_gumbel), ngưỡng tại
#      α′ = α × share (lidds-ml-v4/v5: bỏ 1%, 0,0002 × 0,9; lidds-ml-v5-t3, fit pulse-live-v7-fit-1118: bỏ 0,5%,
#      α′ 0,0003, --top 3); mô hình cuối học TOÀN BỘ dữ liệu; lưu <hash>.lm.json.gz.
#   4) MODELS.json = {workload: {lm, lm_sha256, threshold}}; FIT.json ghi mọi tham số và số khối vượt ngưỡng.
# Workload có ít hơn --minimum-blocks khối thì không có mô hình (không bị chấm).
# ==============================================================================================================
import argparse
from collections import Counter
import gzip
import hashlib
import itertools
import json
import math
from pathlib import Path
import sys

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from sentinel_pulse.detector.token_model import TOP, CountTokenLM, has_execve, strip  # noqa: E402
from lidds_ml_v2 import gumbel, threshold  # noqa: E402

TOP_DROP = 0.01


# Gumbel theo moment (μ, β) trên các cực đại đã bỏ 1% lớn nhất (ít nhất 1 giá trị).
def trimmed_gumbel(maxima, drop=TOP_DROP):
    """Moment Gumbel without the top share of the maxima, at least one (rule R4, as lidds_ml_v4.trimmed_gumbel)."""
    x = np.sort(np.asarray(maxima, float))
    return gumbel(x[:max(2, len(x) - max(1, int(round(len(x) * drop))))])


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


EXCLUDE_BEFORE, EXCLUDE_AFTER = 5.0, 25.0


# Các khoảng [bắt đầu − 5 s, bắt đầu + 25 s] quanh mỗi interval của campaign — bỏ ra khỏi dữ liệu normal.
def trial_spans(campaign):
    """{(pod_uid, container): [(start - 5 s, start + 25 s), ...]} of every campaign interval: a trial's process runs
    15 s from its start; the margins cover the launch through kubectl exec and its exit."""
    out = {}
    for line in (campaign / 'INTERVALS.jsonl').read_text().splitlines():
        if line:
            row = json.loads(line)
            start = float(row['start_at'])
            out.setdefault((row['pod_uid'], row['container_name']), []).append((start - EXCLUDE_BEFORE, start + EXCLUDE_AFTER))
    return out


# Tách dòng tokens.jsonl theo workload ra file tạm (đọc mỗi file nguồn đúng một lần).
def part_of(w, part):
    """session-stream-v1: the grams of one lineage part of a window, or None when that part is empty. 'session' is
    the part counted on session-lineage threads (runtime exec and descendants), 'native' the whole minus it."""
    if part == 'whole':
        return w['grams']
    if 'session' not in w:
        raise ValueError('--part needs windows of the lineage build')
    if part == 'session':
        return w['session'] or None
    left = {tuple(int(v) for v in g[:4]): int(g[4]) for g in w['grams']}
    for g in w['session']:
        key = tuple(int(v) for v in g[:4])
        left[key] -= int(g[4])
    native = [[*k, c] for k, c in left.items() if c > 0]
    return native or None


def _open(path, mode='r'):
    """A scratch file, gzip (level 1) when its name ends in .gz (--gzip-work: the split of three capture days does
    not fit the analysis host's disk uncompressed)."""
    path = str(path)
    if path.endswith('.gz'):
        return gzip.open(path, mode + 't', compresslevel=1) if 'w' in mode else gzip.open(path, 'rt')
    return open(path, mode)


def _part(path, k):
    path = str(path)
    return f'{path[:-3]}.f{k}.gz' if path.endswith('.gz') else f'{path}.f{k}'


PROG_NAMES = '{"type":"prog_names"'     # exec-identity-v1: the loader's program-name lines share tokens.jsonl


def by_program(w):
    """exec-identity-v1: {program hash: the session grams of that program} of one window (lineage build with programs)."""
    if 'session_prog' not in w:
        raise ValueError('--by-prog needs windows of the exec-identity build')
    out = {}
    for g in w['session_prog']:
        out.setdefault(int(g[5]), []).append([int(v) for v in g[:5]])
    return out


def split(sources, work, part='whole', pool_key=None, by_prog=False, prog_names=None, gzip_work=False):
    """One pass over each run: the lines of each workload into their own file (name: sha256 prefix). sources:
    [(run root, lo, hi, excluded spans per container or None)]; a window is kept when lo <= window_end < hi and it
    lies in no excluded span of its container. session-stream-v1: with part 'session' or 'native' only that lineage
    part of a window is kept (windows whose part is empty are dropped); with pool_key every workload goes to one file
    (a pooled model). exec-identity-v1: with by_prog (part 'session') the session part of a window goes per program
    to the file of key '<pool key>|prog:<hash>'; the loader's program-name lines are skipped everywhere and, with a dict
    prog_names, collected as {hash: set of names}."""
    if by_prog and part != 'session':
        raise ValueError('--by-prog needs --part session')
    handles, names = {}, {}

    def put(key, line):
        if key not in handles:
            names[key] = work / (hashlib.sha256(key.encode()).hexdigest()[:16] + ('.jsonl.gz' if gzip_work else '.jsonl'))
            handles[key] = _open(names[key], 'w')
        handles[key].write(line if line.endswith('\n') else line + '\n')
    for root, lo, hi, excluded in sources:
        for path in sorted(root.glob('workers/*/segments/*/tokens.jsonl*')):
            opener = gzip.open if path.suffix == '.gz' else open
            with opener(path, 'rt') as handle:
                first = handle.readline()
                while first.startswith(PROG_NAMES):
                    if prog_names is not None:
                        for h, n in json.loads(first)['names'].items():
                            prog_names.setdefault(h, set()).add(n)
                    first = handle.readline()
                if not first or json.loads(first)['window_end'] >= hi:
                    continue                       # a segment that starts after the span holds none of it
                for line in itertools.chain((first,), handle):
                    if line.startswith(PROG_NAMES):
                        if prog_names is not None:
                            for h, n in json.loads(line)['names'].items():
                                prog_names.setdefault(h, set()).add(n)
                        continue
                    w = json.loads(line)
                    end = w['window_end']
                    if not lo <= end < hi:
                        continue
                    if excluded and any(a <= end < b for a, b in excluded.get((w['pod_uid'], w['container_name']), ())):
                        continue
                    if by_prog:
                        for prog, grams in sorted(by_program(w).items()):
                            row = {k: v for k, v in w.items() if k not in ('session', 'session_prog')}
                            row['grams'] = grams
                            put(f"{pool_key or w['workload_key']}|prog:{prog}", json.dumps(row, separators=(',', ':')))
                        continue
                    if part != 'whole':
                        grams = part_of(w, part)
                        if grams is None:
                            continue
                        w['grams'] = grams
                        w.pop('session', None)
                        w.pop('session_prog', None)
                        line = json.dumps(w, separators=(',', ':'))
                    put(pool_key or w['workload_key'], line)
    for h in handles.values():
        h.close()
    return names


# Mở rộng khoảng cross-fit để gồm normal bổ sung nằm sau HOẶC trước capture (sửa 17/11 cho lượt v6).
def crossfit_span(train, validation, extra):
    """(train, validation) whose outer ends bound the cross-fit (crossfit_one learns and scores [train[0], validation[1]]):
    an extra normal after the capture extends the end (pulse-live-v5-fit-1110), one before it the start (pulse-live-v6-v1)."""
    if extra[0] >= validation[1]:
        return list(train), [validation[0], extra[1]]
    if extra[1] <= train[0]:
        return [extra[0], train[1]], list(validation)
    raise ValueError('the extra span overlaps the capture')


# Fold của một cửa sổ: số thứ tự đoạn 30 phút chứa nó, lấy dư cho số fold.
def fold_of(window_end, start, seconds, folds):
    """Contiguous chunks of the capture dealt to the folds in turn: a held-out window is far from most learnt windows."""
    return int((window_end - start) // seconds) % folds


# Lõi cross-fit cho MỘT workload: đếm gram theo fold, chấm mỗi fold bằng mô hình các fold khác, gom cực đại khối 60 s.
def crossfit_one(path, start, end, block, folds, seconds, top=None, load=None, score_opts=None):
    """(final model on every window, held-out block maxima, windows learnt): one parse to count, one to score each fold.
    load-threshold-v1: with a dict `load`, also the held-out maxima per block and power-of-two event class
    (load['blocks'][cell][class]) and the held-out windows' event counts (load['events'][count])."""
    grams = [Counter() for _ in range(folds)]
    parts = [_open(_part(path, k), 'w') for k in range(folds)]
    windows = 0
    with _open(path) as handle:
        for line in handle:
            w = json.loads(line)
            if start <= w['window_end'] < end:
                k = fold_of(w['window_end'], start, seconds, folds)
                for *gram, c in w['grams']:
                    grams[k][strip(gram)] += int(c)
                parts[k].write(line)
                windows += 1
    for part in parts:
        part.close()
    maxima = {}
    for k in range(folds):
        lm = CountTokenLM()
        for j in range(folds):
            if j != k:
                for gram, c in grams[j].items():
                    lm.learn(gram, c)
        lm.finalize()
        opts = score_opts or {}
        previous = {}                                   # improvement-round-2 A4: container -> (window end, raw score)
        with _open(_part(path, k)) as handle:
            for line in handle:
                w = json.loads(line)
                cell = (w['pod_uid'], w['container_name'], math.floor(w['window_end'] / block))
                score = lm.window_score(w['grams'], top, opts.get('mask'), opts.get('distinct'))
                if opts.get('persist'):
                    container = (w['pod_uid'], w['container_name'])
                    end, prior = previous.get(container, (None, 0.0))
                    previous[container] = (w['window_end'], score)
                    score = min(score, prior) if end is not None and abs(w['window_end'] - end - 0.5) < 1e-3 else 0.0
                maxima[cell] = max(maxima.get(cell, 0.0), score)
                if load is not None:
                    events = int(w.get('events') or sum(int(g[4]) for g in w['grams']))
                    cls = max(0, events).bit_length() - 1 if events > 0 else -1
                    per = load['blocks'].setdefault(cell, {})
                    per[cls] = max(per.get(cls, 0.0), score)
                    load['events'][events] = load['events'].get(events, 0) + 1
        del lm
        Path(_part(path, k)).unlink()
    final = CountTokenLM()
    for part in grams:
        for gram, c in part.items():
            final.learn(gram, c)
    return final.finalize(), maxima, windows


# Một workload trọn vẹn: cross-fit → ngưỡng Gumbel → lưu mô hình; (tuỳ chọn) dump cực đại giữ ra cho phân tích ngưỡng.
def fit_crossfit(job):
    """lidds-ml-v4 on the cluster; (key, report row, spec entry or None)."""
    key, path, train, validation, alpha, block, minimum, output, folds, seconds, share, *rest = job
    dump = rest[:1]                                        # optional: dump directory, top-k, trim (lidds-ml-v5-t3)
    top = rest[1] if len(rest) > 1 else TOP
    trim = rest[2] if len(rest) > 2 else TOP_DROP
    load_dir = rest[3] if len(rest) > 3 else None          # load-threshold-v1 dump directory
    score_opts = rest[4] if len(rest) > 4 else None        # improvement-round-2 window-score options
    load = dict(blocks={}, events={}) if load_dir else None
    lm, maxima, windows = crossfit_one(path, train[0], validation[1], block, folds, seconds, top, load, score_opts)
    if load is not None:
        target = Path(load_dir) / (hashlib.sha256(key.encode()).hexdigest()[:16] + '.load.json')
        target.write_text(json.dumps(dict(workload=key, block=block, events={str(k): v for k, v in sorted(load['events'].items())},
                                          blocks=[[*cell, {str(c): v for c, v in classes.items()}] for cell, classes in sorted(load['blocks'].items())])))
    blocks = np.asarray(list(maxima.values()), float)
    if dump and dump[0]:                                   # ml-final-study-v1 part C: the held-out block maxima
        target = Path(dump[0]) / (hashlib.sha256(key.encode()).hexdigest()[:16] + '.maxima.json')
        target.write_text(json.dumps(dict(workload=key, blocks=[[*cell, v] for cell, v in sorted(maxima.items())])))
    row = dict(training_windows=windows, validation_blocks=len(blocks), distinct_contexts=sum(len(level) for level in lm.count))
    if windows == 0 or len(blocks) < minimum:
        return key, row, None
    fit = trimmed_gumbel(blocks, trim)
    thr = threshold(fit, alpha * share)
    model = Path(output) / (hashlib.sha256(key.encode()).hexdigest()[:16] + '.lm.json.gz')
    lm.save(model)
    row.update(gumbel=fit, threshold=thr, validation_block_max=float(blocks.max()),
               validation_blocks_above=int((blocks > thr).sum()))
    entry = dict(lm=str(model), lm_sha256=sha(model), threshold=thr)
    if top != TOP:
        entry['top'] = int(top)                            # the worker's window score (TokenBranch reads it)
    for key_, value in (score_opts or {}).items():         # improvement-round-2: the worker scores as the fit did
        if value:
            entry[key_] = sorted(value) if key_ == 'mask' else value
    return key, row, entry


# (Gate v5, đã loại) Gộp mô hình mọi workload thành mô hình "pool".
def merge_models(paths):
    """The model of all workloads together: the sum of their counts (protocol lidds-ml-v5)."""
    pool = CountTokenLM()
    for path in paths:
        lm = CountTokenLM.load(Path(path))
        for level, contexts in enumerate(lm.count):
            for context, nexts in contexts.items():
                pool.count[level][context].update(nexts)
        pool.names.update(lm.names)
        for name, tokens in lm.given.items():
            pool.given[name].update(tokens)
        pool.total += lm.total
    return pool.finalize()


POOL_HOLDS = (0.0, 1.0, 2.0)     # the hold and phase seconds of protocol lidds-ml-v5


def fit_pool_threshold(job):
    """Block maxima of the pool score outside each exec hold, moment Gumbel without their top 1 %:
    (key, {hold: fit or None}, {hold: blocks}). One pass serves every hold of the protocol's candidates."""
    key, path, pool_path, start, end, block = job
    pool = CountTokenLM.load(Path(pool_path))
    maxima, last_exec = {h: {} for h in POOL_HOLDS}, {}
    with _open(path) as handle:
        for line in handle:
            w = json.loads(line)
            if not start <= w['window_end'] < end:
                continue
            container = (w['pod_uid'], w['container_name'])
            if has_execve(w['grams']):
                last_exec[container] = w['window_end']
            since = w['window_end'] - last_exec.get(container, -math.inf)
            score = pool.window_score(w['grams'])
            cell = container + (math.floor(w['window_end'] / block),)
            for hold in POOL_HOLDS:
                if not hold or since > hold:
                    maxima[hold][cell] = max(maxima[hold].get(cell, 0.0), score)
    fits = {h: (trimmed_gumbel(list(m.values())) if len(m) >= 3 else None) for h, m in maxima.items()}
    return key, fits, {h: len(m) for h, m in maxima.items()}


# Chế độ cũ (không --folds): học trên training, ngưỡng trên cực đại của validation.
def fit_one(job):
    """Learn on the training span, score the validation span, fit the Gumbel; (key, report row, spec entry or None)."""
    key, path, train, validation, alpha, block, minimum, output = job
    lm, trained = CountTokenLM(), 0
    with _open(path) as handle:
        for line in handle:
            w = json.loads(line)
            if train[0] <= w['window_end'] < train[1]:
                lm.learn_window(w['grams'])
                trained += 1
    lm.finalize()
    maxima = {}
    with _open(path) as handle:
        for line in handle:
            w = json.loads(line)
            if validation[0] <= w['window_end'] < validation[1]:
                cell = (w['pod_uid'], w['container_name'], math.floor(w['window_end'] / block))
                maxima[cell] = max(maxima.get(cell, 0.0), lm.window_score(w['grams']))
    blocks = np.asarray(list(maxima.values()), float)
    row = dict(training_windows=trained, validation_blocks=len(blocks), distinct_contexts=sum(len(level) for level in lm.count))
    if trained == 0 or len(blocks) < minimum:
        return key, row, None
    fit = gumbel(blocks)
    thr = threshold(fit, alpha / 3)
    model = Path(output) / (hashlib.sha256(key.encode()).hexdigest()[:16] + '.lm.json.gz')
    lm.save(model)
    row.update(gumbel=fit, threshold=thr, validation_block_max=float(blocks.max()),
               validation_blocks_above=int((blocks > thr).sum()))
    return key, row, dict(lm=str(model), lm_sha256=sha(model), threshold=thr)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--run-root', type=Path, required=True)
    ap.add_argument('--train', type=float, nargs=2, required=True)
    ap.add_argument('--validation', type=float, nargs=2, required=True)
    ap.add_argument('--alpha', type=float, required=True, help='system alpha; the token branch gets alpha / 3')
    ap.add_argument('--block', type=float, default=60.0)
    ap.add_argument('--minimum-blocks', type=int, default=30)
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--work', type=Path, help='scratch directory for the per-workload split (default OUTPUT/split)')
    ap.add_argument('--jobs', type=int, default=1, help='workloads fitted in parallel')
    ap.add_argument('--folds', type=int, default=0, help='cross-fit folds (lidds-ml-v4); 0 = training / validation split')
    ap.add_argument('--fold-seconds', type=float, default=1800.0)
    ap.add_argument('--share', type=float, default=1 / 3, help='share of alpha for this branch')
    ap.add_argument('--extra-run', type=Path, action='append', default=[],
                    help='a finished live run or capture whose normal is learnt too (needs --folds): its windows inside '
                    'its --extra-span, outside every campaign interval of their container (-5 s, +25 s) when it has a '
                    'campaign; repeat both options for several (exec-identity-v1 final fit: three diurnal days)')
    ap.add_argument('--extra-span', type=float, nargs=2, action='append', default=[], metavar=('START', 'END'))
    ap.add_argument('--pool-level', type=float, help='lidds-ml-v5 gate: level of the pool threshold (needs --folds)')
    ap.add_argument('--exec-hold', type=float, default=1.0, help='lidds-ml-v5 gate: seconds held after an execve')
    ap.add_argument('--top', type=int, default=TOP, help='window score: mean of the TOP highest -log p (lidds-ml-v5-t3: 3)')
    ap.add_argument('--trim', type=float, default=TOP_DROP, help='share of the highest held-out maxima dropped before the Gumbel fit')
    ap.add_argument('--dump-load', type=Path, help='load-threshold-v1: held-out block maxima per power-of-two event class and the event counts')
    ap.add_argument('--score-mask', type=int, nargs='*', default=[], help='improvement-round-2 A2: call numbers left out of the top-k')
    ap.add_argument('--score-distinct', action='store_true', help='improvement-round-2 A3: each gram once in the top-k')
    ap.add_argument('--persist', action='store_true', help='improvement-round-2 A4: score min(s_t, s_t-1) of consecutive windows')
    ap.add_argument('--part', choices=['whole', 'session', 'native'], default='whole',
                    help='session-stream-v1: learn and threshold one lineage part of each window (lineage build)')
    ap.add_argument('--pool-key', help='session-stream-v1: one pooled model of every workload under this key')
    ap.add_argument('--gzip-work', action='store_true', help='gzip (level 1) the per-workload scratch files')
    ap.add_argument('--by-prog', action='store_true',
                    help="exec-identity-v1: with --part session, one model per program hash (key '<pool key>|prog:<hash>')")
    ap.add_argument('--dump-maxima', type=Path, help='ml-final-study-v1 part C: write the held-out block maxima per workload here')
    a = ap.parse_args()
    if not a.train[0] < a.train[1] <= a.validation[0] < a.validation[1]:
        raise SystemExit('spans must be ordered: training before validation')
    a.output.mkdir(parents=True, exist_ok=False)
    work = a.work or a.output / 'split'
    work.mkdir(parents=True, exist_ok=True)
    if len(a.extra_run) != len(a.extra_span) or (a.extra_run and not a.folds):
        raise SystemExit('every --extra-run needs its --extra-span, and --folds')
    sources = [(a.run_root, a.train[0], a.validation[1], None)]
    for run, span in zip(a.extra_run, a.extra_span):
        if not span[0] < span[1]:
            raise SystemExit('an extra span must have START < END')
        campaign = run / 'pulse-development-matrix'
        sources.append((run, span[0], span[1], trial_spans(campaign) if campaign.exists() else None))   # a capture has no campaign
        try:
            a.train, a.validation = crossfit_span(a.train, a.validation, span)
        except ValueError:
            raise SystemExit('the extra spans must not overlap the capture or each other') from None
    prog_names = {}
    names = split(sources, work, a.part, a.pool_key, a.by_prog, prog_names, a.gzip_work)
    jobs = [(k, str(v), a.train, a.validation, a.alpha, a.block, a.minimum_blocks, str(a.output)) for k, v in sorted(names.items())]
    worker = fit_one
    if a.folds:
        if a.dump_maxima:
            a.dump_maxima.mkdir(parents=True, exist_ok=True)
        if a.dump_load:
            a.dump_load.mkdir(parents=True, exist_ok=True)
        opts = dict(mask=a.score_mask or None, distinct=a.score_distinct, persist=a.persist)
        jobs = [j + (a.folds, a.fold_seconds, a.share, str(a.dump_maxima) if a.dump_maxima else None, a.top, a.trim,
                     str(a.dump_load) if a.dump_load else None, opts) for j in jobs]
        worker = fit_crossfit
    if a.jobs > 1:
        from multiprocessing import Pool
        with Pool(a.jobs) as pool:
            results = pool.map(worker, jobs, chunksize=1)
    else:
        results = [worker(j) for j in jobs]
    spec, report = {}, {}
    for key, row, entry in results:
        report[key] = row
        if entry:
            spec[key] = entry
        print(f"{key:55s} train {row['training_windows']:7d} blocks {row['validation_blocks']:5d} "
              f"thr {row.get('threshold', float('nan')):7.3f} above {row.get('validation_blocks_above', '-')}", flush=True)
    if a.pool_level:
        pool_path = a.output / 'pool.lm.json.gz'
        merge_models([entry['lm'] for entry in spec.values()]).save(pool_path)
        if a.exec_hold not in POOL_HOLDS:
            raise SystemExit(f'--exec-hold must be one of {POOL_HOLDS}')
        pool_jobs = [(k, str(names[k]), str(pool_path), a.train[0], a.validation[1], a.block) for k in sorted(spec)]
        if a.jobs > 1:
            from multiprocessing import Pool
            with Pool(a.jobs) as pool:
                fits = pool.map(fit_pool_threshold, pool_jobs, chunksize=1)
        else:
            fits = [fit_pool_threshold(j) for j in pool_jobs]
        for key, by_hold, blocks in fits:
            spec[key]['pool_threshold'] = threshold(by_hold[a.exec_hold], a.pool_level)
            report[key].update(pool_gumbel={f'{h:g}': fit for h, fit in by_hold.items()},
                               pool_blocks={f'{h:g}': n for h, n in blocks.items()}, pool_threshold=spec[key]['pool_threshold'])
        (a.output / 'GATE.json').write_text(json.dumps(dict(pool=dict(lm=str(pool_path), lm_sha256=sha(pool_path)),
                                                            exec_hold_seconds=a.exec_hold, level=a.pool_level), indent=1) + '\n')
    (a.output / 'MODELS.json').write_text(json.dumps(spec, indent=1, sort_keys=True) + '\n')
    (a.output / 'FIT.json').write_text(json.dumps(dict(schema='pulse-token-branch-fit-v1', run_root=str(a.run_root),
                                                       extra_run=str(a.extra_run[0]) if len(a.extra_run) == 1 else None,
                                                       extra_span=a.extra_span[0] if len(a.extra_span) == 1 else None,
                                                       extra_runs=[str(r) for r in a.extra_run], extra_spans=a.extra_span,
                                                       part=a.part, pool_key=a.pool_key, by_prog=a.by_prog,
                                                       prog_names={h: sorted(n) for h, n in sorted(prog_names.items())},
                                                       train=a.train, validation=a.validation, alpha=a.alpha,
                                                       branch_alpha=a.alpha * (a.share if a.folds else 1 / 3), block=a.block,
                                                       folds=a.folds, fold_seconds=a.fold_seconds if a.folds else None,
                                                       top=a.top, trim=a.trim,
                                                       workloads=report),
                                                  indent=1, sort_keys=True) + '\n')
    for f in [*work.glob('*.jsonl'), *work.glob('*.jsonl.gz')]:
        f.unlink()
    work.rmdir() if not any(work.iterdir()) else None


if __name__ == '__main__':
    main()
