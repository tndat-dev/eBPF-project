"""Score sealed, prospective 500 ms normal captures with the frozen syscall-arms arms.

This is an offline comparison. Predictions remain unadjudicated; replay time
cannot measure live kernel-to-alert latency. No fitting or promotion occurs.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict, deque
import fcntl
import gzip
import json
import math
import os
from pathlib import Path
import time

import numpy as np

from ..encoding import decode_vector, schema_digest
from ..collector.features import TRACKED_SYSCALLS
from ..integrity import contained_artifact, sha256_file
from ..common import atomic_json, load_artifact, compression_receipt, open_sealed, sealed_sha256

IDENTITY = ('node_name', 'pod_uid', 'container_name', 'workload_revision', 'cgroup_id')


class ContextBuilder:
    """syscall-arms rolling-10/history-3 preprocessing without a train/calibration split."""

    def __init__(self, spec, begin, finish):
        self.begin, self.finish = begin, finish
        self.ids = list(TRACKED_SYSCALLS)
        self.add = list(spec['add'])
        drop = set(spec['drop'])
        self.keep = [i for i in range(249) if not any(
            i == j + offset for j, number in enumerate(self.ids) if number in drop
            for offset in (0, 29, 191, 220))]
        self.states = {}
        # feature-group arms (feature_groups.py): kept columns of the 249 vector and history depth;
        # contexts are emitted at the same windows as base29 and then cut, so arms stay matched
        self.cut = spec if ('columns' in spec or spec.get('history', 3) != 3) else None

    def observe(self, row):
        a, b = float(row['window_start']), float(row['window_end'])
        ident = tuple(str(row[k]) for k in IDENTITY)
        if (not math.isfinite(a) or not math.isfinite(b) or not self.begin <= a < b <= self.finish
                or not row.get('eligible_for_normal_review') or not .35 <= b-a <= .8):
            self.states.pop(ident, None)
            return None
        prior = self.states.get(ident)
        if (prior is None or not .35 <= b-prior['end'] <= .8
                or abs(a-prior['end']) > 1e-5):
            prior = dict(rates=deque(maxlen=10), vectors=deque(maxlen=3), end=a)
            self.states[ident] = prior
        counts = row['full_counts_delta']
        rates = np.array([counts.get(str(i), 0)/(b-a) for i in self.ids+self.add])
        vector = decode_vector(row).copy()
        if len(vector) != 249 or not np.isfinite(vector).all():
            raise ValueError('invalid base feature vector')
        result = None
        if len(prior['rates']) == 10:
            history = np.asarray(prior['rates'])
            mean, std = np.log1p(history.mean(0)), np.log1p(history.std(0))
            vector[191:220], vector[220:249] = mean[:29], std[:29]
            selected = np.array([counts.get(str(i), 0) for i in self.add])
            vector = np.concatenate([vector[self.keep], np.log1p(selected),
                selected/max(row['exact_total'], 1), mean[29:], std[29:]]).astype(np.float32)
            if len(prior['vectors']) == 3:
                result = np.concatenate([*prior['vectors'], vector])
            prior['vectors'].append(vector)
        prior['rates'].append(rates)
        prior['end'] = b
        if result is not None and self.cut is not None:
            from .feature_groups import transform
            result = transform(result, self.cut)
        return result


def merged(intervals, gap=0.):
    result = []
    for a, b in sorted(intervals):
        if result and a <= result[-1][1]+gap:
            result[-1][1] = max(result[-1][1], b)
        else:
            result.append([a, b])
    return result


def bounds(path):
    """Read only the first and last complete feature records of a sealed file."""
    if not path.exists():
        # compressed: the compressor recorded the bounds before removing the original
        entry = compression_receipt(path)
        if entry and 'first_window_start' in entry:
            return entry['first_window_start'], entry['last_window_end']
        first = last = None
        with open_sealed(path) as stream:
            for line in stream:
                row = json.loads(line)
                if first is None and 'window_start' in row:
                    first = float(row['window_start'])
                if 'window_end' in row:
                    last = max(last or -math.inf, float(row['window_end']))
        return first, last
    first = last = None
    with path.open('rb') as stream:
        for line in stream:
            row = json.loads(line)
            if 'window_start' in row:
                first = float(row['window_start'])
                break
        stream.seek(max(0, path.stat().st_size-1024**2))
        if stream.tell():
            stream.readline()
        for line in stream:
            if line.endswith(b'\n'):
                row = json.loads(line)
                if 'window_end' in row:
                    last = max(last or -math.inf, float(row['window_end']))
    return first, last


def validate_row(row, node, run, keys):
    if row.get('schema') != 'sentinel-pulse-extended-feature-v2':
        raise ValueError('wrong matched feature schema')
    if row.get('telemetry_contract') != 'pulse-entered-plus-seccomp-skip-idle-v2':
        raise ValueError('wrong matched telemetry contract')
    if row.get('node_name') != node or row.get('run_id') != run:
        raise ValueError('capture source identity mismatch')
    if row.get('workload_key') not in keys:
        return False
    if any(row.get(k) is None or str(row[k]) in ('', 'unknown') for k in IDENTITY):
        raise ValueError('incomplete workload identity')
    counts = row['full_counts_delta']
    if any(not str(k).isdigit() or not 0 <= int(k) < 1024
           or type(v) is not int or v < 0 for k, v in counts.items()):
        raise ValueError('invalid full syscall delta')
    if sum(counts.values()) != row['exact_total']:
        raise ValueError('full-ID delta differs from exact total')
    return True


def score_segment(segment, node, registration, index, terminal, study, output, batch_size=512,
                  progress=None, score_sink=None):
    """One sealed segment; all arm/seed models see the same admitted contexts.

    ``score_sink(tag, rows, predictions)``, when given, receives every scored
    batch so raw scores can be kept for offline recalibration.
    """
    seal_path = segment/'TERMINAL.json'
    seal = json.loads(seal_path.read_text())
    hashes = {}
    for name in ('features.jsonl', 'decisions.jsonl', 'issues.jsonl'):
        path = segment/name
        digest = sealed_sha256(path)
        if seal.get('seals', {}).get(name) != digest:
            raise ValueError('segment checksum mismatch: '+str(path))
        hashes[name] = digest
    begin, finish = registration['holdout_start_unix'], registration['planned_end_unix']
    keys = set(registration['workload_keys'])
    builders = {}; models = {}; pending = defaultdict(list)
    counts = Counter(); totals = {}; exposure = defaultdict(list); last_order = {}
    positive_intervals = defaultdict(list)
    last_progress = time.monotonic()
    expected_schema = schema_digest(index['columns'])
    schema_seen = False
    positive_path = output/'positive-windows.jsonl.gz'
    partial = positive_path.with_suffix('.partial')
    if output.exists():
        raise ValueError('segment output already exists without completed ledger')
    output.mkdir(parents=True)

    def flush(key, sink):
        batch = pending[key]
        if not batch:
            return
        meta = [row for row, _ in batch]
        contexts = np.stack([context for _, context in batch])
        model = models[key]
        predictions = model.predict_contexts(contexts)
        if score_sink is not None:
            score_sink(key, meta, predictions)
        entry = totals.setdefault(key, dict(scored_windows=0, raw_positive_windows=0,
            tree_positive_windows=0, support_positive_windows=0, candidate_preview_positive_windows=0))
        entry['scored_windows'] += len(batch)
        entry['tree_positive_windows'] += int((predictions['tree_p'] <= model.alpha/2).sum())
        entry['support_positive_windows'] += int((predictions['support_p'] <= model.alpha/2).sum())
        flags = predictions['anomalous']
        entry['raw_positive_windows'] += int(flags.sum())
        entry['candidate_preview_positive_windows'] += int(flags.sum())
        for i in np.flatnonzero(flags):
            row = meta[i]
            positive_intervals[key].append([row['window_start'], row['window_end']])
            document = {k: row.get(k) for k in (*IDENTITY, 'workload_key', 'pod_name',
                'capture_segment', 'window_start', 'window_end', 'exact_total', 'exact_counts')}
            document.update(model_tag=key, candidate_alert_preview=True, operational_alert=False,
                alpha=float(model.alpha), normal_label='unadjudicated_observation',
                tree_score=float(predictions['tree_score'][i]), tree_p=float(predictions['tree_p'][i]),
                support_score=float(predictions['support_score'][i]), support_p=float(predictions['support_p'][i]),
                joint_p=float(predictions['joint_p'][i]), offline_replay=True,
                kernel_to_alert_seconds=None)
            sink.write(json.dumps(document, separators=(',', ':'), allow_nan=False)+'\n')
        pending[key].clear()

    with gzip.open(partial, 'wt') as positives, open_sealed(segment/'features.jsonl') as source:
        for line in source:
            row = json.loads(line)
            if 'columns' in row:
                if (row['columns'] != index['columns'] or len(row['columns']) != 249
                        or row.get('feature_schema_sha256') != expected_schema):
                    raise ValueError('base schema differs from frozen syscall-arms columns')
                schema_seen = True
                continue
            if row['window_end'] <= begin or row['window_start'] >= finish:
                continue
            if not schema_seen or row.get('feature_schema_sha256') != expected_schema or row.get('vector_dim') != 249:
                raise ValueError('feature row is not bound to the frozen syscall-arms schema')
            if not validate_row(row, node, registration['capture_run_id'], keys):
                counts['outside_registered_workload'] += 1
                continue
            workload = row['workload_key']
            ident = (workload, *[str(row[k]) for k in IDENTITY])
            if row['window_end'] <= last_order.get(ident, -math.inf):
                raise ValueError('duplicate or unordered feature window')
            last_order[ident] = row['window_end']
            counts['input_rows'] += 1
            counts['ineligible_input_rows'] += not row.get('eligible_for_normal_review', False)
            any_scored = False
            for arm, spec in index['arms'].items():
                builder = builders.get((workload, arm))
                if builder is None:
                    builder = builders[workload, arm] = ContextBuilder(spec, begin, finish)
                context = builder.observe(row)
                if context is None:
                    continue
                any_scored = True
                for seed in registration['seeds']:
                    tag = f'{workload}|{arm}|{seed}'
                    if tag not in models:
                        item = terminal['completed'][tag]
                        path = contained_artifact(study, item['artifact'])
                        if sha256_file(path) != item['sha256']:
                            raise ValueError('frozen model hash mismatch: '+tag)
                        with path.open('rb') as model_file:
                            models[tag] = load_artifact(model_file)
                        models[tag].base.estimator.n_jobs = 1
                        # feature-group history arms keep 1 or 2 previous vectors instead of 3
                        if models[tag].base.feature_dim*(spec.get('history', 3)+1) != len(context):
                            raise ValueError('matched model dimension mismatch')
                    pending[tag].append((row, context))
                    if len(pending[tag]) >= batch_size:
                        flush(tag, positives)
            if any_scored:
                exposure[workload].append([row['window_start'], row['window_end']])
            else:
                counts['unscored_input_rows'] += 1
            if progress is not None and time.monotonic()-last_progress >= 10:
                progress(dict(counts=dict(counts), loaded_models=len(models),
                              scored_contexts=sum(v['scored_windows'] for v in totals.values())))
                last_progress = time.monotonic()
        for tag in sorted(pending):
            flush(tag, positives)
    os.replace(partial, positive_path)
    result = dict(schema='pulse-r4-holdout-segment-evaluation-v1', node_name=node,
        segment=str(segment), source_seals=hashes, terminal_sha256=sha256_file(seal_path),
        counts=dict(counts), model_counts=totals,
        scored_intervals={k: merged(v) for k, v in exposure.items()},
        positive_episodes={k: merged(v, registration['episode_quiet_seconds']) for k, v in positive_intervals.items()},
        positive_windows_sha256=sha256_file(positive_path),
        labels_adjudicated=False, precision=None, recall=None, kernel_to_alert_seconds=None,
        automatic_promotion=False, completed_at_unix=time.time())
    atomic_json(output/'RESULTS.json', result)
    return result


def aggregate(results, keys):
    exposure = defaultdict(list); episodes = defaultdict(list); totals = {}; counts = Counter()
    for result in results:
        counts.update(result['counts'])
        for key, items in result['scored_intervals'].items():
            exposure[key].extend(items)
        for tag, items in result['positive_episodes'].items():
            episodes[tag].extend(items)
        for tag, metrics in result['model_counts'].items():
            total = totals.setdefault(tag, Counter())
            total.update(metrics)
    hours = {key: sum(b-a for a, b in merged(exposure[key]))/3600 for key in keys}
    return dict(counts=dict(counts), valid_scored_workload_hours=hours,
        missing_scored_workloads=[key for key, hours in hours.items() if not hours],
        pooled_valid_workload_hours=sum(hours.values()),
        model_counts={tag: dict(value, unadjudicated_positive_episodes=len(merged(episodes[tag], 15.)))
                      for tag, value in totals.items()},
        labels_adjudicated=False, confirmed_precision=None, confirmed_FPR=None, recall=None,
        confusion_matrix={'TP': None, 'FP': None, 'TN': None, 'FN': None},
        kernel_to_alert_seconds=None, automatic_promotion=False)


def run(study, output, once=False, poll_seconds=30):
    registration_path = study/'NORMAL_HOLDOUT_START.json'
    registration = json.loads(registration_path.read_text())
    audit_path = study/'R4_FIT_AUDIT.json'
    audit = json.loads(audit_path.read_text())
    if sha256_file(audit_path) != registration['fit_audit_sha256']:
        raise ValueError('fit audit changed since holdout registration')
    if sha256_file(study/'TERMINAL.json') != registration['r4_terminal_sha256']:
        raise ValueError('syscall-arms terminal changed since holdout registration')
    terminal = json.loads((study/'TERMINAL.json').read_text())
    if sha256_file(study/'INDEX.json') != audit['binding']['index_sha256']:
        raise ValueError('syscall-arms arm index changed')
    if sha256_file(Path(__file__).with_name('matched_study.py')) != registration['matched_study_source_sha256']:
        raise ValueError('syscall-arms preprocessing source differs from registration')
    index = json.loads((study/'INDEX.json').read_text())
    registration = dict(registration, seeds=[73021, 73022, 73023], episode_quiet_seconds=15.)
    output.mkdir(parents=True, exist_ok=True)
    with (output/'evaluation.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        binding = dict(schema='pulse-r4-prospective-normal-evaluator-v1',
            registration_sha256=sha256_file(registration_path),
            fit_audit_sha256=sha256_file(audit_path), source_sha256=sha256_file(Path(__file__)),
            preprocessing='syscall-arms rolling10 + history3, reset at sealed segment and continuity gaps',
            episode_quiet_seconds=15., episode_unit='workload/arm/seed, union across replicas',
            estimator_rule='joint_p <= frozen per-model alpha; tree/support, no semantic gate',
            predictions='unadjudicated normal observations; preserve every positive',
            inference='offline replay; no live latency estimate',
            registered_at_unix=time.time(), automatic_promotion=False)
        start_path = output/'START.json'
        if start_path.exists():
            existing = json.loads(start_path.read_text())
            binding['registered_at_unix'] = existing['registered_at_unix']
            if binding != existing:
                raise ValueError('evaluator registration changed')
        else:
            atomic_json(start_path, binding)
        ledger = {}; result_path = output/'SEGMENTS.json'
        if result_path.exists():
            ledger = json.loads(result_path.read_text())
        while True:
            latest = {}; waiting = {}
            for node, worker in registration['workers'].items():
                latest[node] = None
                terminals = sorted(Path(worker['output']).glob('segments/s*/TERMINAL.json'))
                for path in terminals:
                    segment = path.parent
                    key = node+'/'+segment.name
                    first, last = bounds(segment/'features.jsonl')
                    if last is not None:
                        latest[node] = max(latest[node] or last, last)
                    if key in ledger or first is None or last <= registration['holdout_start_unix'] or first >= registration['planned_end_unix']:
                        continue
                    atomic_json(output/'STATUS.json', dict(state='scoring_sealed_segment', current_segment=key,
                        completed_segments=len(ledger), updated_at_unix=time.time(),
                        planned_end_unix=registration['planned_end_unix'], automatic_promotion=False))
                    dest = output/'segments'/node/segment.name
                    if (dest/'RESULTS.json').exists():
                        result = json.loads((dest/'RESULTS.json').read_text())
                    else:
                        def progress(metrics):
                            atomic_json(output/'STATUS.json', dict(state='scoring_sealed_segment',
                                current_segment=key, completed_segments=len(ledger), **metrics,
                                updated_at_unix=time.time(), planned_end_unix=registration['planned_end_unix'],
                                automatic_promotion=False))
                        result = score_segment(segment, node, registration, index, terminal, study, dest,
                                               progress=progress)
                    ledger[key] = str(dest/'RESULTS.json')
                    atomic_json(result_path, ledger)
                if latest[node] is None or latest[node] < registration['planned_end_unix']:
                    waiting[node] = 'awaiting sealed capture through registered holdout end'
            report = aggregate([json.loads(Path(p).read_text()) for p in ledger.values()], registration['workload_keys'])
            complete = not waiting and time.time() >= registration['planned_end_unix']
            report.update(state='completed_unadjudicated_normal_evaluation' if complete else 'collecting_and_scoring_normal_holdout',
                completed_segments=len(ledger), sealed_coverage_end=latest, waiting=waiting,
                holdout_start_unix=registration['holdout_start_unix'], planned_end_unix=registration['planned_end_unix'],
                wall_progress=min(1., max(0., (time.time()-registration['holdout_start_unix'])/86400)),
                registered_workload_keys=len(registration['workload_keys']), expected_models=693,
                updated_at_unix=time.time(), fresh_blind_complete=False)
            atomic_json(output/'STATUS.json', report)
            if complete:
                atomic_json(output/'TERMINAL.json', report)
            if once or complete:
                return report
            time.sleep(poll_seconds)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--study', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--once', action='store_true')
    args = parser.parse_args()
    run(args.study.resolve(), args.output.resolve(), args.once)


if __name__ == '__main__':
    main()
