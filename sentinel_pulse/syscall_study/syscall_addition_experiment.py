"""Isolated, checkpointed syscall *addition* study on sealed full-ID histograms.

All variants use the SAME 1-second entry-only observable. This is not a replay
of the 500ms Pulse candidate: histogram captures contain no task transitions,
and 1s counts must never be divided into invented 500ms observations.
"""
from __future__ import annotations

import argparse
import ast
from collections import Counter, defaultdict, deque
import fcntl
import importlib.metadata
import json
import math
from pathlib import Path
import platform
import sys
import time

from ..integrity import sha256_file
from .syscall_histogram_analysis import (
    interval_regime, latest_metadata, load_metadata, load_traffic_receipt,
    read_jsonl, summarize, workload_identity,
)
from ..common import atomic_json


PROFILE = 'histogram-entry-only-1000ms-rolling10-no-transition-v1'
VARIANTS = ('base29', 'plus_top8', 'plus_top16', 'plus_top32', 'plus_all_observed')
HISTORY = 3
ROLLING = 10
ALPHA = .005
MAX_SNAPSHOT_BOUNDARY_GAP_SECONDS = .05


def tracked_from_source(path):
    tree = ast.parse(path.read_text())
    result = next(ast.literal_eval(n.value) for n in tree.body
                  if isinstance(n, ast.AnnAssign) and isinstance(n.target, ast.Name)
                  and n.target.id == 'TRACKED_SYSCALLS')
    if len(result) != 29 or any(type(k) is not int for k in result):
        raise ValueError('expected explicit baseline 29 IDs')
    return result


def phase_for(begin, end, probe_start, probe_end, split):
    if begin < probe_start or end > probe_end:
        return None
    if split == 'holdout':
        return 'holdout'
    if split != 'selection':
        raise ValueError('unsupported cohort split')
    cut = probe_start + .7 * (probe_end - probe_start)
    if end < cut - 2.:
        return 'train'
    if begin > cut + 2.:
        return 'calibration'
    return None


def choose_variants(training_counts, baseline):
    # The only ranking input is the training prefix, never calibration/holdout.
    if any(type(k) is not int or not 0 <= k < 1024 or type(v) is not int or v < 0
           for k, v in training_counts.items()):
        raise ValueError('invalid training ID/count')
    ranked = [k for k, v in sorted(training_counts.items(), key=lambda x: (-x[1], x[0]))
              if v and k not in baseline]
    return dict(base29=tuple(sorted(baseline)), **{
        name: tuple(sorted(set(baseline) | set(ranked[:limit])))
        for name, limit in [('plus_top8', 8), ('plus_top16', 16),
                            ('plus_top32', 32), ('plus_all_observed', len(ranked))]
    }), ranked


def histogram_vector(counts, seconds, prior_rates, ids, sensitive):
    import numpy as np
    if not math.isfinite(seconds) or seconds <= 0:
        raise ValueError('invalid interval length')
    total = sum(counts.values())
    selected = np.asarray([counts.get(k, 0) for k in ids], dtype=np.float64)
    other = total - int(selected.sum())
    if other < 0:
        raise ValueError('selected exceeds exact total')
    rates = selected / seconds
    history = np.asarray(prior_rates, dtype=np.float64) if len(prior_rates) else rates.reshape(1, -1)
    bins = np.zeros(64)
    for number, count in counts.items():
        index = ((number * 2654435761) & 0xFFFFFFFF) >> 26
        bins[index] += count
    denominator = max(total, 1)
    vector = np.concatenate((np.log1p(selected), selected / denominator,
        [math.log1p(other), other / denominator, math.log1p(total),
         sum(counts.get(k, 0) for k in sensitive) / denominator, 0.],
        bins / denominator, np.log1p(history.mean(axis=0)), np.log1p(history.std(axis=0))))
    # The fifth scalar is explicitly unavailable/constant; it is NOT a claim of
    # no seccomp skips. Task transitions are unavailable and absent in ALL arms.
    return vector.astype(np.float32), rates


def cohort_paths(path, expected_hash, split):
    if sha256_file(path) != expected_hash:
        raise ValueError('cohort digest mismatch')
    cohort = json.loads(path.read_text())
    if (cohort.get('input_errors') or cohort.get('excluded_capture_count')
            or cohort.get('eligible_capture_count') != 15 or len(cohort.get('captures', [])) != 15):
        raise ValueError('complete admitted 15-capture cohort required')
    seen = set()
    paths = []
    for item in cohort['captures']:
        root = Path(item['capture_dir']).resolve()
        if root.parent.name != split or root in seen or not item['valid_for_selection']:
            raise ValueError('wrong split, duplicate or inadmissible input')
        seen.add(root)
        paths.append((root, item['capture_sha256']))
    return sorted(paths)


def load_rows(root, expected_hash, split):
    # summarize rehashes sealed files, checks metadata/allowlist/cadence/drop
    # counters and binds the traffic schedule. Never accept aggregate totals
    # as a substitute for this capture-level admission.
    report = summarize(root)
    if not report['capture_valid_for_feature_selection'] or report['capture_sha256'] != expected_hash:
        raise ValueError('capture integrity/admission differs from cohort')
    start = report['probe_started_at_unix']; end = report['probe_ended_at_unix']
    start_doc = json.loads((root/'START.json').read_text())
    terminal_doc = json.loads((root/'TERMINAL.json').read_text())
    schedule, schedule_error = load_traffic_receipt(root, start_doc, terminal_doc)
    if schedule_error:
        raise ValueError(f'invalid traffic receipt: {schedule_error}')
    metadata, invalid = load_metadata(root/'metadata-snapshots.jsonl')
    if invalid:
        raise ValueError('invalid metadata snapshots')
    rows = []
    for row in read_jsonl(root/'histogram.jsonl'):
        if row['type'] != 'interval':
            continue
        begin, finish = row['window_start'], row['window_end']
        phase = phase_for(begin, finish, start, end, split)
        if phase is None:
            continue
        meta = latest_metadata(metadata, finish, 60.)
        identity = workload_identity(row['cgroup_id'], meta['document']) if meta else None
        if identity is None:
            raise ValueError('unresolved histogram identity')
        if identity['container_name'] == 'pod-slice':
            continue
        key = f"{identity['namespace']}/{identity['workload_name']}:{identity['container_name']}"
        ident = tuple(identity[k] for k in ('node_name', 'pod_uid', 'container_name',
                                          'workload_revision', 'cgroup_id'))
        regime = interval_regime(begin, finish, schedule) if schedule else 'unlabelled'
        if regime is None:
            raise ValueError('histogram interval does not map to exactly one registered regime')
        counts = {int(k): v for k, v in row['counts'].items()}
        rows.append(dict(workload=key, identity=ident, phase=phase, begin=begin, end=finish,
                         counts=counts, regime=regime, run_id=root.name))
    return rows


def build_contexts(rows, ids, sensitive):
    import numpy as np
    state = {}; outputs = defaultdict(lambda: defaultdict(list)); metadata = defaultdict(list)
    counts = Counter()
    for row in rows:
        ident = (row['identity'], row['run_id'], row['phase'])
        previous = state.get(ident)
        dt = row['end'] - row['begin']
        if not .75 <= dt <= 1.5:
            state.pop(ident, None); counts['cadence_rejected'] += 1
            continue
        # Snapshot reads take measurable time: adjacent cgroup intervals can
        # have a sub-millisecond boundary gap. Exact float equality would reset
        # history on every row and silently yield zero eligible contexts.
        boundary_gap = None if previous is None else row['begin'] - previous['end']
        if (previous is None or boundary_gap < -1e-6
                or boundary_gap > MAX_SNAPSHOT_BOUNDARY_GAP_SECONDS):
            previous = dict(end=None, rates=deque(maxlen=ROLLING), vectors=deque(maxlen=HISTORY))
            state[ident] = previous; counts['history_reset'] += 1
        vector, rate = histogram_vector(row['counts'], dt, previous['rates'], ids, sensitive)
        # Enforce FULL rolling warmup in each partition and do not share
        # history across train/calibration/holdout, node, container or capture.
        if len(previous['rates']) >= ROLLING:
            if len(previous['vectors']) == HISTORY:
                context = np.concatenate((*previous['vectors'], vector))
                outputs[row['workload']][row['phase']].append(context)
                if row['phase'] == 'holdout':
                    metadata[row['workload']].append({k: row[k] for k in
                        ('run_id', 'regime', 'begin', 'end', 'identity')})
            previous['vectors'].append(vector)
        else:
            previous['vectors'].clear(); counts['rolling_warming'] += 1
        previous['rates'].append(rate); previous['end'] = row['end']
    return {k: {p: np.stack(v) for p, v in phases.items()} for k, phases in outputs.items()}, metadata, dict(counts)


def run(selection, selection_hash, holdout, holdout_hash, output):
    import numpy as np
    from ..detector.extended_reference_experiment import PulseExtendedReferenceTree
    from ..collector.features import SENSITIVE_IDS
    from ..detector.support_model import pvalues
    package = Path(__file__).resolve().parents[1]
    baseline = tracked_from_source(package/'collector'/'features.py')
    selection_inputs = cohort_paths(selection, selection_hash, 'selection')
    holdout_inputs = cohort_paths(holdout, holdout_hash, 'holdout')
    binding = dict(profile=PROFILE, selection_cohort_sha256=selection_hash, holdout_cohort_sha256=holdout_hash,
        source_sha256={n: sha256_file(package/n) for n in (
            'syscall_study/syscall_addition_experiment.py', 'collector/features.py', 'detector/model.py',
            'detector/extended_reference_experiment.py', 'syscall_study/syscall_histogram_analysis.py',
            'detector/support_model.py')},
        software=dict(python=platform.python_version(), numpy=np.__version__,
                      sklearn=importlib.metadata.version('scikit-learn')),
        variants=list(VARIANTS), alpha=ALPHA, history=HISTORY, rolling=ROLLING,
        ranking='training-prefix-only; descending exact counts; ID tie-break',
        split='per-selection-capture 70/30 temporal; 2s embargo; reset all feature history at partition',
        max_snapshot_boundary_gap_seconds=MAX_SNAPSHOT_BOUNDARY_GAP_SECONDS,
        include_idle=True, transition_features=False, seccomp_skips_observed=False,
        holdout_previously_inspected_in_C4_C6=True, final_blind_confirmation=False,
        model_promotion=False, pulse_candidate_modified=False)
    output.mkdir(parents=True, exist_ok=True)
    lock = (output/'run.lock').open('a'); fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    if (output/'START.json').exists():
        if json.loads((output/'START.json').read_text())['binding'] != binding:
            raise ValueError('resume binding differs')
        if (output/'TERMINAL.json').exists():
            return json.loads((output/'TERMINAL.json').read_text())
    else:
        atomic_json(output/'START.json', dict(registered_at_unix=time.time(), binding=binding,
            interpretation='exploratory normal comparison; no attack/precision/recall conclusion'))
    selection_rows = []; holdout_rows = []
    for split, inputs, dest in [('selection', selection_inputs, selection_rows), ('holdout', holdout_inputs, holdout_rows)]:
        for root, expected_hash in inputs:
            dest.extend(load_rows(root, expected_hash, split))
            atomic_json(output/'PREPARE_STATUS.json', dict(state='verifying_inputs', split=split,
                        last_capture=root.name, selection_rows=len(selection_rows), holdout_rows=len(holdout_rows),
                        updated_at_unix=time.time()))
    training_counts = Counter()
    for row in selection_rows:
        if row['phase'] == 'train': training_counts.update(row['counts'])
    variants, ranked = choose_variants(training_counts, baseline)
    ranking = dict(training_counts={str(k): v for k, v in sorted(training_counts.items())},
        additional_ids_ranked=ranked, variants={k: list(v) for k, v in variants.items()},
        source_phase='train_only', holdout_used_for_ranking=False)
    atomic_json(output/'SELECTION.json', ranking)
    state = json.loads((output/'STATUS.json').read_text()) if (output/'STATUS.json').exists() else dict(
        state='running', binding=binding, completed={}, unknowns={}, precision=None, recall=None,
        false_positive_rate=None, kernel_to_alert=None, fresh_blind_complete=False)
    if state['binding'] != binding:
        raise ValueError('status checkpoint binding differs')
    all_rows = selection_rows + holdout_rows
    # Bound peak memory to ONE workload/variant rather than materializing
    # 21 workloads of a 4*expanded-width context simultaneously.
    workloads = sorted({row['workload'] for row in all_rows})
    state['expected_models'] = len(workloads) * len(variants)
    for workload in workloads:
        workload_rows = [row for row in all_rows if row['workload'] == workload]
        for variant, ids in variants.items():
            key = workload+'|'+variant
            if key in state['completed']:
                result = state['completed'][key]
                for relative, expected in result.get('seals', {}).items():
                    if sha256_file(output/relative) != expected:
                        raise ValueError('completed checkpoint artifact changed')
                continue
            contexts, metadata, preparation = build_contexts(workload_rows, ids, SENSITIVE_IDS)
            phases = contexts.get(workload, {})
            needed = ('train', 'calibration', 'holdout')
            if any(p not in phases or len(phases[p]) < (199 if p == 'calibration' else 100) for p in needed):
                state['unknowns'][key] = {p: len(phases.get(p, ())) for p in needed}
                continue
            model = PulseExtendedReferenceTree(history=HISTORY, alpha=ALPHA, random_state=73021)
            # _examples on a single context of length 4 produces exactly this
            # context, without manufacturing cross-identity temporal neighbours.
            width = 4*len(ids)+69
            parts = {p: [c.reshape(4, width) for c in phases[p]] for p in ('train', 'calibration')}
            fit = model.fit_sequences(parts)
            data = phases['holdout']; before = time.perf_counter()
            scores = model._raw_scores(data[:, :-width], data[:, -width:])
            probability = pvalues(scores, model.calibration_scores); flags = probability <= ALPHA
            inference_seconds = time.perf_counter() - before
            import hashlib
            name = hashlib.sha256(key.encode()).hexdigest()
            artifact = output/(name+'.pkl'); model.save(artifact)
            prediction = output/(name+'.npz')
            np.savez_compressed(prediction, score=scores, pvalue=probability, positive=flags)
            meta = output/(name+'-contexts.json'); atomic_json(meta, dict(contexts=metadata[workload]))
            regimes = defaultdict(Counter)
            for row, positive in zip(metadata[workload], flags):
                regimes[row['regime']]['contexts'] += 1
                regimes[row['regime']]['raw_positive'] += int(positive)
            state['completed'][key] = dict(ids=list(ids), feature_dim=width, context_dim=4*width,
                fit=fit, holdout_contexts=len(data), raw_positive=int(flags.sum()),
                raw_positive_fraction=float(flags.mean()), inference_batch_seconds=inference_seconds,
                by_regime={k: dict(v) for k, v in regimes.items()}, preparation=preparation,
                label='pending_adjudication; not FP/TN',
                seals={p.name: sha256_file(p) for p in (artifact, prediction, meta)})
            state.update(updated_at_unix=time.time(), completed_models=len(state['completed']))
            atomic_json(output/'STATUS.json', state)
    complete = len(state['completed']) == state['expected_models']
    state.update(state=('completed_exploratory_addition_study' if complete
                        else 'incomplete_exploratory_addition_study'),
        finished_at_unix=time.time(), completed_models=len(state['completed']),
        incomplete_models=len(state['unknowns']),
        statement=('Raw positives alone cannot decide which syscall to add; blind recall/control required.'
                   if complete else 'Not all workload/variant fits completed; this is an incomplete run, not an evaluation result.'))
    atomic_json(output/'STATUS.json', state); atomic_json(output/'TERMINAL.json', state)
    return state


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('selection', 'holdout', 'output'): parser.add_argument('--'+name, type=Path, required=True)
    for name in ('selection-sha256', 'holdout-sha256'): parser.add_argument('--'+name, required=True)
    args = parser.parse_args()
    try:
        result = run(args.selection, args.selection_sha256, args.holdout, args.holdout_sha256, args.output)
    except (ValueError, KeyError, TypeError) as exc:
        args.output.mkdir(parents=True, exist_ok=True)
        atomic_json(args.output/'BLOCKED.json', dict(error=type(exc).__name__, reason=str(exc),
                    observed_at_unix=time.time(), original_evidence_modified=False))
        sys.exit(65)
    print(json.dumps({k: result[k] for k in ('state', 'completed_models', 'incomplete_models')}))


if __name__ == '__main__':
    main()
