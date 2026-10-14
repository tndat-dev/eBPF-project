"""Checkpointed, read-only summary of a completed idle-aware shadow soak.

Counts previews for adjudication; does not silently label them false positives.
The original source, frozen model and scorer are never changed.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import math
from pathlib import Path
import time

from .integrity import sha256_file
from .syscall_histogram_pilot import atomic_json


AGE_LIMITS = (.01, .05, .1, .5, 1., 2., 10., 60., 600., 3600.)
INFERENCE_LIMITS = (1., 5., 10., 20., 50., 100., 1000.)


def bump(target, key):
    target[key] = target.get(key, 0) + 1


def bucket(value, limits):
    if not isinstance(value, (int, float)) or isinstance(value, bool) or not math.isfinite(value):
        return 'missing_or_nonfinite'
    if value < 0:
        return 'negative_clock_or_value'
    return next(('le_' + str(x) for x in limits if value <= x), 'gt_' + str(limits[-1]))


def observe(state, row):
    binding = state['binding']
    if not isinstance(row, dict):
        bump(state['issues'], 'non_object_record')
        return
    status = row.get('status', 'missing_status')
    if not isinstance(status, str) or not isinstance(row.get('workload_key', 'unknown_workload'), str):
        bump(state['issues'], 'invalid_status_or_workload')
        return
    bump(state['status_counts'], status)
    workload = row.get('workload_key', 'unknown_workload')
    w = state['workloads'].setdefault(workload, dict(rows=0, statuses={}, preview_positive=0,
        scored=0, raw_model_anomalies=0, feature_end_to_score_age_buckets_seconds={},
        inference_time_buckets_ms={}, preview_examples=[]))
    w['rows'] += 1
    bump(w['statuses'], status)
    if row.get('run_id') != binding['run_id']:
        bump(state['issues'], 'run_binding_mismatch')
    if status != 'record_rejected' and row.get('candidate_manifest_sha256') != binding['manifest_sha256']:
        bump(state['issues'], 'model_binding_mismatch')
    if any(row.get(k) is not False for k in ('alert', 'policy_applied', 'serving_compatible')):
        bump(state['issues'], 'shadow_invariant_violation')
    if status == 'candidate-raw-score-only':
        w['scored'] += 1
        if row.get('policy_sha256') != binding['policy_sha256'] or row.get('policy_evaluated') is not True:
            bump(state['issues'], 'preview_policy_binding_mismatch')
        if row.get('raw_model_anomaly') is True:
            w['raw_model_anomalies'] += 1
        if row.get('candidate_alert_preview') is True:
            w['preview_positive'] += 1
            if len(w['preview_examples']) < 10:
                w['preview_examples'].append({k: row.get(k) for k in ('pod_uid', 'container_name',
                    'workload_revision', 'cgroup_id', 'window_end', 'processed_at', 'joint_p',
                    'candidate_policy_alpha', 'feature_event_age_seconds')})
        if row.get('candidate_alert_preview') != row.get('raw_model_anomaly'):
            bump(state['issues'], 'preview_model_disagreement')
        bump(w['feature_end_to_score_age_buckets_seconds'], bucket(row.get('feature_event_age_seconds'), AGE_LIMITS))
        bump(w['inference_time_buckets_ms'], bucket(row.get('inference_ms'), INFERENCE_LIMITS))
    end = row.get('window_end')
    if isinstance(end, (int, float)) and math.isfinite(end):
        state['maximum_window_end'] = max(state.get('maximum_window_end') or end, end)


def file_identity(path):
    s = path.stat()
    return dict(path=str(path.resolve()), device=s.st_dev, inode=s.st_ino, bytes=s.st_size,
                mtime_ns=s.st_mtime_ns)


def run(capture, decisions, output, run_id, manifest_hash, policy_hash, maximum_rows=None):
    terminal = json.loads((capture/'TERMINAL.json').read_text())
    if terminal.get('state') != 'completed_observation' or terminal.get('boundary_observation_seconds', 0) < 86400:
        raise ValueError('completed 24-hour capture required')
    if terminal.get('start_sha256') != sha256_file(capture/'START.json'):
        raise ValueError('capture START/terminal binding differs')
    output.mkdir(parents=True, exist_ok=True)
    lock = (output/'summary.lock').open('a')
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    binding = dict(decisions=file_identity(decisions), capture_terminal_sha256=sha256_file(capture/'TERMINAL.json'),
        capture_start_sha256=sha256_file(capture/'START.json'), auditor_sha256=sha256_file(Path(__file__)),
        run_id=run_id, manifest_sha256=manifest_hash, policy_sha256=policy_hash,
        expected_capture_feature_rows=terminal['feature_rows'])
    status = output/'STATUS.json'
    if status.exists():
        state = json.loads(status.read_text())
        if state['binding'] != binding:
            raise ValueError('summary input/source binding changed; use a separate output')
        if state['state'] == 'completed_shadow_summary':
            return state
    else:
        state = dict(schema='pulse-shadow-soak-summary-v1', binding=binding, state='summarizing',
            registered_at_unix=time.time(), position=0, rows=0, status_counts={}, issues={}, workloads={},
            prefix_sha256=hashlib.sha256(b'').hexdigest(), maximum_window_end=None,
            precision=None, recall=None, false_positive_rate=None, kernel_to_alert=None,
            confusion_matrix=dict(TP=None, FP=None, TN=None, FN=None), normal_labels='pending_adjudication',
            prediction_unit='individual shadow feature record; not attack interval',
            latency_measurement='feature window end to score, histogram; not kernel-to-alert',
            automatic_promotion=False)
        atomic_json(output/'START.json', state)
        atomic_json(status, state)
    hasher = hashlib.sha256()
    with decisions.open('rb') as stream:
        left = state['position']
        while left:
            chunk = stream.read(min(1024*1024, left))
            if not chunk:
                raise ValueError('checkpoint points past input end')
            hasher.update(chunk); left -= len(chunk)
        if hasher.hexdigest() != state['prefix_sha256']:
            raise ValueError('previously summarized input prefix changed')
        checkpoint_at, processed = time.monotonic(), 0
        while stream.tell() < binding['decisions']['bytes']:
            raw = stream.readline()
            if stream.tell() > binding['decisions']['bytes'] or not raw.endswith(b'\n'):
                raise ValueError('snapshot ends inside a decision record')
            hasher.update(raw)
            state['rows'] += 1
            try:
                observe(state, json.loads(raw))
            except (ValueError, UnicodeDecodeError):
                bump(state['issues'], 'malformed_decision')
            state['position'] = stream.tell()
            state['prefix_sha256'] = hasher.hexdigest()
            processed += 1
            if time.monotonic() - checkpoint_at >= 5:
                state['updated_at_unix'] = time.time()
                atomic_json(status, state)
                checkpoint_at = time.monotonic()
            if maximum_rows is not None and processed >= maximum_rows:
                atomic_json(status, state)
                return state
    if file_identity(decisions) != binding['decisions']:
        raise ValueError('decision stream changed during summary')
    state.update(state='completed_shadow_summary', finished_at_unix=time.time(),
        decisions_sha256=hasher.hexdigest(),
        decision_count_minus_capture_feature_rows=state['rows']-binding['expected_capture_feature_rows'],
        count_comparison_only_not_feature_decision_alignment_proof=True)
    atomic_json(status, state)
    atomic_json(output/'TERMINAL.json', state)
    return state


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('capture', 'decisions', 'output'):
        p.add_argument('--'+name, type=Path, required=True)
    for name in ('run-id', 'manifest-sha256', 'policy-sha256'):
        p.add_argument('--'+name, required=True)
    a = p.parse_args()
    run(a.capture, a.decisions, a.output, a.run_id, a.manifest_sha256, a.policy_sha256)


if __name__ == '__main__':
    main()
