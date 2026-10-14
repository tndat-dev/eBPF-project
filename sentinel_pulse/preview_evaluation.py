"""Interval evaluation for the pinned idle-aware candidate preview stream."""
from __future__ import annotations

import math

IDENTITY = ('workload_key', 'node_name', 'pod_uid', 'container_name',
            'workload_revision', 'cgroup_id')


def interval_union(intervals):
    end = -math.inf
    total = 0.
    for begin, finish in sorted(intervals):
        total += max(0., finish - max(begin, end))
        end = max(end, finish)
    return total


def evaluate_interval(rows, trial, model_hash, policy_hash):
    """One outcome per exact container and fixed 15s horizon; retain unknowns.

    Expected-normal controls yield provisional FP/TN labels. An infrastructure
    interval or incomplete scored exposure cannot silently become a TN/FN.
    """
    begin = float(trial['start_at'])
    finish = begin + 15.
    if not math.isfinite(begin) or trial['label'] not in ('attack', 'expected_normal'):
        raise ValueError('invalid interval label or start')
    if any(not str(trial.get(key, '')) for key in IDENTITY):
        raise ValueError('incomplete trial identity')
    windows, positives, issues = [], [], []
    for row in rows:
        if any(str(row.get(key)) != str(trial[key]) for key in IDENTITY):
            continue
        a, b = float(row.get('window_start', 0)), float(row.get('window_end', 0))
        if not (math.isfinite(a) and math.isfinite(b)) or b <= begin or a >= finish:
            continue
        if (row.get('candidate_manifest_sha256') != model_hash
                or row.get('policy_sha256') != policy_hash):
            issues.append('model_or_policy_binding_mismatch')
            continue
        if (row.get('alert') is not False or row.get('policy_applied') is not False
                or row.get('serving_compatible') is not False):
            issues.append('shadow_invariant_violation')
            continue
        emitted = float(row.get('preview_emitted_at', float('nan')))
        if (row.get('status') != 'candidate-raw-score-only'
                or row.get('policy_evaluated') is not True
                or row.get('eligible_for_normal_review') is not True
                or not .35 <= b-a <= .8 or not math.isfinite(emitted)
                or not 0 <= emitted-b <= 1.5):
            continue
        if type(row.get('candidate_alert_preview')) is not bool:
            issues.append('invalid_preview_boolean')
            continue
        windows.append((max(a, begin), min(b, finish)))
        # A pre-injection window must never detect an attack. Require the
        # complete feature window and emitted preview inside the horizon.
        if (a >= begin and b <= finish and emitted <= finish
                and row['candidate_alert_preview']):
            positives.append(row)
    exposure = interval_union(windows)
    outcome = dict(trial, scored_seconds=exposure, scored_fraction=exposure/15,
                   issues=sorted(set(issues)), prediction_unit='15s exact-container interval',
                   detected=False, outcome='unknown', kernel_to_preview_seconds=None,
                   kernel_to_alert_seconds=None, operational_alert=False)
    if exposure < 13.5 or issues or trial.get('infrastructure_issue'):
        return outcome
    detected = bool(positives)
    outcome.update(detected=detected, outcome=('TP' if detected else 'FN')
                   if trial['label']=='attack' else ('FP_expected' if detected else 'TN_expected'))
    if detected:
        first = min(positives, key=lambda row: row['preview_emitted_at'])
        outcome['first_preview_at'] = first['preview_emitted_at']
        if trial['label']=='attack':
            kernel = trial.get('kernel_event_at')
            if kernel is None or not math.isfinite(float(kernel)) or not begin <= kernel <= begin+10:
                outcome.update(outcome='unknown', issues=['missing_or_invalid_kernel_provenance'])
            elif first['preview_emitted_at'] < kernel:
                outcome.update(outcome='unknown', issues=['preview_precedes_kernel_event'])
            else:
                outcome['kernel_to_preview_seconds'] = first['preview_emitted_at']-kernel
    elif trial['label']=='attack' and trial.get('kernel_event_at') is None:
        outcome.update(outcome='unknown', issues=['missing_kernel_provenance'])
    return outcome


def summarize(outcomes):
    from collections import Counter
    counts = Counter(row['outcome'] for row in outcomes)
    tp, fn = counts['TP'], counts['FN']
    fp, tn = counts['FP_expected'], counts['TN_expected']
    latencies = [row['kernel_to_preview_seconds'] for row in outcomes
                 if row['outcome']=='TP' and row.get('kernel_to_preview_seconds') is not None]
    import numpy as np
    return dict(schema='pulse-preview-interval-matrix-v1', intervals=len(outcomes),
        confusion_matrix_expected_control_labels=dict(TP=tp,FN=fn,FP=fp,TN=tn),
        unknown=counts['unknown'], precision_expected=tp/(tp+fp) if tp+fp else None,
        recall_observed=tp/(tp+fn) if tp+fn else None,
        recall_end_to_end_lower_bound=tp/sum(r['label']=='attack' for r in outcomes)
            if any(r['label']=='attack' for r in outcomes) else None,
        control_positive_rate=fp/(fp+tn) if fp+tn else None,
        confirmed_precision=None, confirmed_FPR=None, control_labels='pending_post_run_adjudication',
        kernel_to_preview_seconds=None if not latencies else dict(samples=len(latencies),
            p50=float(np.percentile(latencies,50)),p95=float(np.percentile(latencies,95)),
            p99=float(np.percentile(latencies,99))),
        latency_conditional_on_detected_trials=True, kernel_to_alert=None,
        alert=False, policy_applied=False, automatic_promotion=False)
