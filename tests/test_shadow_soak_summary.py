import hashlib
import json

import pytest

from sentinel_pulse.shadow_soak_summary import bucket, run


def fixture(tmp_path, rows):
    capture = tmp_path/'capture'; capture.mkdir()
    (capture/'START.json').write_text('{}')
    terminal = dict(state='completed_observation', boundary_observation_seconds=86400,
        feature_rows=len(rows), start_sha256=hashlib.sha256(b'{}').hexdigest())
    (capture/'TERMINAL.json').write_text(json.dumps(terminal))
    decisions = tmp_path/'decisions.jsonl'
    decisions.write_text(''.join(json.dumps(r)+'\n' for r in rows))
    return dict(capture=capture, decisions=decisions, output=tmp_path/'summary', run_id='run',
                manifest_hash='model', policy_hash='policy')


def decision(preview=False):
    return dict(status='candidate-raw-score-only', run_id='run', candidate_manifest_sha256='model',
        policy_sha256='policy', policy_evaluated=True, workload_key='production/app:app',
        raw_model_anomaly=preview, candidate_alert_preview=preview, alert=False, policy_applied=False,
        serving_compatible=False, inference_ms=20., feature_event_age_seconds=1., window_end=100.)


def test_resume_counts_every_row_once_and_keeps_preview_unadjudicated(tmp_path):
    args = fixture(tmp_path, [decision(True), decision(False), decision(True)])
    partial = run(**args, maximum_rows=1)
    assert partial['rows'] == 1
    result = run(**args)
    assert result['rows'] == 3
    assert result['decision_count_minus_capture_feature_rows'] == 0
    w = result['workloads']['production/app:app']
    assert w['preview_positive'] == 2
    assert w['scored'] == 3
    assert result['false_positive_rate'] is None and result['precision'] is None
    assert result['confusion_matrix']['FP'] is None
    assert run(**args)['rows'] == 3


def test_changed_input_is_not_resumed_as_same_evidence(tmp_path):
    args = fixture(tmp_path, [decision(), decision()])
    run(**args, maximum_rows=1)
    args['decisions'].write_text(json.dumps(decision(True))+'\n')
    with pytest.raises(ValueError, match='binding changed'):
        run(**args)


def test_model_policy_mismatch_and_missing_model_stay_visible(tmp_path):
    scored = decision(True); scored['candidate_manifest_sha256'] = 'different'
    scored['policy_sha256'] = 'different'
    missing = dict(decision(), status='candidate-model-unavailable', candidate_alert_preview=None)
    result = run(**fixture(tmp_path, [scored, missing]))
    assert result['issues']['model_binding_mismatch'] == 1
    assert result['issues']['preview_policy_binding_mismatch'] == 1
    assert result['status_counts']['candidate-model-unavailable'] == 1
    assert result['workloads']['production/app:app']['scored'] == 1


def test_clock_skew_and_processing_delay_have_distinct_buckets():
    assert bucket(-1, (1., 2.)) == 'negative_clock_or_value'
    assert bucket(float('nan'), (1., 2.)) == 'missing_or_nonfinite'
    assert bucket(1.5, (1., 2.)) == 'le_2.0'
    assert bucket(20, (1., 2.)) == 'gt_2.0'
