import json

import numpy as np
import pytest

from test_sentinel_pulse_idle_candidate_scorer import _candidate

from sentinel_pulse.attack.confirmation_study import save_calibration
from sentinel_pulse.detector.candidate_policy import ConfirmedPreviewPolicy, load_preview_policy
from sentinel_pulse.detector.idle_candidate import IdleCandidateScorer
from sentinel_pulse.detector.recalibrate_bundle import recalibrate

KEY = 'production/test:app'


def _calibration(tmp_path, model_hash, n=700):
    path = tmp_path / 'cal.npz'
    save_calibration(path, {KEY: list(np.linspace(0, 1, n))}, {KEY: list(np.linspace(0, 5, n))},
                     dict(model_hash=model_hash, since_unix=1.0, until_unix=2.0, excluded_spans=[]))
    return path


def test_recalibrated_bundle_keeps_estimator_and_replaces_only_calibration(tmp_path):
    source, digest = _candidate(tmp_path)
    new_hash = recalibrate(source, digest, _calibration(tmp_path, digest), tmp_path / 'out', 'recal-test')
    scorer = IdleCandidateScorer(tmp_path / 'out', new_hash)
    model = scorer.models[KEY]
    assert len(model.base.calibration_scores) == 700 and len(model.support_calibration) == 700
    assert np.all(np.diff(model.base.calibration_scores) >= 0)
    manifest = json.loads((tmp_path / 'out' / 'CANDIDATE_MANIFEST.json').read_text())
    assert manifest['recalibration']['source_manifest_sha256'] == digest
    assert manifest['recalibration']['estimators_changed'] is False
    assert manifest['workloads'][KEY]['original_artifact_sha256'] != manifest['workloads'][KEY]['artifact_sha256']


def test_recalibration_refuses_foreign_or_too_small_calibration(tmp_path):
    source, digest = _candidate(tmp_path)
    with pytest.raises(ValueError, match='not produced by this candidate'):
        recalibrate(source, digest, _calibration(tmp_path, 'other'), tmp_path / 'a', 'x')
    small = tmp_path / 'small'
    small.mkdir()
    with pytest.raises(ValueError, match='too few'):
        recalibrate(source, digest, _calibration(small, digest, n=10), tmp_path / 'b', 'x')


def _policy(tmp_path, digest, k=2, n=3, scale=10.0):
    policy = {
        'schema': 'sentinel-pulse-candidate-preview-policy-v2', 'candidate_manifest_sha256': digest,
        'frozen_before_independent_evaluation': True, 'blind_outcome_used': False, 'automatic_promotion': False,
        'rule': {'score': 'joint_p', 'comparison': 'less_than_or_equal',
                 'threshold_source': 'per_workload_model_calibrated_alpha', 'semantic_gate': False,
                 'alpha_scale': scale, 'temporal_confirmation': {'k': k, 'n': n, 'max_gap_seconds': 1.0}},
        'nominal_error_budget': {'interval_target': .05, 'horizon_windows': 30, 'is_guarantee': False},
    }
    path = tmp_path / 'policy.json'
    path.write_text(json.dumps(policy))
    return path


def test_confirmed_policy_needs_k_of_n_windows_in_live_runtime_form(tmp_path):
    source, digest = _candidate(tmp_path)
    scorer = IdleCandidateScorer(source, digest)
    policy = load_preview_policy(_policy(tmp_path, digest), scorer)
    assert isinstance(policy, ConfirmedPreviewPolicy)
    alpha = scorer.models[KEY].alpha

    def step(t, p):
        score = dict(status='candidate-raw-score-only', workload_key=KEY, joint_p=p, raw_model_anomaly=p <= alpha)
        context = dict(workload_key=KEY, pod_uid='u', container_name='app', workload_revision='r', cgroup_id='1',
                       window_start=t, window_end=t + .5)
        return policy.evaluate(score, context)
    low, high = alpha * 5, .9  # passes only the scaled threshold
    out = [step(100 + .5 * i, p) for i, p in enumerate([low, high, low, low])]
    assert [o['candidate_alert_preview'] for o in out] == [False, False, True, True]
    assert out[0]['preview_reason'] == 'awaiting_confirmation' and out[1]['window_passed'] is False
    assert all(o['alert'] is False for o in out)
    with pytest.raises(ValueError, match='window identity'):
        policy.evaluate(dict(status='candidate-raw-score-only', workload_key=KEY, joint_p=.5,
                             raw_model_anomaly=False), None)


def test_v2_rule_shape_is_strict(tmp_path):
    source, digest = _candidate(tmp_path)
    scorer = IdleCandidateScorer(source, digest)
    path = _policy(tmp_path, digest)
    data = json.loads(path.read_text()); data['rule']['semantic_gate'] = True
    path.write_text(json.dumps(data))
    with pytest.raises(ValueError, match='registered form'):
        load_preview_policy(path, scorer)
