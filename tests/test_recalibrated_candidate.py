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


def _ideas_module(name):
    import importlib.util
    from pathlib import Path
    spec = importlib.util.spec_from_file_location(name, Path(__file__).parents[1] / 'scripts' / 'analysis' / f'{name}.py')
    mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    return mod


def _stream(seed=7, n=400):
    """Joint/tree/support p-values of one container with a burst, a gap and an overlap."""
    rng = np.random.default_rng(seed)
    t, rows = 100.0, []
    for i in range(n):
        if i == 150: t += 3.0           # gap > 1 s: history restarts
        if i == 300: t -= 0.4           # overlap > 0.25 s: history restarts
        burst = 120 <= i < 140 or 320 <= i < 330
        tp, sp = (rng.uniform(1e-5, 2e-3), rng.uniform(1e-4, .5)) if burst else (rng.uniform(1e-3, 1), rng.uniform(1e-3, 1))
        rows.append(dict(start=t, end=t + .5, tree_p=float(tp), support_p=float(sp), joint_p=min(1.0, 2 * min(tp, sp))))
        t += .5
    return rows


def _live(policy, rows, alpha):
    out = []
    for r in rows:
        score = dict(status='candidate-raw-score-only', workload_key=KEY, joint_p=r['joint_p'], tree_p=r['tree_p'],
                     support_p=r['support_p'], raw_model_anomaly=r['joint_p'] <= alpha)
        ctx = dict(workload_key=KEY, pod_uid='u', container_name='app', workload_revision='r', cgroup_id='1',
                   window_start=r['start'], window_end=r['end'])
        out.append(policy.evaluate(score, ctx)['candidate_alert_preview'])
    return out


def _write(tmp_path, digest, rule):
    path = _policy(tmp_path, digest)
    data = json.loads(path.read_text()); data['rule'] = rule
    path.write_text(json.dumps(data))
    return path


BASE_RULE = {'score': 'joint_p', 'comparison': 'less_than_or_equal',
             'threshold_source': 'per_workload_model_calibrated_alpha', 'semantic_gate': False}


def test_live_cusum_matches_the_offline_screen_window_for_window(tmp_path):
    source, digest = _candidate(tmp_path)
    scorer = IdleCandidateScorer(source, digest)
    rule = dict(BASE_RULE, temporal_rule={'kind': 'cusum', 'drift': 3.0, 'threshold': 6.0, 'max_gap_seconds': 1.0})
    policy = load_preview_policy(_write(tmp_path, digest, rule), scorer)
    rows = _stream()
    live = _live(policy, rows, scorer.models[KEY].alpha)
    offline = _ideas_module('ideas_screen').alarms_cusum(rows, 3.0, 6.0)
    assert live == offline and any(live)


def test_live_cauchy_k2of2_matches_the_offline_screen_window_for_window(tmp_path):
    source, digest = _candidate(tmp_path)
    scorer = IdleCandidateScorer(source, digest)
    rule = dict(BASE_RULE, alpha_scale=10.0, combination='cauchy',
                temporal_confirmation={'k': 2, 'n': 2, 'max_gap_seconds': 1.0})
    policy = load_preview_policy(_write(tmp_path, digest, rule), scorer)
    alpha = scorer.models[KEY].alpha
    rows = [dict(r, alpha=alpha) for r in _stream(seed=9)]
    live = _live(policy, rows, alpha)
    offline = _ideas_module('ideas_screen').alarms_kofn(rows, 'cauchy', 10.0)
    assert live == offline and any(live)


def test_cusum_rule_shape_is_strict(tmp_path):
    source, digest = _candidate(tmp_path)
    scorer = IdleCandidateScorer(source, digest)
    for rule in (dict(BASE_RULE, alpha_scale=10.0, temporal_rule={'kind': 'cusum', 'drift': 3.0, 'threshold': 6.0, 'max_gap_seconds': 1.0}),
                 dict(BASE_RULE, temporal_rule={'kind': 'sprt', 'drift': 3.0, 'threshold': 6.0, 'max_gap_seconds': 1.0}),
                 dict(BASE_RULE, alpha_scale=10.0, combination='fisher', temporal_confirmation={'k': 2, 'n': 2, 'max_gap_seconds': 1.0})):
        with pytest.raises(ValueError, match='registered form'):
            load_preview_policy(_write(tmp_path, digest, rule), scorer)


def test_live_rules_also_match_the_whole_normal_burden_script(tmp_path):
    source, digest = _candidate(tmp_path)
    scorer = IdleCandidateScorer(source, digest)
    alpha = scorer.models[KEY].alpha
    ib = _ideas_module('ideas_burden')
    rows = _stream(seed=11)
    for rule, det in ((dict(BASE_RULE, temporal_rule={'kind': 'cusum', 'drift': 3.0, 'threshold': 6.0, 'max_gap_seconds': 1.0}), ib.Cusum(3.0, 6.0)),
                      (dict(BASE_RULE, alpha_scale=10.0, combination='cauchy',
                            temporal_confirmation={'k': 2, 'n': 2, 'max_gap_seconds': 1.0}), ib.CauchyK2(10.0))):
        live = _live(load_preview_policy(_write(tmp_path, digest, rule), scorer), rows, alpha)
        offline = [det.update('c', dict(window_start=r['start'], window_end=r['end'], joint_p=r['joint_p'], tree_p=r['tree_p'],
                                        support_p=r['support_p'], candidate_policy_alpha=alpha)) for r in rows]
        assert live == offline


def test_stable_cusum_policy_file_is_the_rule_tested_window_for_window(tmp_path):
    from pathlib import Path
    shipped = json.loads((Path(__file__).parents[1]/'sentinel_pulse/protocol/policy-cusum-b3-h6.json').read_text())
    assert shipped['rule'] == dict(BASE_RULE, temporal_rule={'kind': 'cusum', 'drift': 3.0, 'threshold': 6.0,
                                                               'max_gap_seconds': 1.0})
    assert shipped['candidate_manifest_sha256'].startswith('4bad16dc')
    source, digest = _candidate(tmp_path)
    load_preview_policy(_write(tmp_path, digest, shipped['rule']), IdleCandidateScorer(source, digest))


def test_live_cusum_on_alarm_modes(tmp_path):
    from sentinel_pulse.detector.confirmation import CusumPolicy, CusumState
    source, digest = _candidate(tmp_path)
    scorer = IdleCandidateScorer(source, digest)
    rows = _stream(seed=13)
    for mode in ('cap', 'restart'):
        rule = dict(BASE_RULE, temporal_rule={'kind': 'cusum', 'drift': 3.0, 'threshold': 6.0, 'max_gap_seconds': 1.0,
                                              'on_alarm': mode})
        policy = load_preview_policy(_write(tmp_path, digest, rule), scorer)
        assert policy.confirmation == CusumPolicy(3.0, 6.0, 1.0, mode)
        live = _live(policy, rows, scorer.models[KEY].alpha)
        state = CusumState(CusumPolicy(3.0, 6.0, 1.0, mode))
        ref = [state.update(dict(node_name='n', window_start=r['start'], window_end=r['end'], joint_p=r['joint_p'])) for r in rows]
        assert live == ref
    with pytest.raises(ValueError):
        load_preview_policy(_write(tmp_path, digest, dict(BASE_RULE, temporal_rule={
            'kind': 'cusum', 'drift': 3.0, 'threshold': 6.0, 'max_gap_seconds': 1.0, 'on_alarm': 'forever'})), scorer)
