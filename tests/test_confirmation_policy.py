import json

import pytest

from sentinel_pulse.attack.confirmation_study import EpisodeCounter, attack_replay, normal_burden
from sentinel_pulse.detector.confirmation import ConfirmationPolicy, ConfirmationState, apply, default_grid

ALPHA = 1 / 600
MODEL = '747c4eed2a9a74321d0ac3b716c201c449f946665252baa1ca314b1f18278a08'
POLICY = 'fd0be94a4ca7f2cd64b97bf5c7dc074763405f821ab346e8e19bb5975d10f401'
IDENTITY = dict(workload_key='production/app:app', node_name='w1', pod_uid='p1', container_name='app',
                workload_revision='r1', cgroup_id=7)


def row(start, joint_p, **extra):
    base = dict(IDENTITY, status='candidate-raw-score-only', window_start=start, window_end=start + .5,
                joint_p=joint_p, candidate_policy_alpha=ALPHA, candidate_alert_preview=joint_p <= ALPHA,
                policy_evaluated=True, candidate_manifest_sha256=MODEL, policy_sha256=POLICY,
                alert=False, policy_applied=False, serving_compatible=False,
                eligible_for_normal_review=True, preview_emitted_at=start + .6)
    base.update(extra)
    return base


def signals(policy, ps, step=.5, start=100.):
    state = ConfirmationState(policy)
    return [state.update(row(start + i * step, p)) for i, p in enumerate(ps)]


def test_single_window_policy_reproduces_frozen_preview():
    ps = [1e-4, .5, 1e-3, ALPHA, ALPHA * 1.01]
    assert signals(ConfirmationPolicy(), ps) == [p <= ALPHA for p in ps]


def test_k_of_n_needs_k_passes_inside_last_n_windows():
    low, high = 1e-4, .5
    assert signals(ConfirmationPolicy(k=2, n=3), [low, high, low, high, high, low]) == \
        [False, False, True, False, False, False]
    assert signals(ConfirmationPolicy(k=2, n=2), [low, low, low]) == [False, True, True]


def test_gap_or_overlap_restarts_confirmation():
    state = ConfirmationState(ConfirmationPolicy(k=2, n=2))
    assert state.update(row(100., 1e-4)) is False
    assert state.update(row(102., 1e-4)) is False  # 1.5 s hole > max gap
    assert state.update(row(102.5, 1e-4)) is True


def test_identities_do_not_share_history():
    state = ConfirmationState(ConfirmationPolicy(k=2, n=2))
    assert state.update(row(100., 1e-4)) is False
    assert state.update(row(100.5, 1e-4, pod_uid='p2')) is False


def test_alpha_scale_tightens_threshold():
    assert signals(ConfirmationPolicy(alpha_scale=.25), [ALPHA * .3, ALPHA * .2]) == [False, True]


def test_invalid_policies_rejected():
    with pytest.raises(ValueError):
        ConfirmationPolicy(k=3, n=2)
    with pytest.raises(ValueError):
        ConfirmationPolicy(alpha_scale=0)
    with pytest.raises(ValueError):
        ConfirmationPolicy(alpha_scale=21)
    assert ConfirmationPolicy(alpha_scale=5).name == 'k1of1_a5'


def test_apply_keeps_unscored_rows_and_audit_field():
    warming = dict(IDENTITY, status='warming', window_start=99.5, window_end=100.)
    out = apply([row(100.5, 1e-4), warming, row(100., 1e-4)], ConfirmationPolicy(k=2, n=2))
    assert [r['status'] for r in out] == ['warming', 'candidate-raw-score-only', 'candidate-raw-score-only']
    assert [r.get('candidate_alert_preview') for r in out[1:]] == [False, True]
    assert all(r['frozen_candidate_alert_preview'] is True for r in out[1:])


def test_episode_counter_merges_within_quiet_gap():
    counter = EpisodeCounter(quiet=15)
    for at in (0, 5, 19.9, 35, 49.99):
        counter.add('w', 'k', at)
    assert counter.windows['w'] == 5 and counter.episodes['w'] == 2


def test_grid_contains_frozen_policy_and_is_fixed():
    names = [p.name for p in default_grid()]
    assert 'k1of1_a1' in names and len(names) == len(set(names)) == 21


def test_normal_burden_counts_and_baseline_check(tmp_path):
    seg = tmp_path / 'k8s-worker1.local' / 'segments' / 's00001'
    seg.mkdir(parents=True)
    rows = [row(100 + i * .5, p) for i, p in enumerate([1e-4, 1e-4, .5, .5] + [.5] * 40 + [1e-4])]
    rows.append(dict(IDENTITY, status='warming', window_start=99., window_end=99.5))
    (seg / 'decisions.jsonl').write_text(''.join(json.dumps(r) + '\n' for r in rows))
    result = normal_burden(tmp_path / 'k8s-worker1.local', [ConfirmationPolicy(), ConfirmationPolicy(k=2, n=2)])
    assert result['baseline_reproduces_frozen_previews'] is True
    assert result['policies']['k1of1_a1']['total_positive_windows'] == 3
    assert result['policies']['k1of1_a1']['total_episodes'] == 2
    assert result['policies']['k2of2_a1']['total_positive_windows'] == 1
    assert result['scored_windows']['production/app:app'] == 45


def test_attack_replay_detects_only_inside_interval(tmp_path):
    campaign = tmp_path / 'campaign'
    trial_dir = campaign / 'trials' / '0001'
    trial_dir.mkdir(parents=True)
    control = dict(IDENTITY, trial_id='1:control', label='expected_normal', start_at=100.)
    attack = dict(IDENTITY, trial_id='1:attack', label='attack', start_at=120., kernel_event_at=121.)
    decisions = [row(100 + i * .5, .5) for i in range(40)] + [row(120 + i * .5, .5) for i in range(30)]
    decisions[44]['joint_p'] = decisions[45]['joint_p'] = 1e-4  # 122.0 and 122.5
    (trial_dir / 'EVALUATION_INPUT.json').write_text(json.dumps(dict(control=control, attack=attack, decisions=decisions)))
    (campaign / 'RESULTS.json').write_text(json.dumps(dict(completed={'1': []})))
    report = attack_replay([campaign], [ConfirmationPolicy(), ConfirmationPolicy(k=3, n=3)])
    base, strict = report['policies']['k1of1_a1'], report['policies']['k3of3_a1']
    assert base['confusion_matrix_expected_control_labels'] == dict(TP=1, FN=0, FP=0, TN=1)
    assert strict['confusion_matrix_expected_control_labels'] == dict(TP=0, FN=1, FP=0, TN=1)


def test_recalibrator_matches_conformal_formula_and_skips_small_sets():
    import numpy as np
    from sentinel_pulse.detector.recalibration import Recalibrator
    cal = Recalibrator({'production/app:app': np.arange(2000.), 'small': [1.]},
                       {'production/app:app': np.arange(2000.) / 10, 'small': [1.]})
    out = cal.rewrite(row(100., .9, tree_score=1999.5, support_score=0.))
    assert out['tree_p'] == pytest.approx(1 / 2001) and out['support_p'] == 1.0
    assert out['joint_p'] == pytest.approx(2 / 2001) and out['frozen_joint_p'] == .9
    assert cal.rewrite(row(100., .9, workload_key='small', tree_score=0, support_score=0)) is None


def test_calibration_respects_time_span_exclusions_and_roundtrip(tmp_path):
    from sentinel_pulse.attack.confirmation_study import calibration_scores, load_calibration, save_calibration
    seg = tmp_path / 'w1' / 'segments' / 's00001'
    seg.mkdir(parents=True)
    rows = [row(100 + i * .5, .5, tree_score=float(i), support_score=float(-i)) for i in range(20)]
    rows[3]['eligible_for_normal_review'] = False
    (seg / 'decisions.jsonl').write_text(''.join(json.dumps(r) + '\n' for r in rows))
    tree, support, stats = calibration_scores([tmp_path / 'w1'], since=101., until=108., exclude=[(104., 105.)])
    assert tree['production/app:app'] == [2., 4., 5., 6., 7., 10., 11., 12., 13., 14., 15.]
    assert stats['ineligible_rows'] == 1 and stats['excluded_rows'] == 2
    save_calibration(tmp_path / 'cal.npz', tree, support, {'note': 'x'})
    recal, meta = load_calibration(tmp_path / 'cal.npz', minimum_examples=1)
    assert meta == {'note': 'x'} and recal.sizes() == {'production/app:app': 11}
    with pytest.raises(FileExistsError):
        save_calibration(tmp_path / 'cal.npz', tree, support, {})


def test_recalibrated_replay_without_calibration_is_unknown(tmp_path):
    from sentinel_pulse.detector.recalibration import Recalibrator
    campaign = tmp_path / 'campaign'
    trial_dir = campaign / 'trials' / '0001'
    trial_dir.mkdir(parents=True)
    control = dict(IDENTITY, trial_id='1:control', label='expected_normal', start_at=100.)
    attack = dict(IDENTITY, trial_id='1:attack', label='attack', start_at=120., kernel_event_at=121.)
    decisions = [row(100 + i * .5, .5, tree_score=0., support_score=0.) for i in range(70)]
    (trial_dir / 'EVALUATION_INPUT.json').write_text(json.dumps(dict(control=control, attack=attack, decisions=decisions)))
    (campaign / 'RESULTS.json').write_text(json.dumps(dict(completed={'1': []})))
    report = attack_replay([campaign], [ConfirmationPolicy()], recalibrator=Recalibrator({}, {}))
    assert report['policies']['k1of1_a1']['unknown'] == 2
