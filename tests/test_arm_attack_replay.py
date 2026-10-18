from sentinel_pulse.syscall_study.arm_attack_replay import interval_outcome


def windows(p_at, start=100., n=34, alpha=.01):
    return [dict(start=start + i * .5, end=start + i * .5 + .5, joint_p=p_at.get(i, .5), alpha=alpha) for i in range(n)]


ALPHA = lambda w: w['alpha']


def test_attack_tp_uses_first_inside_positive_and_kernel_time():
    trial = dict(label='attack', start_at=100., kernel_event_at=100.4)
    out = interval_outcome(windows({4: .001, 9: .001}), trial, ALPHA)
    assert out['outcome'] == 'TP' and abs(out['delay'] - (102.5 - 100.4)) < 1e-9


def test_control_and_coverage_rules():
    assert interval_outcome(windows({3: .001}), dict(label='expected_normal', start_at=100.), ALPHA)['outcome'] == 'FP_expected'
    assert interval_outcome(windows({}), dict(label='expected_normal', start_at=100.), ALPHA)['outcome'] == 'TN_expected'
    assert interval_outcome(windows({}, n=20), dict(label='expected_normal', start_at=100.), ALPHA)['outcome'] == 'unknown'
    assert interval_outcome(windows({}), dict(label='attack', start_at=100.), ALPHA)['outcome'] == 'unknown'  # no kernel time
    assert interval_outcome(windows({}), dict(label='attack', start_at=100., kernel_event_at=100.2), ALPHA)['outcome'] == 'FN'
