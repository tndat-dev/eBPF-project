import numpy as np

from sentinel_pulse.syscall_study import arm_budget as ab
from sentinel_pulse.syscall_study import feature_groups as fg
from sentinel_pulse.syscall_study.matched_holdout import ContextBuilder


def test_groups_partition_the_249_columns():
    covered = sorted(i for g in fg.GROUPS.values() for i in g)
    assert covered == list(range(249))


def test_arms_drop_exactly_their_group():
    arms = fg.feature_arms()
    assert len(arms['base29']['columns']) == 249 and arms['base29']['history'] == 3
    assert len(arms['drop_syscall_bins']['columns']) == 249 - 64
    assert not set(fg.GROUPS['rolling']) & set(arms['drop_rolling']['columns'])
    assert set(arms['bins_only']['columns']) == set(fg.GROUPS['aggregates']) | set(fg.GROUPS['syscall_bins']) | set(fg.GROUPS['transition_bins'])
    assert arms['history1']['history'] == 1 and len(arms['history1']['columns']) == 249


def test_transform_cuts_history_and_columns():
    ctx = np.arange(4*249, dtype=np.float32).reshape(1, 996)
    spec = dict(columns=[0, 248], history=1)
    out = fg.transform(ctx, spec)
    # last two vectors (offsets 2*249 and 3*249), columns 0 and 248
    assert out.tolist() == [[498, 746, 747, 995]]
    assert fg.transform(ctx[0], spec).tolist() == [498, 746, 747, 995]
    assert fg.transform(ctx, dict(add=[], drop=[])) is ctx


def _rows(n=40):
    rng = np.random.default_rng(3)
    for i in range(n):
        yield dict(node_name='n', pod_uid='p', container_name='c', workload_revision='r', cgroup_id=1,
                   window_start=0.5*i, window_end=0.5*i+0.5, eligible_for_normal_review=True, exact_total=10,
                   full_counts_delta={'0': int(rng.integers(0, 5)), '1': 2}, vector=rng.random(249).tolist())


def test_context_builder_feature_arms_are_cut_from_base_contexts_at_the_same_windows():
    base = ContextBuilder(dict(add=[], drop=[]), 0, 100)
    arm = ContextBuilder(fg.feature_arms()['drop_transition_bins'], 0, 100)
    hist = ContextBuilder(fg.feature_arms()['history1'], 0, 100)
    n = 0
    for row in _rows():
        b, a, h = base.observe(row), arm.observe(row), hist.observe(row)
        assert (b is None) == (a is None) == (h is None)
        if b is not None:
            n += 1
            assert np.array_equal(a, fg.transform(b, fg.feature_arms()['drop_transition_bins']))
            assert len(a) == 4*185 and len(h) == 2*249
    assert n > 0


def test_branch_only_pvalues():
    cal = np.sort(np.arange(100, dtype=float))
    tree, support = np.array([99.5]), np.array([0.0])
    assert ab.combined_p('tree', tree, support, cal, cal)[0] == 1/101
    assert ab.combined_p('support', tree, support, cal, cal)[0] == 1.0
    assert ab.combined_p('joint', tree, support, cal, cal)[0] == 2/101
