from collections import Counter
import numpy as np
from sentinel_pulse.matched_study import arm_specs, contexts, SECURITY
from sentinel_pulse.features import TRACKED_SYSCALLS


def rows():
    return [dict(window_start=10+i*.5,window_end=10+(i+1)*.5,node_name='n',pod_uid='uid',
        workload_revision='r',container_name='app',cgroup_id=42,eligible_for_normal_review=True,
        exact_total=3,full_counts_delta={'0':1,'202':2},vector=np.zeros(249,dtype=np.float32))
        for i in range(160)]


def test_arm_ranking_security_and_joint_masks():
    arms=arm_specs(Counter({202:100,0:1000,7:5}),range(400))
    assert len(arms)==11
    assert arms['plus_top8']['add']==[202,7]
    assert arms['plus_security']['add']==list(SECURITY)
    assert arms['drop_exec_pair']['drop']==[59,322]
    assert 202 in arms['plus_all_defined_native']['add']
    assert not set(TRACKED_SYSCALLS)&set(arms['plus_all_defined_native']['add'])


def test_matched_contexts_recompute_rolling_and_reset_at_temporal_split():
    data=contexts(rows(),dict(add=[202],drop=[]),10,90)
    for phase in ('train','calibration'):
        x=data[phase]
        assert x.shape[1]==4*253
        # New ID rolling mean is ln(1 + 2 calls / 0.5s); std=0.
        assert np.allclose(x[:,-2],np.log(5))
        assert np.allclose(x[:,-1],0)
        assert np.allclose(x[:,-253+191],np.log(3))
    # Calibration must discard 10 rolling + 3 history rows after embargo.
    assert len(data['calibration'])<48-13


def test_group_drop_keeps_hash_and_transition_information():
    data=contexts(rows(),dict(add=[],drop=[43,288]),10,90)
    assert data['train'].shape[1]==4*(249-8)
