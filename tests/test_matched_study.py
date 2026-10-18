from collections import Counter
import numpy as np
from sentinel_pulse.syscall_study.matched_study import arm_specs, contexts, SECURITY
from sentinel_pulse.syscall_study.matched_study import sealed_selection_files
from sentinel_pulse.collector.features import TRACKED_SYSCALLS


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


def test_selection_waits_for_sealed_tail_and_skips_later_segments(tmp_path):
    import json
    from sentinel_pulse.integrity import sha256_file
    def segment(index, end, sealed=True):
        directory=tmp_path/'segments'/f's{index:05d}'
        directory.mkdir(parents=True)
        path=directory/'features.jsonl'
        path.write_text(json.dumps(dict(window_end=end))+'\n')
        if sealed:
            (directory/'TERMINAL.json').write_text(json.dumps(
                dict(seals={'features.jsonl':sha256_file(path)})))
        return path
    old=segment(1,90)
    first=segment(2,150)
    tail=segment(3,210,False)
    assert sealed_selection_files(tmp_path,200,100)==([],150)
    (tail.parent/'TERMINAL.json').write_text(json.dumps(
        dict(seals={'features.jsonl':sha256_file(tail)})))
    segment(4,300)
    assert sealed_selection_files(tmp_path,200,100)==([first,tail],210)


def test_empty_selection_coverage_is_json_null(tmp_path):
    assert sealed_selection_files(tmp_path,200)==([],None)
