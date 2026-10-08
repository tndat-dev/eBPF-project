import math
import pytest
from sentinel_pulse.extended_capture import ExtendedFeatureStream,CONTRACT,SCHEMA
from sentinel_pulse.features import TRACKED_SYSCALLS
from sentinel_pulse.encoding import decode_vector


def raw(value=0):
    counts={str(i):0 for i in TRACKED_SYSCALLS};counts['308']=value
    bins=[0]*64;bins[((308*2654435761)&0xffffffff)>>26]=value
    return dict(type='cgroup_snapshot_extended',telemetry_contract=CONTRACT,cgroup_id=1,
                counts=counts,syscall_bins=bins,transition_bins=[0]*64,total=value,seccomp_skipped_or_emulated=value)


META={'1':dict(namespace='production',workload_name='test',container_name='app',node_name='node',pod_uid='uid',workload_revision='r')}


def test_extended_skip_is_counted_and_has_new_feature_contract():
    stream=ExtendedFeatureStream();assert stream.snapshot(raw(),10,META,10.1) is None
    row,schema=stream.snapshot(raw(2),10.5,META,10.6)
    assert row['schema']==SCHEMA and row['exact_counts']['setns']==2
    assert len(decode_vector(row))==249
    assert 'seccomp_denied' not in schema['columns']
    assert decode_vector(row)[schema['columns'].index('seccomp_skipped_or_emulated')]==2
    assert row['eligible_for_normal_review'] is False


@pytest.mark.parametrize('kind',['gap','counter_reset','revision'])
def test_extended_temporal_history_never_crosses_gap_reset_or_revision(kind):
    stream=ExtendedFeatureStream();stream.snapshot(raw(),10,META,10.1)
    stream.snapshot(raw(2),10.5,META,10.6)
    m=META if kind!='revision' else {'1':dict(META['1'],workload_revision='changed')}
    assert stream.snapshot(raw(1 if kind=='counter_reset' else 3),12 if kind=='gap' else 11,m,12.1 if kind=='gap' else 11.1) is None


def test_legacy_contract_cannot_silently_enter_extended_features():
    stream=ExtendedFeatureStream()
    with pytest.raises(ValueError,match='contract'):stream.snapshot(dict(raw(),type='cgroup_snapshot'),10,META,10.1)


def test_extended_integrity_and_loss_are_not_normal():
    stream=ExtendedFeatureStream()
    with pytest.raises(ValueError,match='integrity'):stream.snapshot(dict(raw(2),total=1),10,META,10.1)
    stream.snapshot(raw(),10,META,10.1);stream.stats={'snapshot_projection_fail':1}
    assert stream.snapshot(raw(2),10.5,META,10.6) is None


def test_idle_boundary_resets_rolling_history_and_json_key_order_is_not_semantic():
    stream=ExtendedFeatureStream();stream.snapshot(raw(),10,META,10.1)
    for i in range(1,12):
        value=raw(i);value['counts']=dict(reversed(list(value['counts'].items()))) if i%2 else value['counts']
        row,_=stream.snapshot(value,10+i*.5,META,10+i*.5+.1)
    assert row['eligible_for_normal_review'] and row['history_before']==10
    assert stream.snapshot(raw(11),16,META,16.1) is None
    row,_=stream.snapshot(raw(12),16.5,META,16.6)
    assert row['history_before']==0 and not row['eligible_for_normal_review']
