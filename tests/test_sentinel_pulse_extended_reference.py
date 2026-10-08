import json
import numpy as np
import pytest
from sentinel_pulse import extended_reference_experiment as exp
from sentinel_pulse.extended_reference_experiment import phase_for,partitions_for,PulseExtendedReferenceTree


@pytest.mark.parametrize('begin,end,expected',[(7,7.5,'train'),(7.5,8,None),(12,12.5,None),
                                             (12.01,12.51,'calibration'),(17.5,18,None),(22.01,22.51,'holdout')])
def test_global_temporal_phase_and_embargo(begin,end,expected):
    assert phase_for(begin,end,10,20)==expected


def test_contexts_do_not_cross_global_temporal_partition():
    base=PulseExtendedReferenceTree()
    partitions=dict(train=[np.ones((110,2))],calibration=[np.ones((10,2))*77],holdout=[np.ones((10,2))*999])
    tx,ty,cx,cy,dim=base._split_sequences(partitions,.7)
    assert dim==2 and (tx==1).all() and (ty==1).all() and (cx==77).all() and (cy==77).all()
    assert len(tx)==107 and len(cx)==7


def test_sequences_reset_at_revision_gap_and_embargo(tmp_path):
    path=tmp_path/'workload.jsonl';records=[]
    for begin,revision in [(1,'a'),(1.5,'a'),(2,'b'),(2.5,'b'),(7.5,'b'),(12.5,'b'),(13,'b'),(22.5,'b')]:
        records.append(dict(node_name='node',pod_uid='pod',container_name='app',workload_revision=revision,
                            cgroup_id=1,window_start=begin,window_end=begin+.5,vector=[begin,1]))
    path.write_text(''.join(json.dumps(r)+'\n' for r in records))
    p,counts=partitions_for(path,10,20)
    assert counts==dict(train=4,embargo=1,calibration=2,holdout=1)
    assert sorted(len(s) for s in p['train'])==[2,2]
    assert len(p['calibration'])==1 and len(p['holdout'])==1


def test_reference_tree_does_not_accept_nonfinite_data():
    base=PulseExtendedReferenceTree()
    with pytest.raises(ValueError,match='invalid reference sequence'):
        base._split_sequences(dict(train=[np.full((10,2),np.nan)],calibration=[]),.7)


def test_fetch_waits_without_paramiko_or_password_on_command_line(tmp_path,monkeypatch):
    credential=tmp_path/'private';credential.write_text('fixture-password-not-real\n');credential.chmod(0o600)
    observed=[]
    def run(command,**kwargs):
        observed.append(command)
        raise exp.subprocess.CalledProcessError(1,command)
    monkeypatch.setattr(exp.subprocess,'run',run)
    assert exp.fetch_inputs(tmp_path,credential,tmp_path/'known_hosts') is None
    assert 'StrictHostKeyChecking=yes' in observed[0] and observed[0][:2]==['sshpass','-f']
    assert all('fixture-password-not-real' not in word for word in observed[0])
