import json
from pathlib import Path
import platform
from types import SimpleNamespace
import pytest
from sentinel_pulse import extended_collection as ec
from sentinel_pulse.integrity import sha256_file
from test_sentinel_pulse_extended_capture import raw,META


@pytest.fixture
def setup(tmp_path,monkeypatch):
    source=tmp_path/'source';source.mkdir()
    build=tmp_path/'build';build.mkdir()
    artifacts={}
    for name in ('pulse_counter_extended_loader','pulse_counter_extended.bpf.o'):
        (build/name).write_bytes(b'bound artifact');artifacts[name]=sha256_file(build/name)
    proof=tmp_path/'proof';proof.mkdir()
    (proof/'START.json').write_text(json.dumps(dict(kernel=platform.release(),artifact_sha256=artifacts)))
    (proof/'RESULTS.json').write_text(json.dumps(dict(valid=True)))
    root=tmp_path/'run';root.mkdir()
    monkeypatch.setattr(ec,'clean_source',lambda _:('abc',{}))
    monkeypatch.setattr(ec.signal,'signal',lambda *args:None)
    return source,build,root,proof


def emit(monkeypatch,frames,meta_fail_first=False):
    data=['not JSON\n']
    for boundary,value in frames:
        data.extend([json.dumps(raw(value))+'\n',json.dumps(dict(type='snapshot_end',observed_at=boundary,targets=1,snapshots=1))+'\n'])
    chunks=iter([x.encode() for x in data])
    class Proc:
        stdout=SimpleNamespace(fileno=lambda:99);returncode=0
        def terminate(self):pass
        def wait(self,**kwargs):return 0
    monkeypatch.setattr(ec.subprocess,'Popen',lambda *a,**k:Proc())
    monkeypatch.setattr(ec.select,'select',lambda *a:([1],[],[]))
    monkeypatch.setattr(ec.os,'read',lambda *a:next(chunks,b''))
    monkeypatch.setattr(ec.time,'sleep',lambda _:None)
    realstat=Path.stat;realread=Path.read_text
    metadata_attempts=0
    def stat(path,*a,**k):
        if str(path)=='/run/sentinel-pulse/cgroups.json':return SimpleNamespace(st_mtime_ns=1)
        return realstat(path,*a,**k)
    def read(path,*a,**k):
        nonlocal metadata_attempts
        if str(path)=='/run/sentinel-pulse/cgroups.json':
            metadata_attempts+=1
            if meta_fail_first and metadata_attempts==1:raise OSError('resolver restarted')
            return json.dumps(dict(cgroups=META))
        return realread(path,*a,**k)
    monkeypatch.setattr(Path,'stat',stat);monkeypatch.setattr(Path,'read_text',read)


def test_invalid_record_and_cadence_gap_continue_to_goal_with_evidence(setup,monkeypatch):
    source,build,root,proof=setup
    emit(monkeypatch,[(10,0),(10.5,2),(13,3),(13.5,4)])
    ec.collect(source,build,root,seconds=1,proof=proof)
    result=json.loads((root/'TERMINAL.json').read_text())
    assert result['state']=='completed_observation' and result['errors']==1
    assert result['boundary_observation_seconds']==1 and result['feature_rows']==2
    assert result['normal_training_admission'] is False
    observations=(root/'segments/s0001/observations.jsonl').read_text()
    assert 'not JSON' in (root/'segments/s0001/raw.jsonl').read_text()
    assert 'record_ineligible' in observations and 'cadence_gap' in observations
    # Reboot after completion validates the binding, does not spawn another loader.
    monkeypatch.setattr(ec.subprocess,'Popen',lambda *a,**k:pytest.fail('completed run restarted'))
    ec.collect(source,build,root,seconds=1,proof=proof)


def test_resolver_same_generation_recovers_after_read_failure(setup,monkeypatch):
    source,build,root,proof=setup
    emit(monkeypatch,[(10,0),(10.5,1),(11,2)],meta_fail_first=True)
    ec.collect(source,build,root,seconds=1,proof=proof)
    result=json.loads((root/'TERMINAL.json').read_text())
    assert result['feature_rows']==1
    assert 'resolver_unavailable' in (root/'segments/s0001/observations.jsonl').read_text()


def test_completed_run_does_not_accept_changed_registration(setup,monkeypatch):
    source,build,root,proof=setup;emit(monkeypatch,[(10,0),(10.5,1),(11,2)])
    ec.collect(source,build,root,seconds=1,proof=proof)
    with pytest.raises(ValueError,match='registration changed'):ec.collect(source,build,root,seconds=2,proof=proof)
    status=json.loads((root/'STATUS.json').read_text());status['start_sha256']='tampered'
    (root/'STATUS.json').write_text(json.dumps(status))
    with pytest.raises(ValueError,match='checkpoint'):ec.collect(source,build,root,seconds=1,proof=proof)


def test_proof_must_match_artifacts(setup):
    source,build,root,proof=setup;(build/'pulse_counter_extended.bpf.o').write_bytes(b'drift')
    with pytest.raises(ValueError,match='compiled artifacts'):ec.collect(source,build,root,proof=proof)
    assert not (root/'START.json').exists()


def test_system_stop_resumes_checkpoint_in_new_segment_not_from_zero(setup,monkeypatch):
    source,build,root,proof=setup
    emit(monkeypatch,[(10,0),(10.5,1)])
    handlers={};original_read=ec.os.read;calls=0
    monkeypatch.setattr(ec.signal,'signal',lambda sig,handler:handlers.update({sig:handler}))
    def read(*args):
        nonlocal calls
        calls+=1
        if calls==5:handlers[ec.signal.SIGTERM]()
        return original_read(*args)
    monkeypatch.setattr(ec.os,'read',read)
    with pytest.raises(SystemExit) as stopped:ec.collect(source,build,root,seconds=1,proof=proof)
    assert stopped.value.code==1
    first=json.loads((root/'STATUS.json').read_text())
    assert first['boundary_observation_seconds']==.5 and first['segments']==1
    emit(monkeypatch,[(20,0),(20.5,1)])
    ec.collect(source,build,root,seconds=1,proof=proof)
    terminal=json.loads((root/'TERMINAL.json').read_text())
    assert terminal['boundary_observation_seconds']==1 and terminal['segments']==2
    assert terminal['start_sha256']==first['start_sha256']
    assert (root/'segments/s0001/raw.jsonl').exists() and (root/'segments/s0002/raw.jsonl').exists()
