import json
from pathlib import Path

import pytest

from sentinel_pulse.derive_matched_coordinator_run import derive
from sentinel_pulse.integrity import sha256_file


def test_derive_coordinator_keeps_capture_bindings_and_moves_phase_forward(tmp_path):
    source=__file__.split('/tests/')[0]
    source_path=tmp_path/'source';source_path.symlink_to(source)
    candidate=tmp_path/'candidate';candidate.mkdir()
    (candidate/'CANDIDATE_MANIFEST.json').write_text('{"schema":"fixture"}\n')
    policy=tmp_path/'decision-policy.json';policy.write_text('{}\n')
    binary=tmp_path/'attack';binary.write_bytes(b'static-fixture')
    keys=[f'production/workload-{i}:app' for i in range(21)]
    base=dict(run_id='capture-base',candidate=str(candidate),
        model_hash=sha256_file(candidate/'CANDIDATE_MANIFEST.json'),
        policy=str(policy),policy_hash=sha256_file(policy),binary=str(binary),
        binary_hash=sha256_file(binary),workload_keys=keys,
        matched_observable='500ms full-ID + 249 baseline + transitions + rolling10 + history3 + tree/support',
        workers={f'host-{i}':dict(output=str(tmp_path/f'worker-{i}')) for i in range(3)},
        campaign_output=str(tmp_path/'parent-campaign'),
        schedule=[dict(scenario='dev',workload_key=k) for k in keys],native_syscall_ids=[0,1])
    base_path=tmp_path/'capture.json';base_path.write_text(json.dumps(base))
    root=tmp_path/'derived'
    path=derive(base_path,source_path,root,'coordinator-test',selection_delay=60,
                selection_seconds=600,attack_delay=30)
    actual=json.loads(path.read_text())
    assert actual['workers']==base['workers']
    assert actual['model_hash']==base['model_hash']
    assert actual['binary_hash']==base['binary_hash']
    assert actual['selection_start']>=actual['derived_at_unix']+60
    assert actual['selection_end']==actual['selection_start']+600
    assert actual['attack_not_before']==actual['selection_end']+30
    assert actual['traffic_schedule']==[]
    assert actual['prior_campaign_outputs']==[base['campaign_output']]
    assert path.stat().st_mode & 0o222 == 0
    replay=derive(base_path,source_path,tmp_path/'replay','coordinator-replay',
                  selection_seconds=600,selection_start_at=actual['selection_start'])
    assert json.loads(replay.read_text())['selection_start']==actual['selection_start']
    subset=derive(base_path,source_path,tmp_path/'subset','coordinator-subset',
                  campaign_workloads=[keys[-1]])
    subcfg=json.loads(subset.read_text())
    assert subcfg['schedule']==[base['schedule'][-1]]
    assert subcfg['workload_keys']==keys
    with pytest.raises(ValueError,match='outside frozen'):
        derive(base_path,source_path,tmp_path/'invalid','coordinator-invalid',
               campaign_workloads=['production/not-frozen:app'])


def test_derive_rejects_capture_with_wrong_worker_count(tmp_path):
    base=dict(workers={},workload_keys=[])
    config=tmp_path/'capture.json';config.write_text(json.dumps(base))
    with pytest.raises(ValueError,match='three workers'):
        derive(config,Path(__file__).resolve().parents[1],tmp_path/'derived','coordinator-test')
