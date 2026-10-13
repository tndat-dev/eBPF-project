import json
from pathlib import Path
from unittest.mock import patch

import pytest

from sentinel_pulse.syscall_capture_campaign import (
    Remote, healthy, phases, soak_complete, run,
)


def test_capture_gate_needs_terminal_full_exposure_and_no_live_writer():
    assert not soak_complete({})
    assert not soak_complete({'terminal': {'state': 'completed_observation',
                                           'boundary_observation_seconds': 100}})
    ready = {'terminal': {'state': 'completed_observation',
                          'boundary_observation_seconds': 86400},
             'active_capture_processes': []}
    assert soak_complete(ready)
    assert not soak_complete({**ready, 'active_capture_processes': ['capture']})
    assert not soak_complete({**ready, 'terminal': {'state': 'failed'}})


def test_all_selection_phases_precede_separate_holdout():
    items = phases()
    assert len(items) == 10
    assert {x[0] for x in items[:5]} == {'selection'}
    assert {x[0] for x in items[5:]} == {'holdout'}
    assert [x[1] for x in items[:5]] == [x[1] for x in items[5:]]
    assert set(x[1] for x in items) == {'steady', 'toolmix', 'peak', 'burst', 'recovery'}


def snapshot():
    return {'nodes': {'items': [dict(status=dict(conditions=[
        {'type': 'Ready', 'status': 'True'}, *[{'type': k, 'status': 'False'}
        for k in ('DiskPressure', 'MemoryPressure', 'PIDPressure')]])) for _ in range(6)]},
        'deployments': {'items': [dict(metadata=dict(generation=2), spec=dict(replicas=0),
            status=dict(observedGeneration=2)) for _ in range(4)]}}


def test_health_recognizes_intentionally_zero_scaled_loadgen():
    snap = snapshot()
    assert healthy(snap)
    snap['deployments']['items'][0]['status']['observedGeneration'] = 1
    assert not healthy(snap)
    snap = snapshot()
    snap['nodes']['items'][0]['status']['conditions'][1]['status'] = 'True'
    assert not healthy(snap)


def test_launch_refuses_to_touch_live_soak():
    remote = object.__new__(Remote)
    with patch.object(remote, 'inspect', return_value={}), patch.object(remote, 'command') as command:
        with pytest.raises(RuntimeError, match='still active'):
            remote.launch('10.1.16.237', 'run', {}, 'a' * 40)
        command.assert_not_called()


def test_waiting_campaign_never_changes_traffic_or_launches(tmp_path):
    from argparse import Namespace
    source = tmp_path / 'source'
    (source / 'ml-service').mkdir(parents=True)
    (source / 'ml-service/set_aims_traffic_regime.sh').write_text('# stub')
    args = Namespace(source=source, root=tmp_path / 'output', credential=tmp_path / 'secret', source_commit='a'*40)
    with patch('sentinel_pulse.syscall_capture_campaign.Remote') as remote, \
         patch('sentinel_pulse.syscall_capture_campaign.set_regime') as regime, \
         patch('sentinel_pulse.syscall_capture_campaign.time.sleep', side_effect=InterruptedError):
        remote.return_value.inspect.return_value = {'status': {'state': 'collecting'}}
        with pytest.raises(InterruptedError):
            run(args)
        regime.assert_not_called()
        remote.return_value.launch.assert_not_called()
    status = json.loads((args.root / 'STATUS.json').read_text())
    assert status['state'] == 'waiting_for_existing_soak'
    assert status['completed'] == []


def test_resume_rejects_changed_source_without_touching_traffic(tmp_path):
    from argparse import Namespace
    source = tmp_path / 'source'
    (source / 'ml-service').mkdir(parents=True)
    script = source / 'ml-service/set_aims_traffic_regime.sh'
    script.write_text('# first')
    args = Namespace(source=source, root=tmp_path / 'output', credential=tmp_path / 'secret', source_commit='a'*40)
    with patch('sentinel_pulse.syscall_capture_campaign.Remote') as remote, \
         patch('sentinel_pulse.syscall_capture_campaign.time.sleep', side_effect=InterruptedError):
        remote.return_value.inspect.return_value = {}
        with pytest.raises(InterruptedError):
            run(args)
        script.write_text('# changed')
        with pytest.raises(ValueError, match='changed'):
            run(args)
