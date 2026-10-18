import copy
import hashlib
import json
from pathlib import Path

import pytest

from sentinel_pulse.rca_connect import normalize_connect_event
from sentinel_pulse.rca_tree import build_tree, case_id, event_time, render_markdown, trigger_kind
from sentinel_pulse.rca_service import Service, initial_offset, read_complete


def trigger(**extra):
    return dict(status='candidate-raw-score-only', candidate_manifest_sha256='model',
        policy_sha256='policy', policy_evaluated=True, candidate_alert_preview=True,
        alert=False, node_name='worker1', pod_uid='pod1', container_name='app',
        workload_key='production/order:app', cgroup_id=123, window_end=100.,
        **extra)


def edge(at=99., **source):
    return dict(schema='sentinel-pulse-rca-connect-edge-v1', observed_at=at,
        node_name='worker1', source=dict(pod_uid='pod1', container_name='app',
            exec_id='child', parent_exec_id='parent', binary='/app/python', pid=42,
            **source), parent=dict(exec_id='parent', binary='/usr/bin/parent', pid=10),
        connection=dict(socket_fd=4), destination=dict(address='10.0.0.1', port=443,
            family='AF_INET', kubernetes=None),
        raw_event_sha256=hashlib.sha256(str(at).encode()).hexdigest())


def test_tree_retains_process_parent_destination_and_does_not_claim_cause():
    tree = build_tree(trigger(), [edge()])
    assert tree['trigger_kind']=='candidate_alert_preview'
    assert tree['causal_root_confirmed'] is False
    assert tree['matched_connect_events']==1
    assert any(n.get('binary')=='/usr/bin/parent' for n in tree['nodes'])
    assert any(e['relation']=='parent_of' for e in tree['edges'])
    assert any(n['kind']=='connect_attempt' and n['success']=='unknown_no_return_probe' for n in tree['nodes'])
    assert tree['application_payload_captured'] is False
    assert 'chưa xác nhận' in render_markdown(tree)


@pytest.mark.parametrize('change', [dict(node_name='another-node'), dict(source={'pod_uid':'old-pod'}),
    dict(source={'container_name':'sidecar'}), dict(observed_at=69.), dict(observed_at=106.)])
def test_tree_rejects_wrong_identity_and_out_of_window(change):
    item = edge()
    if 'source' in change:
        item['source'].update(change['source'])
    else: item.update(change)
    assert build_tree(trigger(), [item])['matched_connect_events']==0


def test_missing_exec_identity_is_not_replaced_by_pid():
    item = edge(); item['source'].pop('exec_id')
    tree = build_tree(trigger(), [item])
    assert any(n['id'].startswith('unknown-process:') for n in tree['nodes'])


def test_tree_handles_missing_context_and_bounded_edges():
    assert build_tree(trigger(), [])['matched_connect_events']==0
    tree = build_tree(trigger(), [edge(99.), edge(100.)], max_edges=1)
    assert tree['matched_connect_events']==2
    assert tree['retained_connect_events']==1
    assert tree['truncated']


def test_processes_with_identical_pid_but_different_exec_id_are_not_merged():
    first, second = edge(99.), edge(100.)
    second['source']['exec_id']='other-start'
    tree = build_tree(trigger(), [first, second])
    assert len([n for n in tree['nodes'] if n['kind']=='process'])==2


def test_container_id_is_checked_if_trigger_has_one():
    row = trigger(container_id='new-cri')
    item = edge(); item['source']['container_id']='old-cri'
    assert build_tree(row, [item])['matched_connect_events']==0


@pytest.mark.parametrize('key,value', [('policy_sha256','changed'), ('candidate_manifest_sha256','changed'),
    ('policy_evaluated',False), ('candidate_alert_preview',False), ('pod_uid',None), ('status','warming')])
def test_only_bound_scored_preview_triggers(key, value):
    row = trigger(); row[key]=value
    assert trigger_kind(row, 'model', 'policy') is None


def test_preview_is_never_relabeled_as_operational_alert():
    row = trigger(); row['alert']=True
    assert trigger_kind(row, 'model', 'policy')=='candidate_alert_preview'


@pytest.mark.parametrize('value', [None, True, float('nan'), float('inf')])
def test_bad_timestamp_rejected(value):
    with pytest.raises(ValueError): event_time(value)


def test_iso_timestamp_and_case_binding():
    assert event_time('1970-01-01T00:01:40Z')==100
    row = trigger(); altered = copy.deepcopy(row); altered['pod_uid']='new'
    assert case_id(row)!=case_id(altered)


def test_only_complete_tail_lines_are_consumed(tmp_path):
    path = tmp_path/'decisions'
    path.write_bytes(b'{"old":1}\n{"new":')
    offset = initial_offset(path)
    assert offset==10
    assert read_complete(path, offset)==([], offset)
    with path.open('ab') as sink: sink.write(b'2}\n')
    lines, offset = read_complete(path, offset)
    assert [json.loads(line) for line in lines]==[{'new':2}]
    assert offset==path.stat().st_size


def service(tmp_path, monkeypatch):
    config = tmp_path/'CONFIG.json'
    config.write_text(json.dumps(dict(output=str(tmp_path/'rca'), model_hash='model',
        policy_hash='policy', case_cooldown_seconds=300, before_seconds=30, after_seconds=5,
        ring_seconds=180, max_ring_events=1000, max_cases=10, workers=[],
        connect_policy='sentinel-aims-syscalls')))
    monkeypatch.setattr('sentinel_pulse.rca_service.time.time', lambda: 100.)
    return Service(config), config


def test_initial_tail_does_not_use_stale_path_stat(tmp_path, monkeypatch):
    from types import SimpleNamespace
    path = tmp_path/'decisions'
    path.write_bytes(b'{"old":1}\n{"new":2}\n{"partial":')
    monkeypatch.setattr(Path, 'stat', lambda *args, **kwargs: SimpleNamespace(st_size=10))
    assert initial_offset(path) == len(b'{"old":1}\n{"new":2}\n')


def test_durable_cases_and_cooldown_survive_restart(tmp_path, monkeypatch):
    first, config = service(tmp_path, monkeypatch)
    first.observe_trigger(trigger(), 100.)
    row = trigger(); row['window_end']=101.
    first.observe_trigger(row, 101.)
    first.db.commit(); first.db.close(); first.lock.close()
    resumed = Service(config)
    resumed.observe_trigger(row, 102.)
    assert resumed.db.execute('select count(*) from cases').fetchone()[0]==1
    assert resumed.counts['positive_decisions_grouped_by_cooldown']==1
    resumed.db.close(); resumed.lock.close()


def test_resume_refuses_config_binding_change(tmp_path, monkeypatch):
    first, config = service(tmp_path, monkeypatch)
    first.db.close(); first.lock.close()
    changed = json.loads(config.read_text()); changed['model_hash']='different'
    config.write_text(json.dumps(changed))
    with pytest.raises(ValueError, match='changed'): Service(config)


def test_case_generation_is_idempotent_and_records_empty_context(tmp_path, monkeypatch):
    srv, _ = service(tmp_path, monkeypatch)
    srv.observe_trigger(trigger(), 90.); srv.emit_cases(); srv.emit_cases()
    assert srv.db.execute('select emitted from cases').fetchone()[0]==1
    assert len(list((srv.root/'cases').glob('*.json')))==1
    doc = json.loads(next((srv.root/'cases').glob('*.json')).read_text())
    assert doc['matched_connect_events']==0
    assert doc['coverage']['connect_policy_selected'] is None
    assert doc['nodes'][0]['trigger']['policy_evaluated'] is True
    from sentinel_pulse.audit_rca_cases import validate
    assert validate(doc, 'model', 'policy') == []
    srv.db.close(); srv.lock.close()


def test_normalizer_records_parent_without_argv_or_payload():
    raw = dict(time=99, node_name='worker1', process_kprobe=dict(
        policy_name='sentinel-aims-syscalls', function_name='__x64_sys_connect',
        process=dict(exec_id='child', arguments='secret-token', pod=dict(uid='pod1',
            namespace='production', container=dict(name='app', id='cri-id'))),
        parent=dict(exec_id='parent', binary='/bin/app', arguments='another-secret'), args=[]))
    normalized = normalize_connect_event(raw)
    assert normalized['source']['container_id']=='cri-id'
    assert normalized['parent']['exec_id']=='parent'
    assert 'secret' not in json.dumps(normalized)


