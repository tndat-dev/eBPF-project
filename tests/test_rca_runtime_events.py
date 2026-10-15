import copy
import json

import pytest

from sentinel_pulse.audit_rca_cases import validate
from sentinel_pulse.rca_runtime_events import POLICY, normalize_runtime_event
from sentinel_pulse.rca_runtime_tree import build_runtime_tree, render_runtime_markdown


def process(pid=21, eid='child'):
    return dict(pid=pid, exec_id=eid, parent_exec_id='parent', binary='/app/worker',
        uid=1000, arguments='SECRET_ARG', cwd='/app', pod=dict(namespace='production',
        name='app-1', uid='pod1', container=dict(name='app', id='cri1')))


def record(call, args=(), ret=0, at=99.):
    event = dict(function_name=call, policy_name=POLICY, process=process(),
                 parent=dict(exec_id='parent', pid=1, binary='/bin/parent', arguments='SECRET_PARENT'),
                 args=list(args))
    if ret is not None:
        event['return'] = dict(long_arg=str(ret))
    return dict(node_name='worker1', time=at, process_kprobe=event)


def trigger():
    return dict(status='candidate-raw-score-only', candidate_manifest_sha256='model',
        policy_sha256='policy', policy_evaluated=True, candidate_alert_preview=True,
        alert=False, node_name='worker1', pod_uid='pod1', container_name='app',
        workload_key='production/app:app', cgroup_id=123, window_end=100.)


@pytest.mark.parametrize('call,args,category,operation', [
    ('sys_openat', [dict(label='filename', string_arg='/tmp/proof')], 'file', 'open'),
    ('vfs_write', [dict(label='file', file_arg=dict(path='/tmp/proof'))], 'file', 'write'),
    ('sys_setuid', [dict(label='uid', uint_arg=1000)], 'credential', 'setuid'),
    ('sys_setresgid', [dict(label='egid', uint_arg=1000)], 'credential', 'setresgid'),
    ('sys_capset', [], 'credential', 'capset'),
    ('sys_setns', [dict(label='namespace_fd', int_arg=-1)], 'namespace', 'setns'),
    ('sys_mount', [dict(label='mount_target', string_arg='/no-target')], 'mount', 'mount'),
    ('sys_ptrace', [dict(label='target_pid', int_arg=-1)], 'ptrace', 'ptrace'),
])
def test_all_security_categories_preserve_objects_and_return(call, args, category, operation):
    event = normalize_runtime_event(record(call, args, -1))
    assert event['category'] == category and event['operation'] == operation
    assert event['outcome'] == dict(status='failure', return_observed=True, return_value=-1, errno='EPERM')
    assert 'SECRET' not in json.dumps(event)
    tree = build_runtime_tree(trigger(), [event])
    assert tree['retained_runtime_events'] == 1
    assert any(n['kind'] == 'runtime_event' for n in tree['nodes'])
    assert validate(tree, 'model', 'policy') == []
    assert operation in render_runtime_markdown(tree)


def test_no_return_is_unknown_and_nonblocking_connect_is_not_a_failure():
    unknown = normalize_runtime_event(record('sys_mount', ret=None))
    assert unknown['outcome']['status'] == 'unknown'
    waiting = normalize_runtime_event(record('sys_connect', ret=-115))
    assert waiting['outcome']['status'] == 'in_progress'
    tree = build_runtime_tree(trigger(), [waiting])
    assert validate(tree, 'model', 'policy') == []
    connect = next(n for n in tree['nodes'] if n['kind'] == 'connect_attempt')
    assert connect['success'] == 'in_progress'


def test_committed_credentials_keep_numeric_ids_and_caps_only():
    event = normalize_runtime_event(record('commit_creds', [dict(label='new_credentials',
        process_credentials_arg=dict(uid=1000, euid=1000, gid=1000,
            caps=dict(effective=['CAP_CHOWN'], permitted=[], inheritable=[]), secret='SECRET'))]))
    cred = event['details']['new_credentials']
    assert cred['uid'] == 1000 and cred['capabilities']['effective'] == ['CAP_CHOWN']
    assert 'SECRET' not in json.dumps(event)


def test_native_exec_exit_and_fork_tracepoint_are_distinct_lifecycle_evidence():
    exec_raw = dict(time=98., node_name='worker1', process_exec=dict(process=process(),
        parent=dict(exec_id='parent', pid=1, binary='/bin/parent')))
    exit_raw = dict(time=101., node_name='worker1', process_exit=dict(process=process(), status=7))
    fork_raw = dict(time=97., node_name='worker1', process_tracepoint=dict(process=process(),
        policy_name=POLICY, subsys='sched', event='sched_process_fork',
        args=[dict(label='parent_pid', int_arg=21), dict(label='child_pid', int_arg=22)]))
    events = [normalize_runtime_event(r) for r in (fork_raw, exec_raw, exit_raw)]
    assert [e['operation'] for e in events] == ['fork', 'exec', 'exit']
    tree = build_runtime_tree(trigger(), events)
    assert tree['event_categories'] == dict(process=3)
    assert any(n['kind'] == 'fork_child' and n['host_pid'] == 22 for n in tree['nodes'])
    assert any(n['kind'] == 'executable' for n in tree['nodes'])
    assert validate(tree, 'model', 'policy') == []


@pytest.mark.parametrize('change', [('node_name', 'other'), ('pod_uid', 'other'),
                                   ('container_name', 'other')])
def test_runtime_tree_never_joins_other_container(change):
    event = normalize_runtime_event(record('sys_mount'))
    key, value = change
    if key == 'node_name':
        event[key] = value
    else:
        event['source'][key] = value
    assert build_runtime_tree(trigger(), [event])['matched_runtime_events'] == 0


def test_rare_security_events_survive_bounded_selection_before_file_noise():
    events = [normalize_runtime_event(record('sys_openat', at=90+i/100)) for i in range(30)]
    events += [normalize_runtime_event(record('sys_ptrace', ret=-3, at=99))]
    tree = build_runtime_tree(trigger(), events, max_events=3)
    assert tree['truncated'] and tree['matched_runtime_events'] == 31
    assert tree['event_categories']['ptrace'] == 1


def test_policy_binding_and_payload_whitelist():
    raw = record('sys_openat', [dict(label='buffer', string_arg='SECRET_FILE_DATA')])
    event = normalize_runtime_event(raw)
    assert 'SECRET' not in json.dumps(event)
    wrong = copy.deepcopy(raw); wrong['process_kprobe']['policy_name'] = 'other'
    assert normalize_runtime_event(wrong) is None


def test_mutated_connect_success_claim_is_rejected_by_audit():
    event = normalize_runtime_event(record('sys_connect', ret=-111))
    tree = build_runtime_tree(trigger(), [event])
    connect = next(n for n in tree['nodes'] if n['kind'] == 'connect_attempt')
    connect['success'] = 'success'
    assert 'connection_result_differs_from_kernel_return' in validate(tree, 'model', 'policy')
