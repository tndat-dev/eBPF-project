"""Add observed lifecycle, file, credential and security objects to RCA graphs."""
from __future__ import annotations

from collections import Counter
import hashlib
import json

from .rca_tree import build_tree, event_time, identity, render_markdown


def build_runtime_tree(trigger, events, *, before_seconds=30, after_seconds=5,
                       max_events=1000, coverage=None):
    at = event_time(trigger['window_end'])
    matching = []
    for event in events:
        source = event.get('source', {})
        if (event.get('node_name'), source.get('pod_uid'), source.get('container_name')) != identity(trigger):
            continue
        if trigger.get('container_id') and source.get('container_id') != trigger['container_id']:
            continue
        if at-before_seconds <= event_time(event['observed_at']) <= at+after_seconds:
            matching.append(event)
    matching.sort(key=lambda e: (event_time(e['observed_at']), e['raw_event_sha256']))
    # Preserve rare security evidence before sampled, potentially busy file I/O.
    priority = {'credential': 0, 'namespace': 0, 'mount': 0, 'ptrace': 0, 'process': 1,
                'network': 2, 'file': 3}
    selected = sorted(sorted(matching, key=lambda e: priority.get(e.get('category'), 4))[:max_events],
                      key=lambda e: (event_time(e['observed_at']), e['raw_event_sha256']))
    connects = [e for e in selected if e.get('operation') == 'connect' or 'connection' in e]
    tree = build_tree(trigger, connects, before_seconds=before_seconds, after_seconds=after_seconds,
                      max_edges=max_events, coverage=coverage)
    nodes = {n['id']: n for n in tree['nodes']}; links = tree['edges']
    container = next(n['id'] for n in nodes.values() if n['kind'] == 'container')

    def proc(source, evidence):
        eid = source.get('exec_id')
        pid = 'exec:'+trigger['node_name']+':'+eid if eid else 'unknown-process:'+evidence
        if pid not in nodes:
            nodes[pid] = dict(id=pid, kind='process', **source)
        else:
            nodes[pid].update({k: v for k, v in source.items() if v is not None})
        return pid

    def object_node(kind, details):
        scope = dict(node_name=trigger['node_name'], pod_uid=trigger['pod_uid'],
                     container_name=trigger['container_name'], **details)
        oid = kind+':'+hashlib.sha256(json.dumps(scope, sort_keys=True).encode()).hexdigest()[:24]
        nodes[oid] = dict(id=oid, kind=kind, **scope)
        return oid

    fork_nodes = {}
    for event in selected:
        h = event['raw_event_sha256']; source = event['source']; operation = event.get('operation', 'connect')
        caller = proc(source, h)
        links.append(dict(source=container, target=caller, relation='observed_process_in_container'))
        relatives = [source, event.get('parent', {}), *event.get('ancestors', [])]
        by_exec = {p['exec_id']: p for p in relatives if p.get('exec_id')}
        for relative in relatives:
            parent_id = relative.get('parent_exec_id')
            if not relative.get('exec_id') or not parent_id or parent_id == relative['exec_id']:
                continue
            child = proc(relative, h)
            parent = proc(by_exec.get(parent_id, {'exec_id': parent_id}), h)
            links.append(dict(source=parent, target=child, relation='parent_of', evidence='tetragon_exec_identity'))
        if operation == 'connect':
            connect = nodes.get('connect:'+h)
            if connect and event.get('outcome'):
                connect['outcome'] = event['outcome']
                connect['success'] = event['outcome']['status']
            continue
        eid = 'event:'+h
        nodes[eid] = dict(id=eid, kind='runtime_event', category=event['category'],
            operation=operation, function=event['function'], observed_at=event['observed_at'],
            outcome=event['outcome'], details=event['details'], evidence_sha256=h,
            sampling=event.get('sampling'))
        links.append(dict(source=caller, target=eid, relation='performed_'+operation))
        details = event['details']; target = None
        if event['category'] == 'file':
            if details.get('file', {}).get('path'):
                obj = dict(path=details['file']['path'], path_kind='kernel_file_path',
                           path_flags=details['file'].get('flags'))
            else:
                obj = dict(path=details.get('filename') or details.get('old_path'),
                           path_kind='user_supplied_not_symlink_resolved', dirfd=details.get('dirfd', details.get('old_dirfd')),
                           cwd=source.get('cwd'), new_path=details.get('new_path'))
            target = object_node('file_object', obj)
        elif event['category'] == 'credential':
            target = object_node('credential_object', dict(request=details,
                semantics='new credential snapshot' if operation == 'commit_creds' else 'requested credentials; success may be a no-op'))
        elif event['category'] == 'namespace':
            target = object_node('namespace_object', dict(request=details, caller_exec_id=source.get('exec_id'),
                inode_resolution='unknown; namespace FD is scoped to this caller'))
        elif event['category'] == 'mount':
            target = object_node('mount_object', dict(request=details))
        elif event['category'] == 'ptrace':
            target = object_node('ptrace_target', dict(target_pid=details.get('target_pid'),
                pid_namespace='caller_pid_namespace; not merged with a host PID',
                request=details.get('ptrace_request'), address=details.get('target_address')))
        elif operation == 'fork':
            # The tracepoint reports host PIDs, but no child exec ID. This node
            # is bound to the particular fork event, never a global PID alias.
            target = object_node('fork_child', dict(host_pid=details.get('child_pid'),
                fork_evidence=h, exec_identity='not_available_in_fork_tracepoint'))
            fork_nodes[h] = target
        elif operation == 'exec':
            target = object_node('executable', dict(path=source.get('binary')))
        if target:
            links.append(dict(source=eid, target=target, relation='target_object'))
    # A child is resolved only with corroborating parent exec identity, the
    # same container and a later native exec; a PID alone never merges nodes.
    forks = [e for e in selected if e.get('operation') == 'fork']
    for fork in forks:
        child_pid = fork['details'].get('child_pid')
        if sum(f['details'].get('child_pid') == child_pid for f in forks) != 1:
            continue
        candidates = [e for e in selected if e.get('operation') == 'exec'
            and e['source'].get('pid') == child_pid and e['source'].get('exec_id')
            and e['source'].get('parent_exec_id') == fork['source'].get('exec_id')
            and event_time(e['observed_at']) >= event_time(fork['observed_at'])]
        if len(candidates) == 1:
            child = candidates[0]
            links.append(dict(source=fork_nodes[fork['raw_event_sha256']],
                target=proc(child['source'], child['raw_event_sha256']), relation='observed_child_exec',
                evidence='host_pid + parent_exec_id + exact_container + bounded_time',
                evidence_sha256=[fork['raw_event_sha256'], child['raw_event_sha256']]))
    unique = {json.dumps(e, sort_keys=True): e for e in links}
    tree.update(schema='sentinel-pulse-rca-evidence-tree-v2', nodes=list(nodes.values()), edges=list(unique.values()),
        matched_connect_events=sum(e.get('operation') == 'connect' or 'connection' in e for e in matching),
        matched_runtime_events=len(matching), retained_runtime_events=len(selected),
        event_categories=dict(Counter(e.get('category', 'network') for e in selected)),
        truncated=len(matching)>len(selected),
        limitations=['aggregate_anomaly_does_not_prove_process_causality',
            'file_open_write_detail_is_sampled_per_process_500ms',
            'kprobes_may_not_observe_syscalls_rejected_before_entry_by_seccomp',
            'return_receipt_required_for_success_or_failure',
            'namespace_fd_and_ptrace_pid_are_not_fully_resolved_kernel_objects',
            'no_file_content_argv_or_network_payload'])
    return tree


def render_runtime_markdown(tree):
    intro = render_markdown(tree).replace('Đích connect (chưa biết thành công)', 'Đích connect (kết quả theo từng event)')
    lines = [intro, '## Sự kiện runtime trong cửa sổ điều tra', '',
             '| Nhóm | Thao tác | Kết quả kernel | Đối tượng / chi tiết |', '|---|---|---|---|']
    def safe(value):
        return json.dumps(value, ensure_ascii=False).replace('|', '\\|').replace('\n', ' ')
    for n in tree['nodes']:
        if n['kind'] == 'runtime_event':
            lines.append(f"| {n['category']} | {n['operation']} | {safe(n['outcome'])} | {safe(n['details'])} |")
    lines.extend(['', 'Cây chứa bằng chứng quan sát; chưa phải kết luận nguyên nhân gốc.', ''])
    return '\n'.join(lines)
