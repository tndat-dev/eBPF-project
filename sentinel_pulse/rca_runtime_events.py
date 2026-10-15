"""Normalize lifecycle and syscall evidence without argv or file/network data."""
from __future__ import annotations

import errno
import hashlib
import json

from .rca_connect import _socket_address

SCHEMA = 'sentinel-pulse-rca-runtime-event-v1'
POLICY = 'sentinel-rca-runtime-v1'
SYSCALLS = {
    'sys_connect': ('network', 'connect'),
    'sys_open': ('file', 'open'), 'sys_openat': ('file', 'open'),
    'sys_openat2': ('file', 'open'),
    'vfs_write': ('file', 'write'), 'vfs_writev': ('file', 'write'),
    'vfs_iter_write': ('file', 'write'),
    'sys_unlinkat': ('file', 'unlink'), 'sys_renameat2': ('file', 'rename'),
    'sys_setuid': ('credential', 'setuid'), 'sys_setgid': ('credential', 'setgid'),
    'sys_setreuid': ('credential', 'setreuid'), 'sys_setregid': ('credential', 'setregid'),
    'sys_setresuid': ('credential', 'setresuid'), 'sys_setresgid': ('credential', 'setresgid'),
    'sys_capset': ('credential', 'capset'), 'commit_creds': ('credential', 'commit_creds'),
    'sys_setns': ('namespace', 'setns'), 'sys_unshare': ('namespace', 'unshare'),
    'sys_mount': ('mount', 'mount'), 'sys_umount': ('mount', 'umount'), 'sys_umount2': ('mount', 'umount'),
    'sys_ptrace': ('ptrace', 'ptrace'),
}
INTEGER_KEYS = ('int_arg', 'uint_arg', 'long_arg', 'size_arg')
INTEGER_LABELS = {'socket_fd', 'dirfd', 'flags', 'mode', 'requested_bytes', 'iov_count',
    'uid', 'gid', 'ruid', 'euid', 'suid', 'rgid', 'egid', 'sgid',
    'namespace_fd', 'namespace_flags', 'ptrace_request', 'target_pid', 'target_address',
    'old_dirfd', 'new_dirfd', 'parent_pid', 'child_pid'}
STRING_LABELS = {'filename', 'old_path', 'new_path', 'mount_source', 'mount_target', 'filesystem'}


def integer(argument):
    for key in INTEGER_KEYS:
        value = argument.get(key)
        if value is not None and not isinstance(value, bool):
            return int(value)
    return None


def text(value):
    return value[:1024] if isinstance(value, str) else None


def credentials(value):
    """Only numeric identities and capability names, never arbitrary dictionaries."""
    result = {key: int(value[key]) for key in ('uid', 'gid', 'euid', 'egid', 'suid',
        'sgid', 'fsuid', 'fsgid') if value.get(key) is not None}
    caps = value.get('caps', value)
    selected = {key: [str(v)[:80] for v in caps.get(key, [])[:64]]
                for key in ('effective', 'permitted', 'inheritable') if isinstance(caps.get(key), list)}
    if selected:
        result['capabilities'] = selected
    return result


def process(value):
    pod = value.get('pod') or {}; container = pod.get('container') or {}
    result = {key: value.get(key) for key in
              ('exec_id', 'parent_exec_id', 'pid', 'tid', 'uid', 'binary', 'start_time', 'cwd')}
    result.update(namespace=pod.get('namespace'), pod_name=pod.get('name'), pod_uid=pod.get('uid'),
                  container_name=container.get('name'), container_id=container.get('id'))
    if isinstance(value.get('process_credentials'), dict):
        result['credentials_snapshot'] = credentials(value['process_credentials'])
    return result


def outcome(value, operation):
    if value is None:
        return dict(status='unknown', return_observed=False, return_value=None, errno=None)
    if operation == 'connect' and value in (-errno.EINPROGRESS, -errno.EALREADY):
        status = 'in_progress'
    else:
        status = 'success' if value >= 0 else 'failure'
    return dict(status=status, return_observed=True, return_value=value,
                errno=errno.errorcode.get(-value) if -4095 <= value < 0 else None)


def normalize_runtime_event(record, target_index=None, *, policy_names=(POLICY,)):
    native = next((k for k in ('process_exec', 'process_exit') if isinstance(record.get(k), dict)), None)
    event = record.get(native) if native else record.get('process_kprobe', record.get('process_tracepoint'))
    if not isinstance(event, dict) or not isinstance(event.get('process'), dict):
        return None
    args = event.get('args') or []
    if native:
        category, operation = 'process', 'exec' if native == 'process_exec' else 'exit'
        function = native
    else:
        if event.get('policy_name') not in policy_names:
            return None
        if (event.get('subsys') == 'sched' and event.get('event') == 'sched_process_fork'):
            category, operation, function = 'process', 'fork', 'sched_process_fork'
        else:
            function = str(event.get('function_name', '')).removeprefix('__x64_').removeprefix('__arm64_')
            if function not in SYSCALLS:
                return None
            category, operation = SYSCALLS[function]
    details = {}
    for argument in args:
        label = argument.get('label')
        if label in INTEGER_LABELS:
            details[label] = integer(argument)
        elif label in STRING_LABELS:
            details[label] = text(argument.get('string_arg'))
        elif label == 'file':
            file = argument.get('file_arg') or argument.get('path_arg') or {}
            details['file'] = {k: text(file.get(k)) for k in ('path', 'mount', 'flags', 'permission')}
        elif label == 'new_credentials':
            value = argument.get('process_credentials_arg') or argument.get('cred_arg') or {}
            details['new_credentials'] = credentials(value)
    ret = integer(event.get('return') or {})
    result = dict(schema=SCHEMA, observed_at=record.get('time'), node_name=record.get('node_name'),
        category=category, operation=operation, function=function,
        source=process(event['process']), parent=process(event.get('parent') or {}),
        ancestors=[process(p) for p in (event.get('ancestors') or [])[:16]],
        details=details, outcome=outcome(ret, operation),
        policy_name=event.get('policy_name'),
        raw_event_sha256=hashlib.sha256(json.dumps(record, sort_keys=True, separators=(',', ':')).encode()).hexdigest(),
        application_payload_captured=False)
    if native == 'process_exec':
        result['outcome'] = dict(status='executed', return_observed=False, return_value=None)
    elif native == 'process_exit':
        result['outcome'] = dict(status='exited', exit_status=int(event.get('status', 0)),
                                 signal=text(event.get('signal')), return_observed=False, return_value=None)
    elif operation == 'fork':
        result['outcome'] = dict(status='child_created', return_observed=False, return_value=None)
    if category == 'file' and operation in ('open', 'write'):
        result['sampling'] = dict(rate_limit_ms=500, scope='process', exhaustive=False)
    if operation == 'connect':
        address, port, family = _socket_address(args)
        result['connection'] = dict(socket_fd=details.get('socket_fd'))
        result['destination'] = dict(address=address, port=port, family=family,
                                    kubernetes=(target_index or {}).get(address))
    return result
