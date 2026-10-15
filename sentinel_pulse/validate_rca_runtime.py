"""Capture an isolated live fixture and replay its multi-event RCA evidence.

The output is explicitly manual observability validation, never an ML alert,
blind attack, classifier evaluation, or normal-training admission.
"""
from __future__ import annotations

import argparse
from collections import Counter
import json
import os
from pathlib import Path
import subprocess
import time

from .integrity import sha256_file
from .rca_runtime_events import POLICY, FORK_POLICY, normalize_runtime_event
from .rca_runtime_tree import build_runtime_tree, render_runtime_markdown
from .rca_tree import event_time

NAMESPACE = 'sentinel-rca-validation'
POD = 'rca-runtime-proof-20261015'


def command(*args, timeout=30):
    return subprocess.run(['kubectl', '--request-timeout=15s', *args],
                          capture_output=True, timeout=timeout, check=True)


def write_new(path, value):
    with path.open('x') as stream:
        json.dump(value, stream, indent=2, sort_keys=True, allow_nan=False)
        stream.write('\n'); stream.flush(); os.fsync(stream.fileno())


def run(fixture, output, *, namespace=NAMESPACE, pod_name=POD):
    pod = json.loads(command('get', 'pod', pod_name, '-n', namespace, '-o', 'json').stdout)
    spec = pod['spec']; security = spec.get('securityContext', {}); container = spec['containers'][0]
    if (security.get('runAsUser') != 1000 or not security.get('runAsNonRoot')
            or spec.get('hostPID') or spec.get('hostNetwork') or spec.get('hostIPC')
            or container['securityContext'].get('privileged')
            or 'ALL' not in container['securityContext']['capabilities']['drop']
            or any('hostPath' in v for v in spec.get('volumes', []))):
        raise ValueError('validation target is not the isolated, non-root fixture pod')
    if output.exists():
        raise ValueError('refuse to overwrite a previous validation attempt')
    output.mkdir(parents=True)
    sensors = json.loads(command('get', 'pods', '-n', 'kube-system',
                                '-l', 'app.kubernetes.io/name=tetragon', '-o', 'json').stdout)
    sensor = next(p['metadata']['name'] for p in sensors['items']
                  if p['spec'].get('nodeName') == spec['nodeName'])
    policy_list = json.loads(command('exec', '-n', 'kube-system', sensor, '-c', 'tetragon',
                                    '--', 'tetra', 'tracingpolicy', 'list', '-o', 'json').stdout)
    for name in (POLICY, FORK_POLICY):
        policy = next((p for p in policy_list['policies'] if p['name'] == name
                       and p.get('namespace') == namespace), None)
        if not policy or policy.get('state') != 'TP_STATE_ENABLED':
            write_new(output/'BLOCKED.json', dict(reason='validation_policy_not_enabled', policy=name,
                                                  observed=policy))
            raise ValueError('validation policy is not enabled: '+name)
    write_new(output/'START.json', dict(registered_at_unix=time.time(), fixture_sha256=sha256_file(fixture),
        fixture_kind='restricted_observability_fixture', namespace=namespace, pod_name=pod_name,
        pod_uid=pod['metadata']['uid'], node_name=spec['nodeName'], policies=policy_list,
        attack_or_ML_evaluation=False, modifies_existing_workload=False,
        production_namespace_fixture=namespace == 'production', normal_training_admission=False))
    command('cp', str(fixture), namespace+'/'+pod_name+':/proof/rca-runtime-probe', '-c', 'probe')
    process = None
    with (output/'raw.jsonl').open('xb') as raw, (output/'capture.stderr').open('xb') as errors:
        try:
            process = subprocess.Popen(['kubectl', 'exec', '-n', 'kube-system', sensor,
                '-c', 'tetragon', '--', 'tetra', 'getevents', '-o', 'json', '--namespace', namespace,
                '--event-types', 'PROCESS_EXEC,PROCESS_EXIT,PROCESS_KPROBE,PROCESS_TRACEPOINT'],
                stdout=raw, stderr=errors)
            time.sleep(2)
            result = command('exec', '-n', namespace, pod_name, '-c', 'probe', '--',
                             '/proof/rca-runtime-probe', timeout=25)
            (output/'fixture.stdout').write_bytes(result.stdout)
            (output/'fixture.stderr').write_bytes(result.stderr)
            time.sleep(5)
        finally:
            if process is not None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill(); process.wait()
            raw.flush(); os.fsync(raw.fileno())
    normalized = []
    for line in (output/'raw.jsonl').read_text().splitlines():
        record = normalize_runtime_event(json.loads(line))
        if record and record['source']['pod_uid'] == pod['metadata']['uid']:
            normalized.append(record)
    with (output/'normalized.jsonl').open('x') as stream:
        for event in normalized:
            stream.write(json.dumps(event, separators=(',', ':'))+'\n')
    receipts = [json.loads(line) for line in (output/'fixture.stdout').read_text().splitlines()]
    checks = {}
    pairs = {'setuid_same': 'setuid', 'setuid_denied': 'setuid', 'setgid_same': 'setgid',
        'capset_empty': 'capset', 'unshare_zero': 'unshare', 'unshare_denied': 'unshare',
        'setns_invalid': 'setns', 'mount_denied': 'mount', 'ptrace_missing': 'ptrace',
        'unlink_file': 'unlink'}
    for receipt in receipts:
        name = receipt['operation']
        if name in pairs:
            checks[name] = any(e['operation'] == pairs[name] and e['outcome'].get('return_value') == receipt['kernel_return']
                               for e in normalized)
    for key, operation, predicate in (
        ('open_file', 'open', lambda e: e['details'].get('filename') == '/proof/sentinel-rca-proof.txt' and e['outcome']['status'] == 'success'),
        ('open_missing', 'open', lambda e: e['details'].get('filename') == '/proof/not-existing' and e['outcome']['return_value'] == -2),
        ('write_file', 'write', lambda e: e['details'].get('file', {}).get('path') == '/proof/sentinel-rca-proof.txt' and e['outcome']['return_value'] == 10),
    ):
        checks[key] = any(e['operation'] == operation and predicate(e) for e in normalized)
    for operation in ('fork', 'exec', 'exit', 'commit_creds'):
        checks[operation] = any(e['operation'] == operation for e in normalized)
    trigger = dict(node_name=spec['nodeName'], pod_uid=pod['metadata']['uid'], container_name='probe',
        workload_key=namespace+'/'+pod_name+':probe', window_end=max((event_time(e['observed_at']) for e in normalized), default=time.time()),
        candidate_alert_preview=False, alert=False, policy_evaluated=False,
        trigger_purpose='manual_observability_validation', run_id='rca-runtime-proof-20261015')
    tree = build_runtime_tree(trigger, normalized, coverage=dict(validation_namespace=namespace != 'production',
                              production_namespace_fixture=namespace == 'production',
                              fixture_sha256=sha256_file(fixture), production_ML_trigger=False))
    write_new(output/'TREE.json', tree)
    with (output/'TREE.md').open('x') as stream:
        stream.write(render_runtime_markdown(tree))
    nodes = {n['id'] for n in tree['nodes']}
    checks['fork_pid_arguments'] = any(e['operation'] == 'fork'
        and e['details'].get('parent_pid') == e['source'].get('pid')
        and (e['details'].get('child_pid') or 0) > 0 for e in normalized)
    checks['fork_child_exec_link'] = any(e['relation'] == 'observed_child_exec' for e in tree['edges'])
    checks['child_exit_status'] = any(e['operation'] == 'exit' and e['outcome'].get('exit_status') == 3 for e in normalized)
    checks['empty_capabilities_observed'] = any(e['operation'] == 'commit_creds'
        and e['details'].get('new_credentials', {}).get('capabilities') == dict(effective=[], permitted=[], inheritable=[])
        for e in normalized)
    checks['no_dangling_edges'] = all(e['source'] in nodes and e['target'] in nodes for e in tree['edges'])
    checks['no_argv_or_file_payload'] = not any(k in json.dumps(normalized) for k in ('SECRET_ARG', 'RCA-proof\\n'))
    report = dict(state='completed_observability_validation' if all(checks.values()) else 'completed_with_missing_evidence',
        completed_at_unix=time.time(), checks=checks, categories=dict(Counter(e['category'] for e in normalized)),
        operations=dict(Counter(e['operation'] for e in normalized)), normalized_events=len(normalized),
        graph_nodes=len(tree['nodes']), graph_edges=len(tree['edges']),
        ML_alert_triggered=False, blind_attack=False, model_metrics_measured=False,
        files_sha256={p.name: sha256_file(p) for p in output.iterdir() if p.is_file()})
    write_new(output/'TERMINAL.json', report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fixture', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--namespace', default=NAMESPACE)
    parser.add_argument('--pod', default=POD)
    args = parser.parse_args()
    print(json.dumps(run(args.fixture, args.output, namespace=args.namespace, pod_name=args.pod), indent=2))


if __name__ == '__main__':
    main()
