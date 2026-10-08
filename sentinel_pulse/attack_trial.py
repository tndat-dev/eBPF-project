"""One serialized frozen trial; independent kernel provenance, no model tuning."""
from __future__ import annotations

import json
from pathlib import Path
import shlex
import subprocess
import time

from .run_500ms_blind_matrix import append_jsonl, binary_path_for_controller, ready_pods, select_cgroup
from .tetragon_evidence import EXEC_PROVENANCE_POLICY, find_execve_kprobe_event


def first_alert(records, injection, model_sha, policy_sha):
    accepted = []
    for row in records:
        if row.get('injection_id') != injection['injection_id']:
            continue
        if (row.get('status') != 'alert' or row.get('workload_key') != injection['workload_key']
                or str(row.get('cgroup_id')) != str(injection['cgroup_id'])
                or row.get('pod_uid') != injection['pod_uid']
                or row.get('node_name') != injection['node_name']
                or row.get('model_manifest_sha256') != model_sha
                or row.get('decision_policy_sha256') != policy_sha):
            raise ValueError('attributed alert identity/model/policy mismatch')
        if not injection['injected_at'] <= float(row['alerted_at']) <= injection['injected_at'] + 15:
            raise ValueError('alert outside frozen injection attribution horizon')
        accepted.append(row)
    return min(accepted, key=lambda r: float(r['alerted_at'])) if accepted else None


def select_target(runtime, row, workers, index):
    """Resolve exact controller/container from cgroup identity, not pod prefix."""
    pods = ready_pods(runtime.kubectl_json('get', 'pods', '-n', 'production', '-o', 'json'), row['workload_controller'])
    expected_container = row['workload_key'].split(':', 1)[1]
    cache, matches = {}, []
    for pod in pods:
        worker = workers.get(pod['node_name'])
        if worker is None or (expected_container != 'pod-slice' and expected_container not in pod['containers']):
            continue
        if pod['node_name'] not in cache:
            cache[pod['node_name']] = json.loads(runtime.remote_sudo(worker['host'], 'cat /run/sentinel-pulse/cgroups.json').stdout)
        try:
            cg, identity = select_cgroup(cache[pod['node_name']], pod['uid'], expected_container)
        except ValueError:
            continue
        if identity.get('namespace') != 'production' or identity.get('workload_name') != row['workload_controller']:
            continue
        container = pod['containers'][0] if expected_container == 'pod-slice' else expected_container
        matches.append((pod, worker, container, cg))
    if not matches:
        raise RuntimeError('no exact ready controller/container/cgroup target: ' + row['workload_key'])
    return matches[(index-1) % len(matches)]


def execute(runtime, root, row, injection_id, workers, binary, duration, post_wait,
            model_sha, policy_sha):
    index = int(injection_id.rsplit(':', 1)[1])
    pod, worker, container, cg = select_target(runtime, row, workers, index)
    node = runtime.kubectl_json('get', 'node', pod['node_name'], '-o', 'json')
    conditions = {c['type']: c['status'] for c in node['status'].get('conditions', [])}
    if conditions.get('Ready') != 'True' or any(conditions.get(c) == 'True' for c in ('MemoryPressure', 'PIDPressure')):
        raise RuntimeError('target node is not safe for a bounded generator process tree')
    path = binary_path_for_controller(row['workload_controller'])
    prefix = ['kubectl', 'exec', '-n', 'production', pod['name'], '-c', container, '--']
    # Never overwrite/remove a pre-existing operator file.
    runtime.run(prefix + ['sh', '-c', 'test ! -e "$1"', 'pulse-absent', path], timeout=30)
    created, capture = False, None
    result = dict(row, injection_id=injection_id, pod_name=pod['name'], pod_uid=pod['uid'],
                  node_name=pod['node_name'], cgroup_id=cg, detected=False, status='infrastructure_unknown')
    raw = root / 'trials' / f'{index:04d}'
    raw.mkdir(parents=True, exist_ok=True)
    try:
        created = True
        runtime.run(prefix[:2] + ['-i'] + prefix[2:] + ['sh', '-c',
                    'umask 077; cat > "$1" && chmod 0755 "$1"', 'pulse-copy', path],
                    input_bytes=binary.read_bytes(), timeout=120)
        runtime.run(prefix + ['sh', '-c', 'test "$(wc -c < "$1")" -eq "$2"',
                    'pulse-size', path, str(binary.stat().st_size)], timeout=30)
        sensors = runtime.kubectl_json('get', 'pods', '-n', 'kube-system', '-l', 'app.kubernetes.io/name=tetragon', '-o', 'json')
        sensor = next((p['metadata']['name'] for p in sensors['items'] if p['spec'].get('nodeName') == pod['node_name']), None)
        if sensor is None:
            raise RuntimeError('no node-local Tetragon provenance sensor')
        policies = runtime.run(['kubectl', 'exec', '-n', 'kube-system', sensor, '-c', 'tetragon',
                                '--', 'tetra', 'tracingpolicy', 'list']).stdout.decode()
        if not any(EXEC_PROVENANCE_POLICY in line and 'enabled' in line for line in policies.splitlines()):
            raise RuntimeError('exec provenance policy is not enabled')
        with (raw / 'tetragon.jsonl').open('wb') as out, (raw / 'tetragon.stderr').open('wb') as err:
            capture = subprocess.Popen(['timeout', str(duration + 5) + 's', 'kubectl', 'exec', '-n',
                'kube-system', sensor, '-c', 'tetragon', '--', 'tetra', 'getevents', '-o', 'json',
                '--policy-names', EXEC_PROVENANCE_POLICY], stdout=out, stderr=err, env=runtime.environment)
            time.sleep(0.5)
            injection = dict(result, schema='sentinel-pulse-injection-v1', injected_at=time.time(),
                             duration_seconds=duration, binary_path=path)
            # INTENT is committed BEFORE dispatch. Crash ambiguity is a retained
            # unscored trial, never permission to execute this seed twice.
            append_jsonl(root / 'INTENTS.jsonl', injection)
            runtime.remote_sudo(worker['host'], 'tee -a -- ' + shlex.quote(worker['injections']),
                                payload=(json.dumps(injection, separators=(',', ':')) + '\n').encode())
            append_jsonl(root / 'injections.jsonl', injection)
            attack = runtime.run(prefix + [path, row['scenario'], str(duration), str(row['rate_per_second']), str(row['seed'])],
                                 timeout=duration + 30)
            (raw / 'attack.stdout').write_bytes(attack.stdout)
            (raw / 'attack.stderr').write_bytes(attack.stderr)
            stderr = attack.stderr.decode(errors='replace')
            if 'sentinel-runtime-attack start' not in stderr or 'sentinel-runtime-attack done' not in stderr:
                raise RuntimeError('frozen binary acknowledgement missing')
            capture.wait(timeout=15)
            capture = None
        # Respect the implementation's post-attack wait; association itself is
        # still the unchanged live detector's 15-second horizon.
        time.sleep(post_wait)
        kernel = find_execve_kprobe_event((raw / 'tetragon.jsonl').read_text().splitlines(), injection,
                                          expected_binary=path, maximum_delay_seconds=10)
        append_jsonl(root / 'kernel-events.jsonl', kernel)
        de = Path(worker['injections']).parent / 'decisions.jsonl'
        needle = '"injection_id":"' + injection_id + '"'
        lines = runtime.remote_sudo(worker['host'], 'grep -F -- ' + shlex.quote(needle) + ' ' + shlex.quote(str(de)) + ' || true').stdout
        (raw / 'attributed-alerts.jsonl').write_bytes(lines)
        alert = first_alert([json.loads(line) for line in lines.splitlines()], injection, model_sha, policy_sha)
        tail = runtime.remote_sudo(worker['host'], 'tail -n 16000 -- ' + shlex.quote(str(de))).stdout
        (raw / 'decision-tail.jsonl').write_bytes(tail)
        target_rows = []
        for line in tail.splitlines():
            record = json.loads(line)
            if (record.get('workload_key') == row['workload_key'] and str(record.get('cgroup_id')) == str(cg)
                    and record.get('pod_uid') == pod['uid'] and record.get('node_name') == pod['node_name']
                    and injection['injected_at'] <= float(record.get('window_end', 0)) <= injection['injected_at'] + duration):
                if (record.get('model_manifest_sha256') != model_sha
                        or record.get('decision_policy_sha256') != policy_sha):
                    raise ValueError('target decision model/policy drift')
                target_rows.append(record)
        result['scored_target_windows'] = sum(r.get('status') in {'normal', 'suppressed', 'alert'} for r in target_rows)
        result['target_status_counts'] = {s: sum(r.get('status') == s for r in target_rows)
                                         for s in sorted({r.get('status', 'missing') for r in target_rows})}
        result['minimum_scored_target_windows'] = int(duration / 0.5 * 0.9)
        if result['scored_target_windows'] < result['minimum_scored_target_windows']:
            raise RuntimeError('target had insufficient scored coverage during injected interval')
        result.update(status='observed', detected=alert is not None, kernel_event_at=kernel['kernel_event_at'],
                      kernel_exec_id=kernel['exec_id'], injected_at=injection['injected_at'])
        if alert:
            latency = float(alert['alerted_at']) - float(kernel['kernel_event_at'])
            if latency < 0:
                raise ValueError('negative kernel-to-alert latency; clock/provenance invalid')
            result.update(first_alert_at=alert['alerted_at'], kernel_to_alert_seconds=latency,
                          inference_ms=alert.get('inference_ms'))
    except Exception as exc:
        # All raw output already written remains accessible. Evidence failure
        # cannot turn a negative/unknown trial into a claimed TP.
        result.update(status='infrastructure_unknown', detected=False,
                      error_type=type(exc).__name__, error=str(exc))
        if isinstance(exc, (subprocess.CalledProcessError, subprocess.TimeoutExpired)):
            for name in ('stdout', 'stderr'):
                value = getattr(exc, name, None)
                if value:
                    (raw / ('failure.' + name)).write_bytes(value if isinstance(value, bytes) else value.encode())
    finally:
        if capture is not None:
            capture.terminate()
            try:
                capture.wait(timeout=5)
            except subprocess.TimeoutExpired:
                capture.kill(); capture.wait()
        if created:
            cleanup = runtime.run(prefix + ['rm', '-f', '--', path], check=False, timeout=30)
            result['temporary_binary_cleanup_returncode'] = cleanup.returncode
            if cleanup.returncode:
                result.update(status='infrastructure_unknown', detected=False, cleanup_required=True)
    return result
