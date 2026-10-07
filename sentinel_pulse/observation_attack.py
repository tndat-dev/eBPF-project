"""Detached, checkpointed evaluation of a soaked, frozen candidate.

Results-first observational campaign, NOT the legacy NORMAL_PASS promotion
protocol. Nonzero normal alerts and detection misses never stop the matrix.
Infrastructure failures remain unknown; no injected seed is silently rerun.
"""
from __future__ import annotations

import argparse
import fcntl
import json
import os
from pathlib import Path
import shlex
import subprocess
import time

import numpy as np

from .attack_admission import admit
from .attack_trial import execute
from .blind_contract import load_contract
from .detector_freshness import CONTRACT, CONTRACT_SHA256
from .finalize_candidate import verify_model_bundle
from .integrity import sha256_file
from .recovery_worker_probe import clean_source
from .run_500ms_blind_matrix import Runtime, append_jsonl, atomic_json, build_schedule, cluster_gate, controller_model_workload


class AttackRuntime(Runtime):
    def remote_sudo(self, host, command, *, payload=b'', timeout=30):
        # Force sudo to consume exactly the password line even with cached
        # credentials; never let it leak into a JSON/tee payload.
        return self.run(['sshpass', '-e', 'ssh', '-o', 'StrictHostKeyChecking=yes',
                         '-o', 'ConnectTimeout=8', f'{self.ssh_user}@{host}', 'sudo -k -S -p "" ' + command],
                        input_bytes=self.password.encode() + b'\n' + payload, timeout=timeout)


def rows(path):
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines()]


def trial_key(row):
    return tuple(row[k] for k in ('workload_controller', 'scenario', 'seed', 'rate_per_second'))


def schedule(contract, seed):
    all_rows = build_schedule(contract, seed)
    # A fixed engineering pilot comes first, with no accuracy-dependent
    # promotion gate between it and the rest. Every row appears exactly once.
    pilot = [r for r in all_rows if r['workload_controller'] in {
        'api-gateway', 'aims-postgres-cnpg', 'aims-kafka-dual-role'} and r['seed'] == 53051]
    rest = [r for r in all_rows if trial_key(r) not in {trial_key(p) for p in pilot}]
    return pilot + rest


def result_report(plan, trials):
    keys = [trial_key(r) for r in trials]
    if len(set(keys)) != len(keys) or not set(keys) <= {trial_key(r) for r in plan}:
        raise ValueError('duplicate or out-of-plan trial receipt')
    observed = [r for r in trials if r['status'] == 'observed']
    tp = sum(r['detected'] is True for r in observed)
    latency = [r['kernel_to_alert_seconds'] for r in observed if r.get('detected')]
    measured = {p: float(np.percentile(latency, q)) for p, q in (('p50', 50), ('p95', 95), ('p99', 99))} if latency else None
    return {
        'schema': 'sentinel-pulse-observation-attack-results-v1',
        'expected_trial_intervals': len(plan), 'completed_trial_receipts': len(trials),
        'progress_percent': len(trials) / len(plan) * 100,
        'observed_attack_intervals': len(observed), 'detected_attack_intervals': tp,
        'observed_misses': len(observed) - tp,
        'infrastructure_unknown_intervals': len(trials) - len(observed),
        'end_to_end_detection_fraction_on_completed_planned_trials': tp / len(trials) if trials else None,
        'conditional_observed_attack_recall': tp / len(observed) if observed else None,
        'planned_full_matrix_detection_lower_bound': tp / len(plan),
        'kernel_to_alert_seconds_detected_trials_only': measured,
        'latency_sample_count': len(latency), 'precision': None, 'false_positive_rate': None,
        'confusion_matrix': {'TP_observed': tp, 'FN_observed': len(observed)-tp,
                             'attack_unknown': len(trials)-len(observed), 'FP': None, 'TN': None},
        'normal_soak_alerts_not_silently_adjudicated': True,
        'mixed_window_and_interval_denominators_forbidden': True,
        'attack_attribution_horizon_seconds': 15,
        'minimum_scored_window_fraction_for_observed_trial': 0.9,
        'evidence_class': 'observation_attack_matrix', 'automatic_promotion': False,
        'formal_legacy_pass': False, 'attack_outcomes_used_for_training_or_tuning': False,
    }


def recover_intents(root, plan):
    done = {trial_key(r) for r in rows(root / 'TRIALS.jsonl')}
    allowed = {trial_key(r) for r in plan}
    intents = rows(root / 'INTENTS.jsonl')
    if len({r['injection_id'] for r in intents}) != len(intents):
        raise ValueError('duplicate attack dispatch intent')
    for marker in intents:
        key = trial_key(marker)
        if key not in allowed:
            raise ValueError('dispatch intent outside registration')
        if key not in done:
            append_jsonl(root / 'TRIALS.jsonl', {
                **marker, 'status': 'infrastructure_unknown', 'detected': False,
                'error': 'coordinator interrupted after dispatch intent; not rerun',
                'resume_requires_temporary_binary_review': True})
            done.add(key)


def remote_python(runtime, cfg, host, module, args, payload=None, timeout=40):
    source = cfg['workers'][host]['source']
    cmd = shlex.join(['/usr/bin/env', 'PYTHONPATH=' + source, 'PYTHONDONTWRITEBYTECODE=1',
                      '/opt/sentinel-pulse/runtime-venv/bin/python', '-m', 'sentinel_pulse.' + module, *args])
    return runtime.remote_sudo(host, cmd, payload=payload or b'', timeout=timeout)


def close_leg(runtime, cfg, root, leg):
    errors = {}
    for host in cfg['workers']:
        try:
            unit = 'pulse-attack-leg-' + leg + '.service'
            # A reboot loses transient parent units. Still stop the capture
            # ONLY if its environment proves this leg's ownership.
            runtime.remote_sudo(host, shlex.join(['systemctl', 'stop', unit]) + ' || true', timeout=100)
            remote_python(runtime, cfg, host, 'attack_worker', ['stop', '--run-id', leg], timeout=100)
            # Worker parent seals raw capture/decisions/alerts/injections locally.
            seal = runtime.remote_sudo(host, 'cat ' + shlex.quote('/var/lib/sentinel-pulse-500ms/runs/' + leg + '/ATTACK_RAW_SEAL.json')).stdout
            atomic_json(root / ('seal-' + leg + '-' + host + '.json'), json.loads(seal))
        except Exception as exc:
            errors[host] = str(exc)
    append_jsonl(root / 'LEGS.jsonl', {'run_id': leg, 'closed_at_unix': time.time(), 'errors': errors})
    return errors


def start_leg(runtime, cfg, root, start, number):
    leg = start['run_id'] + f'-a{number:04d}'
    workers = {}
    for host, worker in cfg['workers'].items():
        args = ['preflight-observation', '--source', worker['source'], '--model', worker['model'],
                '--policy', worker['policy'], '--safety', worker['safety'], '--worker-ip', host]
        binding = json.loads(remote_python(runtime, cfg, host, 'recovery_worker_probe', args).stdout)
        if binding['source_commit'] != start['source_commit']:
            raise ValueError('worker source commit differs from registered evaluator')
        for name in ('model_manifest_sha256', 'decision_policy_sha256'):
            if binding[name] != start[name]:
                raise ValueError('worker candidate differs from soaked candidate')
        marker = {
            'schema': 'sentinel-pulse-attack-worker-start-v1', 'run_id': leg,
            'campaign_start_sha256': sha256_file(root / 'START.json'),
            'source_commit': start['source_commit'], 'runtime_files': start['runtime_files'],
            'worker_binding': binding, 'duration_seconds': 1800,
            'model_manifest_sha256': start['model_manifest_sha256'],
            'decision_policy_sha256': start['decision_policy_sha256'],
            'recovery_profile_sha256': start['recovery_profile_sha256'],
            'detector_freshness_contract': CONTRACT, 'detector_freshness_contract_sha256': CONTRACT_SHA256,
            'model': worker['model'], 'policy': worker['policy'], 'safety': worker['safety'],
            'automatic_promotion': False,
        }
        path = '/var/lib/sentinel-pulse-attack-registration/' + leg
        code = 'import pathlib,sys; p=pathlib.Path(sys.argv[1]); p.mkdir(parents=True,exist_ok=False); f=p/"START.json"; f.write_bytes(sys.stdin.buffer.read()); f.chmod(0o444)'
        runtime.remote_sudo(host, shlex.join(['python3', '-c', code, path]),
                            payload=(json.dumps(marker, sort_keys=True) + '\n').encode())
        cmd = ['systemd-run', '--quiet', '--unit=pulse-attack-leg-' + leg,
               '--property=TimeoutStopSec=90', '--property=RuntimeMaxSec=2500',
               '/usr/bin/env', 'PYTHONPATH=' + worker['source'], 'PYTHONDONTWRITEBYTECODE=1',
               '/opt/sentinel-pulse/runtime-venv/bin/python', '-m', 'sentinel_pulse.attack_worker',
               'run', '--run-id', leg, '--source', worker['source']]
        runtime.remote_sudo(host, shlex.join(cmd))
        workers[binding['node_name']] = {'host': host}
    # Installation is detached from this SSH. Wait for validated capture and
    # freshness-bound ML startup; this wait does not consume attack trials.
    deadline = time.monotonic() + 600
    last_error = None
    while time.monotonic() < deadline:
        try:
            for node, worker in workers.items():
                reply = json.loads(remote_python(runtime, cfg, worker['host'], 'attack_worker', ['probe', '--run-id', leg]).stdout)
                if reply['detector']['ActiveState'] != 'active' or not reply['capture']['valid']:
                    raise RuntimeError('worker not ready: ' + node)
                worker.update(injections=reply['injections'], feature=reply['features'])
            time.sleep(5)  # history/freshness warm-up, never treated as scored exposure
            return leg, workers
        except Exception as exc:
            last_error = str(exc)
            time.sleep(10)
    raise RuntimeError('worker startup unavailable: ' + str(last_error))


def register(cfg, normal_root, root, seed):
    source, model, policy = Path(cfg['source']), Path(cfg['model']), Path(cfg['policy'])
    commit, files = clean_source(source)
    manifest, candidates, collect_only = verify_model_bundle(model)
    if collect_only:
        raise ValueError('candidate bundle is incomplete')
    model_sha, policy_sha = sha256_file(model / 'manifest.json'), sha256_file(policy)
    admission = admit(normal_root, manifest, model_sha, policy_sha)
    # Only orchestration/admission may differ from the soaked source. Core ML,
    # capture, feature and decision code is verified byte-for-byte before attacks.
    soaked_source = Path(json.loads((normal_root / 'START.json').read_text())['binding']['config']['source'])
    cores = ['capture.py', 'features.py', 'encoding.py', 'integrity.py', 'detect.py', 'model.py',
             'decision_policy.py', 'telemetry_recovery.py', 'detector_freshness.py', 'latency.py']
    for filename in cores:
        rel = 'sentinel_pulse/' + filename
        if sha256_file(source / rel) != sha256_file(soaked_source / rel):
            raise ValueError('scoring/capture differs from soaked candidate: ' + filename)
    contract_path = source / 'sentinel_pulse/protocol/development-r10/blind-attack-contract-r10.json'
    implementation_path = source / 'sentinel_pulse/protocol/attack-implementation-contract-b1.json'
    contract = load_contract(contract_path)
    if manifest['blind_attack_contract_sha256'] != sha256_file(contract_path):
        raise ValueError('matrix differs from contract frozen before training')
    implementation = json.loads(implementation_path.read_text())
    binary_source = source / implementation['source']['path']
    independence = contract['pretraining_independence']
    for name, actual in [('source_implementation_contract_sha256', sha256_file(implementation_path)),
                         ('source_runtime_sha256', sha256_file(binary_source))]:
        if independence[name] != actual:
            raise ValueError('frozen attack implementation drift')
    safety = contract['safety_contract']
    if safety != {'external_network': False, 'persistent_write': False, 'successful_mount': False,
                  'successful_privilege_change': False, 'target_namespace': 'production'}:
        raise ValueError('unsafe attack contract')
    plan = schedule(contract, seed)
    for item in plan:
        item['workload_key'] = controller_model_workload(manifest, item['workload_controller'])
    binding = {'source_commit': commit, 'runtime_files': files, 'config': cfg,
               'normal_admission': admission, 'schedule': plan, 'schedule_seed': seed,
               'model_manifest_sha256': model_sha, 'decision_policy_sha256': policy_sha,
               'contract_sha256': sha256_file(contract_path), 'implementation_sha256': sha256_file(implementation_path),
               'binary_sha256': implementation['binary']['sha256'],
               'recovery_profile_sha256': sha256_file(source / 'sentinel_pulse/protocol/telemetry-recovery-v1.json'),
               'exec_policy_sha256': sha256_file(source / 'sentinel/k8s/tetragon-sentinel-pulse-exec-provenance.yaml'),
               'post_attack_wait_seconds': implementation['post_attack_wait_seconds'],
               'attack_seconds': implementation['attack_seconds'], 'maximum_wall_seconds': 86400,
               'minimum_scored_window_fraction_for_observed_trial': 0.9,
               'global_health_warning_policy': 'retain context; only target readiness, telemetry and safety block dispatch',
               'zero_alert_gate': False, 'stop_on_detection_miss': False, 'automatic_promotion': False,
               'evidence_class': 'observation_attack_matrix', 'attack_outcomes_used_for_training_or_tuning': False}
    start_path = root / 'START.json'
    if start_path.exists():
        start = json.loads(start_path.read_text())
        if {k: start[k] for k in binding} != binding:
            raise ValueError('registered campaign binding changed')
    else:
        root.mkdir(parents=True, exist_ok=False)
        start = dict(binding, schema='sentinel-pulse-observation-attack-start-v1',
                     run_id=root.name, started_at_unix=time.time())
        atomic_json(start_path, start); start_path.chmod(0o444)
    binary = root / 'runtime_attack_blind'
    if not binary.exists():
        subprocess.run(['gcc', '-O2', '-Wall', '-Wextra', '-Werror', '-static', str(binary_source), '-o', str(binary)], check=True)
    if sha256_file(binary) != binding['binary_sha256']:
        raise ValueError('static binary checksum differs from frozen implementation')
    binary.chmod(0o555)
    return start


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--normal-root', type=Path, required=True)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--password-file', type=Path, required=True)
    parser.add_argument('--seed', type=int, default=20261007)
    args = parser.parse_args()
    if args.password_file.stat().st_mode & 0o077:
        raise ValueError('credential must not be group/world readable')
    cfg = json.loads(args.config.read_text())
    if set(cfg['workers']) != {'10.1.16.237', '10.1.16.238', '10.1.16.239'}:
        raise ValueError('explicit three-worker configuration required')
    runtime = AttackRuntime(args.password_file.read_text().strip())
    with Path('/home/dat/.pulse-attack-campaign.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        root = args.root
        start = register(cfg, args.normal_root, root, args.seed)
        if (root / 'TERMINAL.json').exists():
            return
        recover_intents(root, start['schedule'])
        # An SSH disconnect need not terminate the process inside the pod.
        # Wait out the frozen generator's lifetime before any next dispatch.
        dispatches = rows(root / 'INTENTS.jsonl')
        if dispatches:
            until = max(r['injected_at'] + start['attack_seconds'] + start['post_attack_wait_seconds'] for r in dispatches)
            while time.time() < until:
                time.sleep(min(10, until - time.time()))
        active = rows(root / 'ACTIVE_LEG.jsonl')
        if active:
            close_leg(runtime, cfg, root, active[-1]['run_id'])
        leg, workers = None, None
        number = len(active)
        deadline = start['started_at_unix'] + start['maximum_wall_seconds']
        try:
            for index, trial in enumerate(start['schedule'], 1):
                if trial_key(trial) in {trial_key(r) for r in rows(root / 'TRIALS.jsonl')}:
                    continue
                if time.time() >= deadline:
                    break
                while time.time() < deadline:
                    try:
                        # A rollout/degraded unrelated volume is context, not a
                        # reason to reset or indefinitely veto the whole matrix.
                        # Node-local sensor, target readiness and capture checks
                        # still precede dispatch. No degraded interval is normal.
                        try:
                            cluster_gate(runtime)
                            health_context = {'global_health_gate': True}
                        except Exception as health_error:
                            health_context = {'global_health_gate': False, 'error': str(health_error)}
                        append_jsonl(root / 'HEALTH.jsonl', dict(health_context, checked_at_unix=time.time(), before_trial=index))
                        desired = runtime.kubectl_json('get', 'tracingpoliciesnamespaced.cilium.io',
                            'sentinel-pulse-exec-provenance', '-n', 'production', '-o', 'json')
                        rendered = json.loads(runtime.run(['kubectl', 'apply', '--dry-run=client', '-f',
                            str(Path(cfg['source']) / 'sentinel/k8s/tetragon-sentinel-pulse-exec-provenance.yaml'), '-o', 'json']).stdout)
                        if desired['spec'] != rendered['spec']:
                            raise ValueError('active kernel provenance policy differs')
                        if leg is None:
                            number += 1
                            prospective = start['run_id'] + f'-a{number:04d}'
                            append_jsonl(root / 'ACTIVE_LEG.jsonl', {'run_id': prospective, 'started_at_unix': time.time()})
                            leg, workers = start_leg(runtime, cfg, root, start, number)
                        for worker in workers.values():
                            state = json.loads(remote_python(runtime, cfg, worker['host'], 'attack_worker', ['probe', '--run-id', leg]).stdout)
                            if (state['detector']['ActiveState'] != 'active' or state['detector']['NRestarts'] != '0'
                                    or not state['capture']['valid'] or state['capture']['status'] != 'ready'):
                                raise RuntimeError('capture leg unavailable')
                        break
                    except Exception as exc:
                        append_jsonl(root / 'INFRASTRUCTURE.jsonl', {'checked_at_unix': time.time(), 'before_trial': index,
                                                                  'error': str(exc), 'not_normal': True})
                        if leg is not None:
                            close_leg(runtime, cfg, root, leg); leg, workers = None, None
                        elif 'prospective' in locals():
                            close_leg(runtime, cfg, root, prospective)
                        atomic_json(root / 'STATUS.json', dict(result_report(start['schedule'], rows(root / 'TRIALS.jsonl')),
                                                              status='waiting_for_infrastructure', last_error=str(exc)))
                        time.sleep(60)
                if time.time() >= deadline:
                    break
                try:
                    outcome = execute(runtime, root, trial, start['run_id'] + f':{index:04d}', workers,
                                      root / 'runtime_attack_blind', start['attack_seconds'], start['post_attack_wait_seconds'],
                                      start['model_manifest_sha256'], start['decision_policy_sha256'])
                except Exception as exc:
                    outcome = dict(trial, injection_id=start['run_id'] + f':{index:04d}',
                                   status='infrastructure_unknown', detected=False,
                                   error_type=type(exc).__name__, error=str(exc))
                outcome['leg_run_id'] = leg
                outcome['health_context_before_trial'] = health_context
                append_jsonl(root / 'TRIALS.jsonl', outcome)
                atomic_json(root / 'STATUS.json', dict(result_report(start['schedule'], rows(root / 'TRIALS.jsonl')),
                                                      status='running', last_trial=outcome, updated_at_unix=time.time()))
                if outcome['status'] != 'observed':
                    close_leg(runtime, cfg, root, leg); leg, workers = None, None
            final = result_report(start['schedule'], rows(root / 'TRIALS.jsonl'))
            final.update(status='completed' if len(rows(root / 'TRIALS.jsonl')) == len(start['schedule']) else 'completed_with_incomplete_matrix',
                         finished_at_unix=time.time(), normal_admission=start['normal_admission'])
            atomic_json(root / 'TERMINAL.json', final)
        finally:
            if leg is not None:
                close_leg(runtime, cfg, root, leg)
        if (root / 'TERMINAL.json').exists():
            atomic_json(root / 'EVIDENCE_SEAL.json', {
                str(p.relative_to(root)): sha256_file(p) for p in sorted(root.rglob('*'))
                if p.is_file() and p.name != 'EVIDENCE_SEAL.json'})


if __name__ == '__main__':
    main()
