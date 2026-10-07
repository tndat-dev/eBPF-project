"""Owned, bounded attack capture leg. ML scoring code and policy are unchanged."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import time

from .integrity import sha256_file
from .inspect_recovery_tail import inspect
from .recovery_worker_probe import COLLECTOR, DETECTOR, environment, service, clean_source
from .run_500ms_blind_matrix import atomic_json
from .telemetry_recovery import load_profile

CAPTURES = Path('/var/lib/sentinel-pulse-500ms/runs')
REGISTRATION = Path('/var/lib/sentinel-pulse-attack-registration')


def owned(run_id):
    ce = environment(Path('/etc/sentinel-pulse/500ms-experiment.env'))
    de = environment(Path('/etc/sentinel-pulse-detector-candidate.env'))
    if ce.get('PULSE_500MS_RUN_ID') != run_id or de.get('PULSE_RUN_ID') != run_id:
        raise ValueError('another experiment owns the worker')
    return ce, de


def probe(run_id):
    ce, de = owned(run_id)
    root = CAPTURES / run_id
    marker = json.loads((REGISTRATION / run_id / 'START.json').read_text())
    profile = root / 'telemetry-recovery-profile.json'
    collector_start = json.loads((root / 'START.json').read_text())
    for field in ('loader', 'bpf_object'):
        actual = sha256_file(Path(ce['PULSE_500MS_' + field.upper()]))
        if actual != marker['worker_binding'][field + '_sha256']:
            raise ValueError('collector artifact drift: ' + field)
    if (sha256_file(Path(de['PULSE_MODEL_DIR']) / 'manifest.json') != marker['model_manifest_sha256']
            or sha256_file(Path(de['PULSE_DECISION_POLICY'])) != marker['decision_policy_sha256']
            or de.get('PULSE_FEATURES') != str(root / 'features.jsonl')
            or sha256_file(profile) != marker['recovery_profile_sha256']
            or collector_start.get('collector_variant') != 'projected'):
        raise ValueError('runtime binding drift')
    # Executed files, not merely the staging checkout, are checked on each probe.
    for name, value in marker['runtime_files'].items():
        if sha256_file(Path('/opt/sentinel-pulse') / name) != value:
            raise ValueError('installed runtime source drift: ' + name)
    return {'run_id': run_id, 'collector': service(COLLECTOR), 'detector': service(DETECTOR),
            'capture': inspect(root / 'features.jsonl', load_profile(profile)),
            'features': de['PULSE_FEATURES'], 'decisions': de['PULSE_DECISIONS'],
            'alerts': de['PULSE_ALERTS'], 'injections': de['PULSE_INJECTIONS'],
            'checked_at_unix': time.time(), 'terminal_present': (root / 'ATTACK_WORKER_TERMINAL.json').exists()}


def stop(run_id):
    # Shared services are never stopped unless the individual env proves ownership.
    root = CAPTURES / run_id
    de_path = Path('/etc/sentinel-pulse-detector-candidate.env')
    if de_path.exists():
        de = environment(de_path)
        if de.get('PULSE_RUN_ID') == run_id:
            subprocess.run(['systemctl', 'stop', DETECTOR], check=True, timeout=40)
            subprocess.run(['systemctl', 'disable', DETECTOR], check=True, timeout=20, capture_output=True)
            for name in ('decisions', 'alerts', 'injections'):
                src = Path(de['PULSE_' + name.upper()])
                if src.exists():
                    subprocess.run(['install', '-m', '0640', str(src), str(root / (name + '.jsonl'))], check=True)
    ce_path = Path('/etc/sentinel-pulse/500ms-experiment.env')
    if ce_path.exists() and environment(ce_path).get('PULSE_500MS_RUN_ID') == run_id:
        subprocess.run(['systemctl', 'stop', COLLECTOR], check=True, timeout=40)


def run(source, run_id):
    marker_path = REGISTRATION / run_id / 'START.json'
    marker = json.loads(marker_path.read_text())
    commit, files = clean_source(source)
    if marker['source_commit'] != commit or marker['runtime_files'] != files:
        raise ValueError('worker launch source drift')
    if marker['run_id'] != run_id or marker['schema'] != 'sentinel-pulse-attack-worker-start-v1':
        raise ValueError('invalid attack registration')
    root = CAPTURES / run_id
    if root.exists():
        raise ValueError('refusing to replace an existing worker leg')
    env = dict(os.environ, PYTHONPATH=str(source), SOURCE_ROOT=str(source), RUN_ID=run_id,
               DURATION_SECONDS=str(marker['duration_seconds']), COLLECTOR_VARIANT='projected',
               PROJECTED_CANARY_RUN_DIR=marker['safety'], MODEL_MANIFEST_SOURCE=marker['model'] + '/manifest.json',
               MODEL_SOURCE=marker['model'], DECISION_POLICY_SOURCE=marker['policy'],
               TELEMETRY_RECOVERY_PROFILE_SOURCE=str(source / 'sentinel_pulse/protocol/telemetry-recovery-v1.json'),
               TELEMETRY_NOMINAL_INTERVAL_SECONDS='0.5', TELEMETRY_MINIMUM_AVAILABILITY='0.999',
               TELEMETRY_MAXIMUM_SINGLE_GAP_SECONDS='30', PULSE_OBSERVATIONAL_SCOPE='true',
               DETECTOR_LIVE_FRESHNESS='true', ENABLE_INJECTION_TRACKING='true',
               FEATURE_SOURCE=str(root / 'features.jsonl'), DEPLOYMENT_ID=run_id)
    if sha256_file(Path(env['TELEMETRY_RECOVERY_PROFILE_SOURCE'])) != marker['recovery_profile_sha256']:
        raise ValueError('recovery profile drift')
    exit_code, error = 0, None
    try:
        for installer in ('install_500ms_experiment.sh', 'install_detector_candidate.sh'):
            subprocess.run(['/bin/bash', str(source / 'sentinel_pulse' / installer)], env=env,
                           check=True, timeout=600)
        atomic_json(root / 'ATTACK_RUNTIME_READY.json', {'ready_at_unix': time.time(), 'probe': probe(run_id)})
        deadline = time.monotonic() + marker['duration_seconds']
        while time.monotonic() < deadline and service(COLLECTOR)['ActiveState'] == 'active':
            state = probe(run_id)
            if (state['detector']['ActiveState'] != 'active' or state['detector']['NRestarts'] != '0'
                    or state['capture']['status'] == 'fatal'):
                raise ValueError('worker telemetry/runtime unhealthy: ' + json.dumps(state))
            time.sleep(10)
    except BaseException as exc:
        exit_code, error = 1, str(exc)
        raise
    finally:
        stop(run_id)
        if root.exists():
            atomic_json(root / 'ATTACK_WORKER_TERMINAL.json', {
                'schema': 'sentinel-pulse-attack-worker-terminal-v1', 'run_id': run_id,
                'registration_sha256': sha256_file(marker_path), 'finished_at_unix': time.time(),
                'exit_code': exit_code, 'error': error, 'automatic_promotion': False})
            hashes = {p.name: sha256_file(p) for p in sorted(root.iterdir()) if p.is_file()
                      and p.name != 'ATTACK_RAW_SEAL.json'}
            atomic_json(root / 'ATTACK_RAW_SEAL.json', hashes)
            for path in root.iterdir():
                if path.is_file():
                    path.chmod(0o444)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['run', 'probe', 'stop'])
    parser.add_argument('--run-id', required=True)
    parser.add_argument('--source', type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise ValueError('root worker adapter required')
    if not args.run_id or any(c not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-' for c in args.run_id):
        raise ValueError('unsafe run id')
    if args.command == 'run':
        signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(InterruptedError('worker interrupted')))
        run(args.source, args.run_id)
    elif args.command == 'probe':
        print(json.dumps(probe(args.run_id), sort_keys=True))
    else:
        stop(args.run_id)


if __name__ == '__main__':
    main()
