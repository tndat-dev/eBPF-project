"""Install a boot-persistent capture + frozen candidate shadow observation pair."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import time

from .candidate_policy import CandidatePreviewPolicy
from .extended_collection import IDLE_CONTRACT
from .idle_candidate import FEATURE_CONTRACT, IdleCandidateScorer
from .integrity import sha256_file
from .recovery_worker_probe import clean_source


SYSTEMD = Path('/etc/systemd/system')
CONFIG = Path('/etc/sentinel-pulse')
VAR = Path('/var/lib')
PYTHON = Path('/opt/sentinel-pulse/runtime-venv/bin/python')
DEFAULT_BYTES = 70 * 1024**3
DEFAULT_MIN_FREE = 12 * 1024**3


def install(*, run_id: str, source: Path, build: Path, proof: Path,
            candidate_dir: Path, manifest_sha256: str, policy: Path,
            seconds: int = 86400, maximum_bytes: int = DEFAULT_BYTES,
            minimum_free_bytes: int = DEFAULT_MIN_FREE) -> Path:
    if os.geteuid() != 0:
        raise ValueError('installer must run as root')
    if not re.fullmatch(r'[a-z0-9][a-z0-9-]{2,63}', run_id):
        raise ValueError('run id must be a short lowercase systemd-safe slug')
    if not 3600 <= seconds <= 86400:
        raise ValueError('observation duration must be 1h..24h')
    if maximum_bytes < 10 * 1024**3 or minimum_free_bytes < 4 * 1024**3:
        raise ValueError('storage budget/reserve is below the registered safe minimum')
    for path in (source, build, proof, candidate_dir, policy):
        if not path.is_absolute() or any(c.isspace() for c in str(path)):
            raise ValueError('all pinned paths must be absolute and contain no whitespace')
    if not PYTHON.is_file():
        raise ValueError('worker runtime venv is missing')
    if not Path('/run/sentinel-pulse/allowed-cgroups').is_file():
        raise ValueError('resolver allow-list is not available')
    if not Path('/run/sentinel-pulse/cgroups.json').is_file():
        raise ValueError('resolver cgroup metadata is not available')

    source_commit, _ = clean_source(source)
    start = json.loads((proof / 'START.json').read_text())
    result = json.loads((proof / 'RESULTS.json').read_text())
    if result.get('valid') is not True or start.get('kernel') != platform.release():
        raise ValueError('BPF proof is invalid or bound to another kernel')
    for name in ('pulse_counter_extended_loader', 'pulse_counter_extended.bpf.o'):
        if sha256_file(build / name) != start.get('artifact_sha256', {}).get(name):
            raise ValueError('built BPF artifact differs from the registered proof')

    scorer = IdleCandidateScorer(candidate_dir, manifest_sha256)
    loaded_policy = CandidatePreviewPolicy.load(policy, scorer)
    if hashlib.sha256(policy.read_bytes()).hexdigest() != loaded_policy.sha256:
        raise ValueError('candidate policy changed while it was validated')
    if scorer.manifest.get('feature_contract') != FEATURE_CONTRACT:
        raise ValueError('candidate and observation telemetry contracts differ')

    run_root = VAR / f'sentinel-pulse-normal-{run_id}'
    capture_root, shadow_root = run_root / 'capture', run_root / 'shadow'
    env = CONFIG / f'normal-soak-{run_id}.env'
    capture_unit = SYSTEMD / f'sentinel-pulse-observation-capture@{run_id}.service'
    shadow_unit = SYSTEMD / f'sentinel-pulse-observation-shadow@{run_id}.service'
    all_paths = (run_root, env, capture_unit, shadow_unit)
    if any(path.exists() for path in all_paths):
        raise ValueError('run id already has local state; refusing overwrite or implicit resume')

    free = shutil.disk_usage(VAR).free
    if free < maximum_bytes + minimum_free_bytes:
        raise ValueError(f'insufficient free space for preregistered budget: {free} bytes')

    CONFIG.mkdir(mode=0o750, parents=True, exist_ok=True)
    run_root.mkdir(mode=0o750)
    capture_root.mkdir(mode=0o750)
    shadow_root.mkdir(mode=0o750)
    values = {
        'PYTHONPATH': str(source), 'PULSE_SOURCE': str(source),
        'PULSE_BUILD': str(build), 'PULSE_PROOF': str(proof),
        'PULSE_CAPTURE_ROOT': str(capture_root), 'PULSE_SHADOW_ROOT': str(shadow_root),
        'PULSE_RUN_ROOT': str(run_root), 'PULSE_CANDIDATE_DIR': str(candidate_dir),
        'PULSE_MANIFEST_SHA256': manifest_sha256, 'PULSE_POLICY': str(policy),
        'PULSE_RUN_ID': f'{run_id}-{platform.node()}', 'PULSE_SECONDS': str(seconds),
        'PULSE_MAXIMUM_BYTES': str(maximum_bytes),
        'PULSE_MINIMUM_FREE_BYTES': str(minimum_free_bytes),
    }
    env.write_text(''.join(f'{key}={value}\n' for key, value in values.items()))
    env.chmod(0o600)
    template_root = source / 'sentinel_pulse/systemd'
    for template, destination in (
        ('sentinel-pulse-observation-capture.service.in', capture_unit),
        ('sentinel-pulse-observation-shadow.service.in', shadow_unit),
    ):
        text = (template_root / template).read_text().replace('%i', run_id)
        destination.write_text(text)
        destination.chmod(0o644)

    registration = {
        'schema': 'sentinel-pulse-normal-observation-registration-v1',
        'run_id': run_id, 'node': platform.node(), 'kernel': platform.release(),
        'source_commit': source_commit, 'source_path': str(source),
        'candidate_manifest_sha256': scorer.manifest_sha256,
        'policy_sha256': loaded_policy.sha256, 'telemetry_contract': IDLE_CONTRACT,
        'requested_boundary_observation_seconds': seconds,
        'maximum_bytes': maximum_bytes, 'minimum_free_bytes': minimum_free_bytes,
        'created_at_unix': time.time(), 'purpose': 'independent normal observation; no fitting/tuning/promotion',
        'alerts_are_retained_for_post-run_adjudication': True,
        'infrastructure_gaps_are_not_labeled_normal': True,
    }
    (run_root / 'REGISTRATION.json').write_text(json.dumps(registration, indent=2) + '\n')
    (run_root / 'REGISTRATION.json').chmod(0o440)
    subprocess.run(['systemctl', 'daemon-reload'], check=True)
    subprocess.run(['systemctl', 'enable', capture_unit.name, shadow_unit.name], check=True)
    # Start the collector first; the shadow follower waits for its first segment.
    subprocess.run(['systemctl', 'start', '--no-block', capture_unit.name], check=True)
    subprocess.run(['systemctl', 'start', '--no-block', shadow_unit.name], check=True)
    return run_root


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-id', required=True)
    for name in ('source', 'build', 'proof', 'candidate-dir', 'policy'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--manifest-sha256', required=True)
    parser.add_argument('--seconds', type=int, default=86400)
    parser.add_argument('--maximum-bytes', type=int, default=DEFAULT_BYTES)
    parser.add_argument('--minimum-free-bytes', type=int, default=DEFAULT_MIN_FREE)
    args = parser.parse_args(argv)
    try:
        root = install(run_id=args.run_id, source=args.source, build=args.build,
                       proof=args.proof, candidate_dir=args.candidate_dir,
                       manifest_sha256=args.manifest_sha256, policy=args.policy,
                       seconds=args.seconds, maximum_bytes=args.maximum_bytes,
                       minimum_free_bytes=args.minimum_free_bytes)
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        parser.error(f'observation install refused: {type(exc).__name__}: {exc}')
    print(root)


if __name__ == '__main__':
    main()
