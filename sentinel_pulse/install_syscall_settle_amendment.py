"""Install a bounded operational amendment without changing capture/model code.

Keeps the original START, sealed attempts and four completed phases. Only the
coordinator is stopped; existing workers finish with their original code.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import shlex
import subprocess
import tarfile
import time

from .syscall_capture_campaign import Remote, WORKERS, digest, verify_amendment


OLD = Path('/home/dat/pulse-syscall-capture-c3/source')
NEW = Path('/home/dat/pulse-syscall-c3-settle-20261014/source')
ROOT = Path('/mnt/sentinel-pulse-archive/syscall-capture-c3-r2')
CRITICAL = ['syscall_histogram_pilot.py', 'syscall_histogram_analysis.py', 'capture.py',
            'features.py', 'encoding.py', 'model.py', 'telemetry_recovery.py']
BINARIES = ['build/syscall_histogram_loader', 'build/syscall_histogram.bpf.o',
            'sentinel_pulse/ebpf/pulse_counter_projected_loader',
            'sentinel_pulse/ebpf/pulse_counter_projected.bpf.o']


def install(archive, credential):
    with tarfile.open(archive) as bundle:
        commit = bundle.pax_headers.get('comment', '')
    if len(commit) != 40 or any(x not in '0123456789abcdef' for x in commit):
        raise ValueError('identified Git archive required')
    remote = Remote(credential)
    def sudo(command):
        result = subprocess.run(['sudo', '-k', '-S', '-p', '', *command], input=remote.password+'\n',
                                text=True, capture_output=True, timeout=60)
        if result.returncode:
            raise RuntimeError('installation step failed: ' + command[0])
    if Path(__file__).resolve().parent.parent != NEW:
        raise ValueError('installer must execute from separate new source directory')
    hashes = {}
    for name in CRITICAL:
        old, new = OLD/'sentinel_pulse'/name, NEW/'sentinel_pulse'/name
        if digest(old) != digest(new):
            raise ValueError('capture/model/validation changed: ' + name)
        hashes[name] = digest(new)
    if digest(OLD/'ml-service/set_aims_traffic_regime.sh') != digest(NEW/'ml-service/set_aims_traffic_regime.sh'):
        raise ValueError('traffic protocol changed')
    original = json.loads((ROOT/'START.json').read_text())['contract']
    effective = dict(original, source_commit=commit,
                     controller_sha256=digest(NEW/'sentinel_pulse/syscall_capture_campaign.py'),
                     target_settle_seconds=360)
    amendment = dict(schema='pulse-syscall-operational-amendment-v1', registered_at_unix=time.time(),
        original_start_sha256=digest(ROOT/'START.json'), original_contract=original, effective_contract=effective,
        reason='HPA scale-down changed waypoint cgroups during recovery; wait for stable targets before capture',
        unchanged_runtime_sha256=hashes, new_source=str(NEW), original_source=str(OLD),
        model_or_threshold_changed=False, previous_rejected_attempts_preserved=True,
        previous_completed_phases_preserved=True, hpa_disabled=False)
    marker = ROOT/'AMENDMENT-target-settle-20261014.json'
    if marker.exists():
        existing = json.loads(marker.read_text())
        amendment['registered_at_unix'] = existing['registered_at_unix']
        if existing != amendment:
            raise ValueError('existing amendment differs')
    else:
        with marker.open('x') as stream:
            json.dump(amendment, stream, indent=2); stream.write('\n')
    marker_hash = digest(marker)
    verify_amendment(original, effective, marker, marker_hash, digest(ROOT/'START.json'))
    sudo(['systemctl', 'stop', 'pulse-syscall-capture-c3.service'])
    for host in WORKERS:
        destination = '/home/dat/pulse-syscall-c3-settle-20261014.tar.gz'
        subprocess.run(['sshpass', '-f', str(credential), 'scp', '-q', '-o', 'StrictHostKeyChecking=yes',
                        str(archive), f'dat@{host}:{destination}'], check=True, capture_output=True, timeout=90)
        remote.command(host, ['mkdir', '-p', str(NEW)])
        remote.command(host, ['tar', '-xzf', destination, '-C', str(NEW)])
        code = '''import hashlib,json,shutil
from pathlib import Path
old,new=Path(%r),Path(%r)
for name in %r:
 a,b=old/'sentinel_pulse'/name,new/'sentinel_pulse'/name
 assert hashlib.sha256(a.read_bytes()).hexdigest()==hashlib.sha256(b.read_bytes()).hexdigest(), name
out={}
for name in %r:
 a,b=old/name,new/name;b.parent.mkdir(parents=True,exist_ok=True)
 shutil.copy2(a,b)
 assert hashlib.sha256(a.read_bytes()).digest()==hashlib.sha256(b.read_bytes()).digest()
 out[name]=hashlib.sha256(b.read_bytes()).hexdigest()
print(json.dumps(out))
''' % (str(OLD), str(NEW), CRITICAL, BINARIES)
        print(host, remote.command(host, ['python3', '-c', code]).strip())
    argv = ['/home/dat/sentinel-pulse-syscall-feature-c1/venv/bin/python', '-u', '-m',
            'sentinel_pulse.syscall_capture_campaign', '--root', str(ROOT), '--source', str(NEW),
            '--credential', str(credential), '--source-commit', commit, '--target-settle-seconds', '360',
            '--operational-amendment', str(marker), '--amendment-sha256', marker_hash]
    configuration = NEW.parent/'30-target-settle-c3.conf'
    configuration.write_text('[Service]\nWorkingDirectory='+str(NEW)+'\nExecStart=\nExecStart='+shlex.join(argv)+'\n')
    dropin = '/etc/systemd/system/pulse-syscall-capture-c3.service.d'
    sudo(['mkdir', '-p', dropin])
    sudo(['install', '-m', '0644', str(configuration), dropin+'/30-target-settle-c3.conf'])
    sudo(['systemctl', 'daemon-reload'])
    sudo(['systemctl', 'enable', '--now', 'pulse-syscall-capture-c3.service'])
    print(json.dumps(dict(installed=True, source_commit=commit, amendment_sha256=marker_hash)))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--archive', type=Path, required=True)
    p.add_argument('--credential', type=Path, required=True)
    a = p.parse_args()
    install(a.archive, a.credential)


if __name__ == '__main__':
    main()
