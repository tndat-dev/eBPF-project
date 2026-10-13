"""Install the durable separate experiment without attaching collection probes."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import subprocess
import tarfile

from .syscall_capture_campaign import Remote, SOURCE, WORKERS


def install(source_commit, archive, credential):
    if not re.fullmatch('[0-9a-f]{40}', source_commit):
        raise ValueError('full source Git commit required')
    with tarfile.open(archive, 'r:gz') as bundle:
        if bundle.pax_headers.get('comment') != source_commit:
            raise ValueError('archive Git commit differs from requested source commit')
    remote = Remote(credential)
    for name in ('syscall-capture-c3', 'syscall-capture-c3-r2'):
        status = Path('/mnt/sentinel-pulse-archive') / name / 'STATUS.json'
        if status.exists() and json.loads(status.read_text()).get('active'):
            raise ValueError('cannot replace source during an active capture attempt')
    # Only this waiting coordinator is stopped; the protected soak is separate.
    stopped = subprocess.run(['sudo', '-S', '-p', '', 'systemctl', 'stop', 'pulse-syscall-capture-c3.service'],
                             input=remote.password + '\n', text=True, capture_output=True, timeout=30)
    if stopped.returncode not in (0, 5):
        raise RuntimeError('could not stop the waiting coordinator for installation')
    for host in WORKERS:
        transfer = ['sshpass', '-f', str(credential), 'scp', '-q',
                    '-o', 'StrictHostKeyChecking=yes',
                    '-o', 'UserKnownHostsFile=/home/dat/.ssh/known_hosts',
                    str(archive), f'dat@{host}:/home/dat/pulse-syscall-capture-c3.tar.gz']
        subprocess.run(transfer, check=True, capture_output=True, timeout=90)
        remote.command(host, ['mkdir', '-p', SOURCE])
        remote.command(host, ['tar', '-xzf', '/home/dat/pulse-syscall-capture-c3.tar.gz', '-C', SOURCE])
        remote.command(host, ['make', '-C', SOURCE + '/sentinel_pulse/ebpf',
                              'syscall-histogram', 'HISTOGRAM_BUILD_DIR=' + SOURCE + '/build'], timeout=240)
        remote.command(host, ['make', '-C', SOURCE + '/sentinel_pulse/ebpf', 'projected'], timeout=240)
        check = """import json,os,hashlib,subprocess
from pathlib import Path
import numpy
assert os.stat('/home/dat').st_uid == 1000, 'unexpected artifact owner UID'
assert Path('/run/sentinel-pulse/cgroups.json').is_file()
p=Path(%r)
print(json.dumps(dict(node=subprocess.check_output(['hostname'],text=True).strip(),
 numpy=numpy.__version__, artifacts={str(f.relative_to(p)):hashlib.sha256(f.read_bytes()).hexdigest()
 for f in [p/'build/syscall_histogram_loader',p/'build/syscall_histogram.bpf.o',
 p/'sentinel_pulse/ebpf/pulse_counter_projected_loader',p/'sentinel_pulse/ebpf/pulse_counter_projected.bpf.o']})))
""" % SOURCE
        print(remote.command(host, ['/opt/sentinel-pulse/runtime-venv/bin/python', '-c', check]).strip())
    source = Path(SOURCE)
    env = source.parent / 'syscall-capture-c3.env'
    env.write_text('PULSE_SOURCE_COMMIT=' + source_commit + '\n')
    commands = [
        ['install', '-m', '0644', str(source / 'sentinel_pulse/systemd/pulse-syscall-capture-c3.service'),
         '/etc/systemd/system/pulse-syscall-capture-c3.service'],
        ['install', '-m', '0644', str(env), '/etc/sentinel-pulse/syscall-capture-c3.env'],
        ['systemctl', 'daemon-reload'],
        ['systemctl', 'enable', '--now', 'pulse-syscall-capture-c3.service'],
    ]
    for command in commands:
        result = subprocess.run(['sudo', '-S', '-p', '', *command], input=remote.password + '\n',
                                text=True, capture_output=True, timeout=30)
        if result.returncode:
            raise RuntimeError('local installation failed: ' + command[0])
    print(json.dumps(dict(installed=True, source_commit=source_commit,
                          service='pulse-syscall-capture-c3.service', probe_attached_by_installer=False)))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source-commit', required=True)
    p.add_argument('--archive', type=Path, required=True)
    p.add_argument('--credential', type=Path, required=True)
    a = p.parse_args()
    install(a.source_commit, a.archive, a.credential)


if __name__ == '__main__':
    main()
