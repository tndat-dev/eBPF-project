"""Install detached read-only Pulse analysis alongside the syscall experiment."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import tarfile

from .syscall_capture_campaign import Remote, WORKERS


SOURCE = '/home/dat/pulse-shadow-summary-20261014/source'
UNIT = 'pulse-shadow-soak-summary@normal-a1-20261013.service'


def install(archive, credential):
    with tarfile.open(archive) as bundle:
        commit = bundle.pax_headers.get('comment', '')
    if len(commit) != 40 or any(x not in '0123456789abcdef' for x in commit):
        raise ValueError('identified Git archive required')
    remote = Remote(credential)
    for host in WORKERS:
        preflight = '''from pathlib import Path
import json,subprocess
r=Path('/var/lib/sentinel-pulse-normal-normal-a1-20261013');t=json.loads((r/'capture/TERMINAL.json').read_text())
assert t['state']=='completed_observation' and t['boundary_observation_seconds']>=86400
assert (r/'shadow/decisions.jsonl').is_file()
p=subprocess.run(['systemctl','is-active',%r],text=True,capture_output=True)
assert p.stdout.strip() not in ['active','activating'], 'summary already running; do not replace its source'
print(json.dumps(dict(feature_rows=t['feature_rows'],shadow_bytes=(r/'shadow/decisions.jsonl').stat().st_size)))
''' % UNIT
        print(host, remote.command(host, ['python3', '-c', preflight]).strip())
        target = '/home/dat/pulse-shadow-summary-20261014.tar.gz'
        subprocess.run(['sshpass', '-f', str(credential), 'scp', '-q', '-o', 'StrictHostKeyChecking=yes',
                        str(archive), f'dat@{host}:{target}'], check=True, capture_output=True, timeout=90)
        remote.command(host, ['mkdir', '-p', SOURCE, '/var/lib/pulse-shadow-review'])
        remote.command(host, ['tar', '-xzf', target, '-C', SOURCE])
        remote.command(host, ['install', '-m', '0644', SOURCE+'/sentinel_pulse/systemd/pulse-shadow-soak-summary@.service',
                              '/etc/systemd/system/pulse-shadow-soak-summary@.service'])
        remote.command(host, ['systemctl', 'daemon-reload'])
        remote.command(host, ['systemctl', 'enable', '--no-block', '--now', UNIT])
        print(host, remote.command(host, ['systemctl', 'show', UNIT, '-p', 'ActiveState', '-p', 'SubState']).strip())
    print(json.dumps(dict(installed=True, source_commit=commit, unit=UNIT, workers=list(WORKERS),
                         syscall_campaign_modified=False, frozen_candidate_modified=False)))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('archive', 'credential'):
        p.add_argument('--'+name, required=True, type=Path)
    a = p.parse_args()
    install(a.archive, a.credential)


if __name__ == '__main__':
    main()
