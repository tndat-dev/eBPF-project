"""Install a separate read-only audit of completed telemetry on a worker."""
import argparse
import grp
import json
import os
from pathlib import Path
import subprocess
from .recovery_worker_probe import clean_source


def install(source,revision='r2'):
    if revision!='r2':raise ValueError('only the separately registered r2 audit is supported')
    if os.geteuid()!=0:raise ValueError('systemd installer needs root')
    if not str(source).startswith('/home/dat/') or any(c.isspace() for c in str(source)):
        raise ValueError('explicit pinned checkout required')
    clean_source(source)
    capture=Path('/var/lib/sentinel-pulse-extended-c1-20261008')
    if json.loads((capture/'TERMINAL.json').read_text()).get('state')!='completed_observation':
        raise ValueError('capture not complete; do not replace or restart it')
    root=Path('/var/lib/sentinel-pulse-extended-audit-r2-c1-20261008')
    env=Path('/etc/sentinel-pulse/extended-audit-r2.env')
    unit=Path('/etc/systemd/system/sentinel-pulse-extended-audit-r2.service')
    if root.exists() or env.exists() or unit.exists():raise ValueError('audit exists; resume existing unit')
    root.mkdir(mode=0o750);os.chown(root,0,grp.getgrnam('dat').gr_gid)
    env.write_text('PYTHONPATH='+str(source)+'\nPULSE_AUDIT_SOURCE='+str(source)+'\n');env.chmod(0o600)
    template=(source/'sentinel_pulse/systemd/sentinel-pulse-extended-audit.service').read_text()
    template=template.replace('extended-audit.env','extended-audit-r2.env').replace(
        'sentinel-pulse-extended-audit-c1','sentinel-pulse-extended-audit-r2-c1')
    unit.write_text(template);unit.chmod(0o644)
    subprocess.run(['systemctl','daemon-reload'],check=True)
    subprocess.run(['systemctl','enable',unit.name],check=True)
    subprocess.run(['systemctl','start','--no-block',unit.name],check=True)


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source',type=Path,required=True)
    a=p.parse_args();install(a.source)


if __name__=='__main__':main()
