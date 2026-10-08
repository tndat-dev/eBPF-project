"""Install a queued reference-only experiment on the master; no worker changes."""
import argparse
import grp
import os
from pathlib import Path
import pwd
import subprocess
from .recovery_worker_probe import clean_source


def install(source,credential):
    if os.geteuid()!=0:raise ValueError('systemd installer needs root')
    for path in (source,credential):
        if not str(path).startswith('/home/dat/') or any(c.isspace() for c in str(path)):
            raise ValueError('explicit /home/dat paths required')
    clean_source(source)
    if credential.stat().st_mode&0o077 or credential.stat().st_uid!=pwd.getpwnam('dat').pw_uid:
        raise ValueError('credential must be private and owned by dat')
    if not Path('/home/dat/.ssh/known_hosts').is_file():raise ValueError('strict SSH known-host file required')
    root=Path('/home/dat/pulse-extended-reference-r2-c1-20261008')
    unit=Path('/etc/systemd/system/sentinel-pulse-extended-reference-r2.service')
    env=Path('/etc/sentinel-pulse/extended-reference-r2.env')
    if root.exists() or unit.exists() or env.exists():raise ValueError('existing experiment; resume its unit')
    root.mkdir(mode=0o750);os.chown(root,pwd.getpwnam('dat').pw_uid,grp.getgrnam('dat').gr_gid)
    env.write_text('PULSE_REFERENCE_SOURCE='+str(source)+'\nPULSE_REFERENCE_CREDENTIAL='+str(credential)+'\n');env.chmod(0o644)
    template=(source/'sentinel_pulse/systemd/sentinel-pulse-extended-reference.service').read_text()
    template=template.replace('extended-reference.env','extended-reference-r2.env').replace(
        'pulse-extended-reference-c1','pulse-extended-reference-r2-c1')
    unit.write_text(template);unit.chmod(0o644)
    subprocess.run(['systemctl','daemon-reload'],check=True)
    subprocess.run(['systemctl','enable',unit.name],check=True)
    subprocess.run(['systemctl','start','--no-block',unit.name],check=True)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('source','credential'):p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args();install(a.source,a.credential)


if __name__=='__main__':main()
