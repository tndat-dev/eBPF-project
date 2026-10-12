"""Queue worker replay/master reference fit after idle-aware capture completes."""
import argparse
import grp
import os
from pathlib import Path
import pwd
import subprocess
from .recovery_worker_probe import clean_source


def install(source,master=False,credential=None):
    if os.geteuid()!=0:raise ValueError('root required for system unit installation')
    if not str(source).startswith('/home/dat/') or any(c.isspace() for c in str(source)):raise ValueError('pinned source required')
    clean_source(source)
    if master:
        if credential is None or credential.stat().st_mode&0o077:raise ValueError('private existing credential required')
        unit_name='sentinel-pulse-idle-reference.service';root=Path('/home/dat/pulse-idle-reference-c1-20261012')
        env=Path('/etc/sentinel-pulse/idle-reference.env')
        template=(source/'sentinel_pulse/systemd/sentinel-pulse-extended-reference.service').read_text()
        template=template.replace('extended-reference.env','idle-reference.env').replace(
            'pulse-extended-reference-c1-20261008','pulse-idle-reference-c1-20261012').replace(
            '--known-hosts /home/dat/.ssh/known_hosts','--known-hosts /home/dat/.ssh/known_hosts --idle-aware')
        environment='PULSE_REFERENCE_SOURCE='+str(source)+'\nPULSE_REFERENCE_CREDENTIAL='+str(credential)+'\n'
    else:
        unit_name='sentinel-pulse-idle-audit.service';root=Path('/var/lib/sentinel-pulse-idle-audit-c1-20261012')
        env=Path('/etc/sentinel-pulse/idle-audit.env')
        template=(source/'sentinel_pulse/systemd/sentinel-pulse-extended-audit.service').read_text()
        template=template.replace('sentinel-pulse-extended-collection.service','sentinel-pulse-idle-collection.service').replace(
            'extended-audit.env','idle-audit.env').replace('sentinel-pulse-extended-c1-20261008','sentinel-pulse-idle-c1-20261012').replace(
            'sentinel-pulse-extended-audit-c1-20261008','sentinel-pulse-idle-audit-c1-20261012')
        environment='PYTHONPATH='+str(source)+'\nPULSE_AUDIT_SOURCE='+str(source)+'\n'
    unit=Path('/etc/systemd/system')/unit_name
    if root.exists() or env.exists() or unit.exists():raise ValueError('registered follow-up exists; resume its service')
    root.mkdir(mode=0o750);os.chown(root,pwd.getpwnam('dat').pw_uid if master else 0,grp.getgrnam('dat').gr_gid)
    env.write_text(environment);env.chmod(0o644 if master else 0o600)
    unit.write_text(template);unit.chmod(0o644)
    subprocess.run(['systemctl','daemon-reload'],check=True)
    subprocess.run(['systemctl','enable',unit_name],check=True)
    subprocess.run(['systemctl','start','--no-block',unit_name],check=True)


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source',type=Path,required=True)
    p.add_argument('--master',action='store_true');p.add_argument('--credential',type=Path)
    a=p.parse_args();install(a.source,a.master,a.credential)


if __name__=='__main__':main()
