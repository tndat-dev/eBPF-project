"""Install single-context timing using the original frozen scoring package."""
import argparse
import os
from pathlib import Path
import pwd
import grp
import subprocess
from .recovery_worker_probe import clean_source


def install(source):
    if os.geteuid()!=0:raise ValueError('root required for system service installation')
    clean_source(source)
    root=Path('/home/dat/pulse-extended-reference-benchmark-c1-20261012')
    env=Path('/etc/sentinel-pulse/extended-reference-benchmark.env')
    unit=Path('/etc/systemd/system/sentinel-pulse-extended-reference-benchmark.service')
    if root.exists() or env.exists() or unit.exists():raise ValueError('benchmark registered already; resume its unit')
    frozen=Path('/home/dat/eBPF-project-extended-reference-r2-20261008')
    clean_source(frozen)
    root.mkdir(mode=0o750);os.chown(root,pwd.getpwnam('dat').pw_uid,grp.getgrnam('dat').gr_gid)
    env.write_text('PYTHONPATH='+str(frozen)+'\nPULSE_REFERENCE_BENCH_SCRIPT='+str(source/'sentinel_pulse/benchmark_extended_reference_cli.py')+'\n');env.chmod(0o644)
    unit.write_bytes((source/'sentinel_pulse/systemd'/unit.name).read_bytes());unit.chmod(0o644)
    subprocess.run(['systemctl','daemon-reload'],check=True)
    subprocess.run(['systemctl','enable',unit.name],check=True)
    subprocess.run(['systemctl','start','--no-block',unit.name],check=True)


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source',type=Path,required=True)
    a=p.parse_args();install(a.source)


if __name__=='__main__':main()
