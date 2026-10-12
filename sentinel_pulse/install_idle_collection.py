"""Register separate idle-aware capture; no replacement of frozen v1 data/models."""
import argparse
import json
import os
from pathlib import Path
import platform
import subprocess
from .integrity import sha256_file
from .recovery_worker_probe import clean_source

OUTPUT=Path('/var/lib/sentinel-pulse-idle-c1-20261012')
UNIT='sentinel-pulse-idle-collection.service'


def install(source,build,proof,seconds=5400):
    if os.geteuid()!=0:raise ValueError('root required to attach BPF and install unit')
    for p in (source,build,proof):
        if not p.is_absolute() or not str(p).startswith('/home/dat/') or any(c.isspace() for c in str(p)):
            raise ValueError('explicit pinned /home/dat paths required')
    clean_source(source)
    receipt=json.loads((proof/'RESULTS.json').read_text());start=json.loads((proof/'START.json').read_text())
    if receipt.get('valid') is not True or start.get('kernel')!=platform.release():raise ValueError('proof kernel/validity differs')
    git=['git','-c','safe.directory='+str(source),'-C',str(source)]
    for name in ('pulse_counter_extended_loader','pulse_counter_extended.bpf.o'):
        if sha256_file(build/name)!=start['artifact_sha256'][name]:raise ValueError('compiled collector differs from proof')
    for name in ('pulse_counter.bpf.c','pulse_counter_loader.c','pulse_counter_projection.h','Makefile'):
        before=subprocess.check_output(git+['show',start['source_commit']+':sentinel_pulse/ebpf/'+name])
        if before!=(source/'sentinel_pulse/ebpf'/name).read_bytes():raise ValueError('unverified BPF source change')
    env=Path('/etc/sentinel-pulse/idle-collection.env');unit=Path('/etc/systemd/system')/UNIT
    if OUTPUT.exists() or env.exists() or unit.exists():raise ValueError('registered campaign exists; resume its unit')
    if not 60<=seconds<=86400:raise ValueError('invalid duration')
    OUTPUT.mkdir(mode=0o750)
    env.write_text('PYTHONPATH='+str(source)+'\nPULSE_IDLE_SOURCE='+str(source)+'\nPULSE_IDLE_BUILD='+str(build)+
        '\nPULSE_IDLE_PROOF='+str(proof)+'\nPULSE_IDLE_SECONDS='+str(seconds)+'\n');env.chmod(0o600)
    unit.write_bytes((source/'sentinel_pulse/systemd'/UNIT).read_bytes());unit.chmod(0o644)
    subprocess.run(['systemctl','daemon-reload'],check=True)
    subprocess.run(['systemctl','enable',UNIT],check=True)
    subprocess.run(['systemctl','start','--no-block',UNIT],check=True)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('source','build','proof'):p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--seconds',type=int,default=5400);a=p.parse_args()
    install(a.source,a.build,a.proof,a.seconds)


if __name__=='__main__':main()
