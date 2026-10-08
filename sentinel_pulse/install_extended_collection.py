"""Install a pinned boot-persistent observer; never replace an active campaign."""
import argparse
import json
import os
from pathlib import Path
import platform
import subprocess

from .integrity import sha256_file
from .recovery_worker_probe import clean_source

UNIT='sentinel-pulse-extended-collection.service'
OUTPUT=Path('/var/lib/sentinel-pulse-extended-c1-20261008')


def install(source,build,proof,seconds):
    if os.geteuid()!=0:raise ValueError('installer needs root for systemd and eBPF')
    if not 60<=seconds<=86400:raise ValueError('invalid bounded duration')
    for path in (source,build,proof):
        if not path.is_absolute() or not str(path).startswith('/home/dat/') or any(c.isspace() for c in str(path)):
            raise ValueError('expected explicit absolute /home/dat path without spaces')
    clean_source(source)
    receipt=json.loads((proof/'RESULTS.json').read_text());start=json.loads((proof/'START.json').read_text())
    if receipt.get('valid') is not True or start.get('kernel')!=platform.release():
        raise ValueError('integrated proof is not valid on this kernel')
    for name in ('pulse_counter_extended_loader','pulse_counter_extended.bpf.o'):
        if start['artifact_sha256'].get(name)!=sha256_file(build/name):raise ValueError('proof artifact drift')
    # A root service may trust only this exact clean checkout. No wildcard global Git exception.
    git=['git','-c','safe.directory='+str(source),'-C',str(source)]
    for name in ('pulse_counter.bpf.c','pulse_counter_loader.c','pulse_counter_projection.h','Makefile'):
        frozen=subprocess.check_output(git+['show',start['source_commit']+':sentinel_pulse/ebpf/'+name])
        if frozen!=(source/'sentinel_pulse/ebpf'/name).read_bytes():raise ValueError('unverified collector source change')
    existing=subprocess.run(['systemctl','show',UNIT,'-p','ActiveState','--value'],capture_output=True,text=True,check=True).stdout.strip()
    if existing in ('active','activating','deactivating') or (OUTPUT/'START.json').exists():
        raise ValueError('campaign already exists; resume via systemctl, not reinstall')
    OUTPUT.mkdir(parents=True,exist_ok=True)
    env=Path('/etc/sentinel-pulse/extended-collection.env');env.parent.mkdir(parents=True,exist_ok=True)
    if env.exists():raise ValueError('environment file already exists; inspect before replacing')
    env.write_text('\n'.join(['PYTHONPATH='+str(source),'PULSE_EXTENDED_SOURCE='+str(source),
        'PULSE_EXTENDED_BUILD='+str(build),'PULSE_EXTENDED_ROOT='+str(OUTPUT),
        'PULSE_EXTENDED_PROOF='+str(proof),'PULSE_EXTENDED_SECONDS='+str(seconds)])+'\n');env.chmod(0o600)
    target=Path('/etc/systemd/system')/UNIT
    if target.exists():raise ValueError('system unit already exists')
    target.write_bytes((source/'sentinel_pulse/systemd'/UNIT).read_bytes());target.chmod(0o644)
    subprocess.run(['systemctl','daemon-reload'],check=True)
    subprocess.run(['systemctl','enable',UNIT],check=True)
    subprocess.run(['systemctl','start','--no-block',UNIT],check=True)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('source','build','proof'):p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--seconds',type=int,default=7200);a=p.parse_args();install(a.source,a.build,a.proof,a.seconds)


if __name__=='__main__':main()
