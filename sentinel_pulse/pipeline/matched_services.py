"""Install a new named matched-capture/campaign service without overwrites."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import socket

from ..integrity import sha256_file


def install(config, role, credential=None):
    if os.geteuid()!=0:raise ValueError('systemd installation requires root')
    cfg=json.loads(config.read_text());run_id=cfg['run_id']
    if not re.fullmatch('[a-z0-9-]{3,60}',run_id):raise ValueError('unsafe run id')
    source=Path(cfg['source'])
    if not source.is_absolute() or any(c.isspace() for c in str(source)):raise ValueError('unsafe source path')
    module={'worker':'pipeline.matched_worker','study':'syscall_study.matched_study',
            'campaign':'attack.preview_campaign','traffic':'pipeline.matched_traffic'}[role]
    name=f'pulse-matched-{role}-{run_id}.service'
    path=Path('/etc/systemd/system')/name
    if path.exists():raise ValueError('service exists; inspect and resume explicitly')
    if role=='worker':
        worker=next(w for w in cfg['workers'].values() if w['node_name']==socket.gethostname())
        cfg={**cfg,**worker}
        cfg['artifacts']={cfg[key]:sha256_file(Path(cfg[key])) for key in ('loader','object')}
        cfg['kernel']=__import__('platform').release()
        config=Path('/etc/sentinel-pulse')/f'matched-worker-{run_id}.json'
        if config.exists():raise ValueError('worker config already exists')
        config.write_text(json.dumps(cfg,indent=2)+'\n');config.chmod(0o600)
    python='/opt/sentinel-pulse/runtime-venv/bin/python' if role=='worker' else '/home/dat/ml-venv/bin/python'
    args=f'--config {config}'
    if role=='campaign':
        if credential is None or credential.stat().st_mode&0o077:raise ValueError('private credential required')
        args+=f' --credential {credential}'
    unit=f'''[Unit]
Description=Pulse matched {role} ({run_id})
After=network-online.target
Wants=network-online.target
RequiresMountsFor=/mnt/sentinel-pulse-archive
StartLimitIntervalSec=0

[Service]
Type=simple
User=root
Environment=PYTHONPATH={source}
Environment=PYTHONDONTWRITEBYTECODE=1
Environment=KUBECONFIG=/home/dat/.kube/config
Environment=OPENBLAS_NUM_THREADS=1
Environment=OMP_NUM_THREADS=1
Environment=MALLOC_ARENA_MAX=2
ExecStart={python} -u -m sentinel_pulse.{module} {args}
Restart=on-failure
RestartSec=30
TimeoutStopSec=90
LimitMEMLOCK=infinity
CPUQuota={300 if role=='worker' else 200}%
MemoryMax={3 if role=='worker' else 4}G
TasksMax=256
Nice=10
UMask=0027

[Install]
WantedBy=multi-user.target
'''
    path.write_text(unit)
    subprocess.run(['systemctl','daemon-reload'],check=True)
    subprocess.run(['systemctl','enable','--now',name],check=True)
    print(name)


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--config',type=Path,required=True)
    p.add_argument('--role',choices=['worker','study','campaign','traffic'],required=True)
    p.add_argument('--credential',type=Path);a=p.parse_args();install(a.config,a.role,a.credential)
