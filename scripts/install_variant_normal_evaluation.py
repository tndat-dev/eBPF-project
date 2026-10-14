"""Install a reboot-resumable, read-only C2 evaluation on independent C3 holdout."""
import argparse
import json
from pathlib import Path
import shlex
import subprocess

from sentinel_pulse.integrity import sha256_file


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--credential',type=Path,required=True)
    p.add_argument('--source',type=Path,required=True)
    a=p.parse_args();source=a.source.resolve()
    credential=a.credential.read_text().strip()
    campaign=Path('/mnt/sentinel-pulse-archive/syscall-capture-c3-r2')
    audit=campaign/'holdout-preflight-complete-20261014.json'
    model='/mnt/sentinel-pulse-archive/syscall-variant-artifacts-c2/runs/attempt-000002'
    output='/mnt/sentinel-pulse-archive/syscall-variant-normal-c4'
    args=['/home/dat/sentinel-pulse-syscall-feature-c1/venv/bin/python','-u','-m',
        'sentinel_pulse.variant_independent_normal','--campaign',str(campaign),'--audit',str(audit),
        '--audit-sha256',sha256_file(audit),'--training-manifest',
        '/home/dat/sentinel-pulse-syscall-feature-c1/inputs/manifest.json','--model-root',model,
        '--model-sha256','4c379dcabd8ea2c8ca0c19f9e13e186dfa9fe63f0df1ea1a2d4d591e946c4408',
        '--output',output]
    unit='''[Unit]
Description=Frozen syscall variants on independent C3 normal holdout
After=network-online.target remote-fs.target
Wants=network-online.target
RequiresMountsFor=/mnt/sentinel-pulse-archive
StartLimitIntervalSec=0
[Service]
Type=exec
User=dat
WorkingDirectory=%s
Environment=PYTHONPATH=%s PYTHONDONTWRITEBYTECODE=1 OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1
ExecStart=%s
Restart=on-failure
RestartSec=60
CPUQuota=200%%
MemoryMax=3G
MemorySwapMax=0
Nice=19
IOWeight=1
UMask=0077
[Install]
WantedBy=multi-user.target
'''%(source,source,shlex.join(args))
    name='pulse-syscall-normal-evaluation-c4.service'
    write='from pathlib import Path;import sys;p=Path(sys.argv[1]);assert not p.exists();p.write_text(sys.argv[2])'
    for args in [ ['python3','-c',write,'/etc/systemd/system/'+name,unit],
                  ['systemctl','daemon-reload'],['systemctl','enable','--now','--no-block',name] ]:
        subprocess.run(['sudo','-S','-p','',*args],input=credential+'\n',text=True,capture_output=True,check=True)
    print(json.dumps(dict(unit=name,output=output,audit_sha256=sha256_file(audit),model_count=608,
        no_model_or_threshold_change=True,reboot_resumable=True)))


if __name__=='__main__':main()
