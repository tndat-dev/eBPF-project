"""Deploy separate context exports and a durable frozen-model timing job."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import shlex
import subprocess
import tarfile

from sentinel_pulse.syscall_capture_campaign import Remote, WORKERS


ROOT = '/home/dat/pulse-idle-batch-b1-20261014'
SOURCE = ROOT+'/source'
MODEL = '/mnt/sentinel-pulse-archive/runtime-f95867d-20261012/model-bundle'
FROZEN = '/mnt/sentinel-pulse-archive/runtime-2c1a72d-20261013/source'
MANIFEST_HASH = '747c4eed2a9a74321d0ac3b716c201c449f946665252baa1ca314b1f18278a08'
PYTHON = '/opt/sentinel-pulse/runtime-venv/bin/python'


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--archive',type=Path,required=True)
    p.add_argument('--credential',type=Path,required=True)
    a=p.parse_args();remote=Remote(a.credential)
    with tarfile.open(a.archive) as bundle:commit=bundle.pax_headers.get('comment','')
    if len(commit)!=40 or any(c not in '0123456789abcdef' for c in commit):
        raise ValueError('identified Git archive required')
    def scp(host,local,remote_path):
        subprocess.run(['sshpass','-f',str(a.credential),'scp','-q','-o','StrictHostKeyChecking=yes',
                        str(local),f'dat@{host}:{remote_path}'],check=True,capture_output=True,timeout=90)
    def prepare(host):
        artifact='/home/dat/pulse-idle-batch-b1-20261014.tar.gz'
        scp(host,a.archive,artifact)
        remote.command(host,['mkdir','-p',SOURCE])
        remote.command(host,['tar','-xzf',artifact,'-C',SOURCE])
        test=remote.command(host,['env','PYTHONPATH='+SOURCE,PYTHON,
                                  SOURCE+'/tests/test_sentinel_pulse_idle_batch.py'],timeout=90)
        export=ROOT+'/export-'+host.rsplit('.',1)[-1]
        remote.command(host,['env','PYTHONPATH='+SOURCE,PYTHON,'-m','sentinel_pulse.idle_batch_benchmark',
            'export','--capture','/var/lib/sentinel-pulse-normal-normal-a1-20261013/capture',
            '--manifest',MODEL+'/CANDIDATE_MANIFEST.json','--manifest-sha256',MANIFEST_HASH,
            '--output',export],timeout=120)
        destination=Path(ROOT)/'inputs'/Path(export).name;destination.mkdir(parents=True,exist_ok=True)
        for name in ['CONTEXTS.npz','TERMINAL.json']:
            target=destination/name
            if target.exists():raise ValueError('input copy already exists')
            subprocess.run(['sshpass','-f',str(a.credential),'scp','-q','-o','StrictHostKeyChecking=yes',
                f'dat@{host}:{export}/{name}',str(target)],check=True,capture_output=True,timeout=90)
        return dict(host=host,export=str(destination),stdlib_tests_completed=True)
    with ThreadPoolExecutor(max_workers=3) as pool:receipts=list(pool.map(prepare,WORKERS))
    worker='10.1.16.237'; inputs=[]
    for row in receipts:
        folder=Path(row['export']);target=ROOT+'/inputs/'+folder.name
        remote.command(worker,['mkdir','-p',target])
        # UID/GID 1000 owns the input directory so transport uses dat, not root.
        remote.command(worker,['chown','1000:1000',target])
        for name in ['CONTEXTS.npz','TERMINAL.json']:scp(worker,folder/name,target+'/'+name)
        inputs.extend(['--input',target])
    args=[PYTHON,'-u','-m','sentinel_pulse.idle_batch_benchmark','benchmark',*inputs,
          '--candidate-dir',MODEL,'--manifest-sha256',MANIFEST_HASH,'--frozen-source',FROZEN,
          '--output',ROOT+'/results']
    unit='''[Unit]
Description=Frozen Pulse scalar/batch equivalence and inference timing
After=network-online.target remote-fs.target
RequiresMountsFor=/mnt/sentinel-pulse-archive
StartLimitIntervalSec=0
[Service]
Type=oneshot
User=root
WorkingDirectory=%s
Environment=PYTHONPATH=%s PYTHONDONTWRITEBYTECODE=1 OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1
ExecStart=%s
Restart=on-failure
RestartSec=60
TimeoutStartSec=infinity
CPUQuota=100%%
MemoryMax=2G
MemorySwapMax=0
Nice=19
IOWeight=1
UMask=0077
[Install]
WantedBy=multi-user.target
'''%(SOURCE,SOURCE,shlex.join(args))
    write='from pathlib import Path;import sys;p=Path(sys.argv[1]);assert not p.exists();p.write_text(sys.argv[2])'
    path='/etc/systemd/system/pulse-idle-batch-benchmark-b1.service'
    remote.command(worker,['python3','-c',write,path,unit])
    remote.command(worker,['systemctl','daemon-reload'])
    remote.command(worker,['systemctl','enable','--no-block','--now','pulse-idle-batch-benchmark-b1.service'])
    print(json.dumps(dict(source_commit=commit,context_exports=receipts,benchmark_worker=worker,
        unit='pulse-idle-batch-benchmark-b1.service',accuracy_claim=False,kernel_to_alert_claim=False)))


if __name__=='__main__':main()
