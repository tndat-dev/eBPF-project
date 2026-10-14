"""Run separate 30-minute timing canaries on all three workers, in parallel."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import re
import shlex
import subprocess
import tarfile

from sentinel_pulse.integrity import sha256_file
from sentinel_pulse.syscall_capture_campaign import Remote,WORKERS
from scripts.deploy_idle_batch_live_canary import MODEL,FROZEN,MODEL_HASH,POLICY_HASH


ROOT='/home/dat/pulse-idle-batch-canary-b2-20261014'
SOURCE=ROOT+'/source'
OUTPUT='/var/lib/pulse-idle-batch-canary-b2-20261014'
UNIT='pulse-idle-batch-canary-b2.service'


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--archive',type=Path,required=True);p.add_argument('--credential',type=Path,required=True)
    p.add_argument('--run-name',default='pulse-idle-batch-canary-b2-20261014')
    p.add_argument('--seconds',type=int,default=1800)
    a=p.parse_args();remote=Remote(a.credential)
    if not re.fullmatch(r'pulse-idle-batch-canary-[a-z][0-9]-[0-9]{8}',a.run_name):
        raise ValueError('safe identified canary run name required')
    if not 30<=a.seconds<=3600:raise ValueError('bounded canary duration 30..3600 required')
    root='/home/dat/'+a.run_name;source=root+'/source';output='/var/lib/'+a.run_name
    unit_name=a.run_name.rsplit('-',1)[0]+'.service'
    with tarfile.open(a.archive) as bundle:commit=bundle.pax_headers.get('comment','')
    if len(commit)!=40 or any(c not in '0123456789abcdef' for c in commit):raise ValueError('identified Git archive required')
    benchmark=Path('/home/dat/pulse-parallel-completion-20261014/batch-benchmark.json')
    result=json.loads(benchmark.read_text())
    if result['state']!='completed_equivalence_benchmark' or len(result['workloads'])!=21:raise ValueError('complete equivalence required')
    def scp(host,local,target):
        subprocess.run(['sshpass','-f',str(a.credential),'scp','-q','-o','StrictHostKeyChecking=yes',
            str(local),f'dat@{host}:{target}'],check=True,capture_output=True,timeout=90)
    def deploy(host):
        artifact=root+'.tar.gz';scp(host,a.archive,artifact)
        remote.command(host,['python3','-c','from pathlib import Path;import shutil;'
            'assert not Path('+repr(output)+').exists();assert shutil.disk_usage("/var/lib").free>2*1024**3'])
        remote.command(host,['mkdir','-p',source,root+'/benchmark'])
        remote.command(host,['chown','1000:1000',root+'/benchmark'])
        scp(host,benchmark,root+'/benchmark/TERMINAL.json')
        remote.command(host,['tar','-xzf',artifact,'-C',source])
        args=['/opt/sentinel-pulse/runtime-venv/bin/python','-u','-m','sentinel_pulse.idle_batch_live_canary',
            '--source',source,'--frozen-source',FROZEN,'--build','/home/dat/pulse-extended-telemetry-c1/build',
            '--proof','/home/dat/pulse-extended-telemetry-c1/proof-r2','--candidate',MODEL,'--model-sha256',MODEL_HASH,
            '--policy',FROZEN+'/sentinel_pulse/protocol/idle-aware-candidate-preview-policy-c1.json',
            '--policy-sha256',POLICY_HASH,'--benchmark',root+'/benchmark','--output',output,'--seconds',str(a.seconds)]
        unit='''[Unit]
Description=Frozen Pulse bounded three-worker batch timing canary
After=network-online.target remote-fs.target
RequiresMountsFor=/mnt/sentinel-pulse-archive
[Service]
Type=exec
User=root
WorkingDirectory=%s
Environment=PYTHONPATH=%s PYTHONDONTWRITEBYTECODE=1 OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1
ExecStart=%s
RuntimeMaxSec=%d
TimeoutStopSec=30
CPUQuota=200%%
MemoryMax=2G
MemorySwapMax=0
Nice=15
IOWeight=1
UMask=0077
'''%(source,source,shlex.join(args),a.seconds+120)
        write='from pathlib import Path;import sys;p=Path(sys.argv[1]);assert not p.exists();p.write_text(sys.argv[2])'
        remote.command(host,['python3','-c',write,'/etc/systemd/system/'+unit_name,unit])
        remote.command(host,['systemctl','daemon-reload']);remote.command(host,['systemctl','start','--no-block',unit_name])
        return dict(host=host,unit=unit_name,output=output,seconds=a.seconds)
    with ThreadPoolExecutor(max_workers=3) as pool:receipts=list(pool.map(deploy,WORKERS))
    print(json.dumps(dict(source_commit=commit,benchmark_sha256=sha256_file(benchmark),workers=receipts,
        shadow_only=True,automatic_promotion=False)))


if __name__=='__main__':main()
