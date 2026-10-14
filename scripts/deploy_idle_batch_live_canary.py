"""Start one isolated five-minute timing canary; never modify serving/soak units."""
import argparse
import json
from pathlib import Path
import shlex
import subprocess
import tarfile

from sentinel_pulse.syscall_capture_campaign import Remote


ROOT='/home/dat/pulse-idle-batch-canary-b1-20261014'
SOURCE=ROOT+'/source'
OUTPUT='/var/lib/pulse-idle-batch-canary-b1-20261014'
UNIT='pulse-idle-batch-canary-b1.service'
MODEL='/mnt/sentinel-pulse-archive/runtime-f95867d-20261012/model-bundle'
FROZEN='/mnt/sentinel-pulse-archive/runtime-2c1a72d-20261013/source'
MODEL_HASH='747c4eed2a9a74321d0ac3b716c201c449f946665252baa1ca314b1f18278a08'
POLICY_HASH='fd0be94a4ca7f2cd64b97bf5c7dc074763405f821ab346e8e19bb5975d10f401'


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--archive',type=Path,required=True)
    p.add_argument('--credential',type=Path,required=True)
    a=p.parse_args();remote=Remote(a.credential);host='10.1.16.237'
    with tarfile.open(a.archive) as bundle:commit=bundle.pax_headers.get('comment','')
    if len(commit)!=40 or any(c not in '0123456789abcdef' for c in commit):
        raise ValueError('identified Git archive required')
    artifact=ROOT+'.tar.gz'
    subprocess.run(['sshpass','-f',str(a.credential),'scp','-q','-o','StrictHostKeyChecking=yes',
        str(a.archive),f'dat@{host}:{artifact}'],check=True,capture_output=True,timeout=90)
    remote.command(host,['python3','-c',
        'from pathlib import Path;import shutil;'
        'assert not Path("'+OUTPUT+'").exists();'
        'assert shutil.disk_usage("/var/lib").free>2*1024**3'])
    remote.command(host,['mkdir','-p',SOURCE])
    remote.command(host,['tar','-xzf',artifact,'-C',SOURCE])
    python='/opt/sentinel-pulse/runtime-venv/bin/python'
    remote.command(host,['env','PYTHONPATH='+SOURCE,python,
        SOURCE+'/tests/test_sentinel_pulse_idle_batch.py'],timeout=90)
    args=[python,'-u','-m','sentinel_pulse.idle_batch_live_canary','--source',SOURCE,
        '--frozen-source',FROZEN,'--build','/home/dat/pulse-extended-telemetry-c1/build',
        '--proof','/home/dat/pulse-extended-telemetry-c1/proof-r2',
        '--candidate',MODEL,'--model-sha256',MODEL_HASH,
        '--policy',FROZEN+'/sentinel_pulse/protocol/idle-aware-candidate-preview-policy-c1.json',
        '--policy-sha256',POLICY_HASH,'--benchmark','/home/dat/pulse-idle-batch-b1-20261014/results',
        '--output',OUTPUT]
    unit='''[Unit]
Description=Isolated frozen Pulse five-minute batch timing canary
After=network-online.target remote-fs.target
RequiresMountsFor=/mnt/sentinel-pulse-archive
[Service]
Type=exec
User=root
WorkingDirectory=%s
Environment=PYTHONPATH=%s PYTHONDONTWRITEBYTECODE=1 OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1
ExecStart=%s
RuntimeMaxSec=420
TimeoutStopSec=30
CPUQuota=200%%
MemoryMax=2G
MemorySwapMax=0
Nice=15
IOWeight=1
UMask=0077
'''%(SOURCE,SOURCE,shlex.join(args))
    write='from pathlib import Path;import sys;p=Path(sys.argv[1]);assert not p.exists();p.write_text(sys.argv[2])'
    remote.command(host,['python3','-c',write,'/etc/systemd/system/'+UNIT,unit])
    remote.command(host,['systemctl','daemon-reload'])
    remote.command(host,['systemctl','start','--no-block',UNIT])
    print(json.dumps(dict(source_commit=commit,host=host,unit=UNIT,output=OUTPUT,
        runtime_seconds=300,shadow_only=True,attack_injection=False,model_or_threshold_changed=False)))


if __name__=='__main__':main()
