"""Read C4 inference and B2 live canary progress concurrently, without mutation."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import subprocess
import time

from sentinel_pulse.syscall_capture_campaign import Remote,WORKERS


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--credential',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();remote=Remote(a.credential)
    code='''import json,subprocess,time
from pathlib import Path
p=Path('/var/lib/pulse-idle-batch-canary-b2-20261014')
s=json.loads((p/'START.json').read_text()) if (p/'START.json').exists() else {}
t=(p/'TERMINAL.json').exists();f=p/('TERMINAL.json' if t else 'STATUS.json')
print(json.dumps(dict(status=json.loads(f.read_text()) if f.exists() else {},terminal_exists=t,
 registered_at_unix=s.get('registered_at_unix'),checked_at_unix=time.time(),
 service=subprocess.check_output(['systemctl','show','pulse-idle-batch-canary-b2.service',
 '-p','ActiveState','-p','SubState','-p','Result','-p','NRestarts','-p','MemoryCurrent'],text=True))))
'''
    with ThreadPoolExecutor(max_workers=3) as pool:
        workers=dict(zip(WORKERS,pool.map(lambda h:json.loads(remote.command(h,['python3','-c',code])),WORKERS)))
    root=Path('/mnt/sentinel-pulse-archive/syscall-variant-normal-c4')
    f=root/('STATUS.json' if (root/'STATUS.json').exists() else 'PREPARE_STATUS.json')
    state=json.loads(f.read_text());state.pop('completed',None)
    state['terminal_exists']=(root/'TERMINAL.json').exists()
    state['service']=subprocess.check_output(['systemctl','show','pulse-syscall-normal-evaluation-c4.service',
        '-p','ActiveState','-p','SubState','-p','NRestarts','-p','UnitFileState','-p','MemoryCurrent'],text=True)
    out=dict(checked_at_unix=time.time(),batch_canary=workers,syscall_c4=state)
    with a.output.open('x') as stream:json.dump(out,stream,indent=2);stream.write('\n')
    print(json.dumps(dict(checked_at_unix=out['checked_at_unix'],syscall_state=state['state'],
        completed_models=state.get('completed_models'),canaries={h:w['status'] for h,w in workers.items()})))


if __name__=='__main__':main()
