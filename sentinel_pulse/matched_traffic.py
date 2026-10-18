"""Replay registered AIMS normal-load phases and retain rollout evidence."""
import argparse
import fcntl
import json
from pathlib import Path
import subprocess
import time

from .common import append_jsonl, atomic_json


def run(config):
    cfg=json.loads(config.read_text());root=Path(cfg['traffic_output']);root.mkdir(parents=True,exist_ok=True)
    lock=(root/'traffic.lock').open('a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    if (root/'TERMINAL.json').exists():return
    finished=set(json.loads((root/'STATUS.json').read_text()).get('finished_phases',[])) if (root/'STATUS.json').exists() else set()
    for i,phase in enumerate(cfg['traffic_schedule']):
        if i in finished:continue
        while time.time()<phase['start']:
            atomic_json(root/'STATUS.json',dict(state='waiting_for_registered_phase',phase=i,
                finished_phases=sorted(finished),updated_at_unix=time.time()))
            time.sleep(min(15,max(0,phase['start']-time.time())))
        # An offline VM cannot retroactively generate a missed traffic phase.
        # Record the gap and continue with later phases after reboot.
        if time.time()>=phase['end']:
            append_jsonl(root/'PHASES.jsonl',dict(phase,index=i,state='missed_during_outage',not_normal=True))
            finished.add(i);continue
        with (root/f'phase-{i:02d}.log').open('a') as log:
            result=subprocess.run(['bash',cfg['source']+'/testbed/traffic/set_aims_traffic_regime.sh',phase['regime']],
                                  stdout=log,stderr=log,timeout=600,check=False)
        append_jsonl(root/'PHASES.jsonl',dict(phase,index=i,actual_applied_at=time.time(),
            returncode=result.returncode,state='applied' if result.returncode==0 else 'apply_error',
            rollout_is_retained_context=True))
        finished.add(i)
        atomic_json(root/'STATUS.json',dict(state='running',finished_phases=sorted(finished),updated_at_unix=time.time()))
    atomic_json(root/'TERMINAL.json',dict(state='completed_traffic_schedule',finished_phases=sorted(finished),finished_at=time.time()))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--config',type=Path,required=True)
    run(p.parse_args().config)
