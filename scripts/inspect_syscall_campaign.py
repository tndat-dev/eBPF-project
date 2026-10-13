"""Read current soak/C3 state on the coordinator without changing services."""
import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess

from sentinel_pulse.syscall_capture_campaign import Remote, WORKERS


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--credential', type=Path, required=True)
    p.add_argument('--output', type=Path)
    a = p.parse_args()
    remote = Remote(a.credential)
    def worker(host):
        observed = remote.inspect(host)
        status = observed.get('status') or {}
        command = '''import json,subprocess,time
from pathlib import Path
p=Path('/var/lib/sentinel-pulse-normal-normal-a1-20261013/shadow/decisions.jsonl')
row={}
if p.exists():
 with p.open('rb') as f:
  f.seek(max(0,p.stat().st_size-65536));data=f.read()
 for line in reversed(data.splitlines()):
  try:row=json.loads(line);break
  except (ValueError,UnicodeDecodeError):pass
s=subprocess.check_output(['systemctl','show','sentinel-pulse-observation-shadow@normal-a1-20261013.service','-p','ActiveState','-p','NRestarts'],text=True)
print(json.dumps(dict(service=s,last_row={k:row.get(k) for k in ('processed_at','window_end','feature_event_age_seconds','status')},checked_at_unix=time.time())))
'''
        shadow = json.loads(remote.command(host, ['python3', '-c', command]))
        return dict(status={k: status.get(k) for k in ('state', 'boundary_observation_seconds', 'feature_rows',
            'eligible_for_normal_review_rows', 'errors', 'capacity_pause_count', 'updated_at_unix')},
            terminal=observed.get('terminal'), active_capture=bool(observed.get('active_capture_processes')),
            shadow=shadow)
    with ThreadPoolExecutor(max_workers=3) as pool:
        workers = dict(zip(WORKERS, pool.map(worker, WORKERS)))
    root = Path('/mnt/sentinel-pulse-archive/syscall-capture-c3-r2')
    current = json.loads((root/'STATUS.json').read_text())
    replay = json.loads(Path('/mnt/sentinel-pulse-archive/syscall-variant-replay-c3/TERMINAL.json').read_text())
    smoke = subprocess.run(['sudo','-S','-p','','cat',
        '/home/dat/pulse-syscall-capture-c3/smoke-evidence/TERMINAL.json'],
        input=remote.password+'\n',text=True,capture_output=True,timeout=10)
    result = dict(checked_at=datetime.now(timezone.utc).isoformat(), workers=workers,
        campaign=dict(root=str(root),state=current['state'],active=current['active'],completed=current['completed'],
            source_commit=json.loads((root/'START.json').read_text())['contract']['source_commit'],
            service=subprocess.check_output(['systemctl','show','pulse-syscall-capture-c3.service',
                '-p','ActiveState','-p','SubState','-p','UnitFileState','-p','NRestarts'],text=True)),
        replay=dict(state=replay['state'],completed_models=replay['completed_models'],
                    maximum_score_error=max(x['maximum_score_error'] for x in replay['verified'].values()),
                    independent_test=replay['independent_test']),
        smoke=json.loads(smoke.stdout) if smoke.returncode==0 else dict(read_error=smoke.returncode))
    payload = json.dumps(result, indent=2)+'\n'
    if a.output:
        with a.output.open('x') as output:
            output.write(payload)
    print(payload)


if __name__ == '__main__':
    main()
