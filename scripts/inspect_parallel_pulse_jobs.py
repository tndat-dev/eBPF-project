"""Read progress of C3 and the independent Pulse soak review together."""
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
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    remote = Remote(a.credential)
    code = '''from pathlib import Path
import json,subprocess,time
r=Path('/var/lib/pulse-shadow-review/normal-a1-20261013-r2')
s=json.loads((r/'STATUS.json').read_text())
b=s['binding']['decisions']['bytes'];now=time.time();elapsed=now-s['registered_at_unix']
done=s['position'];eta=(b-done)*elapsed/done if done and elapsed>0 else None
print(json.dumps(dict(checked_at_unix=now,state=s['state'],rows=s['rows'],bytes_read=done,
 total_bytes=b,byte_progress_percent=done/b*100,linear_eta_seconds=eta,
 eta_is_estimate=True,issues=s['issues'],status_counts=s['status_counts'],
 run_id=s['binding']['run_id'],scored=sum(w['scored'] for w in s['workloads'].values()),
 preview_positive_pending_adjudication=sum(w['preview_positive'] for w in s['workloads'].values()),
 terminal_exists=(r/'TERMINAL.json').exists(),
 service=subprocess.check_output(['systemctl','show','pulse-shadow-soak-summary@normal-a1-20261013.service',
 '-p','ActiveState','-p','SubState','-p','NRestarts','-p','UnitFileState'],text=True))))
'''
    with ThreadPoolExecutor(max_workers=3) as pool:
        workers = dict(zip(WORKERS, pool.map(lambda h: json.loads(remote.command(h, ['python3', '-c', code])), WORKERS)))
    root = Path('/mnt/sentinel-pulse-archive/syscall-capture-c3-r2')
    s = json.loads((root/'STATUS.json').read_text())
    active = {k: v for k, v in (s.get('active') or {}).items() if k != 'traffic_identity'}
    result = dict(checked_at=datetime.now(timezone.utc).isoformat(), pulse_review=workers,
        syscall=dict(state=s['state'],completed=s['completed'],active=active,
            terminal_exists=(root/'TERMINAL.json').exists(),
            service=subprocess.check_output(['systemctl','show','pulse-syscall-capture-c3.service',
                '-p','ActiveState','-p','SubState','-p','NRestarts','-p','UnitFileState'],text=True)))
    with a.output.open('x') as stream:
        json.dump(result, stream, indent=2); stream.write('\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
