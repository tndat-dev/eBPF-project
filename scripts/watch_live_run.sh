#!/usr/bin/env bash
# Local watcher for a live run: polls /home/dat/health-run.py on .234 every 5 min and exits (one
# notification) on an anomaly or when all three workers have finished.
#   LAB_SSH_PASSWORD=... bash scripts/watch_live_run.sh [run-id]
cd "$(dirname "$0")/.."
RUN=${1:-pulse-stable-candidate}
prev=""
while true; do
  line=$(timeout 120 python3 scripts/ssh_lab.py --host 10.1.16.234 bash -c "echo $LAB_SSH_PASSWORD | sudo -S -p '' python3 /home/dat/health-run.py $RUN" 2>/dev/null | tail -1)
  if [ -n "$line" ]; then
    verdict=$(PREV="$prev" LINE="$line" python3 - <<'PY'
import json, os
cur = json.loads(os.environ['LINE']); prev = json.loads(os.environ['PREV']) if os.environ['PREV'] else None
alerts, done = [], 0
for n in ('k8s-worker1', 'k8s-worker4', 'k8s-worker3'):
    w = cur.get(n)
    if not isinstance(w, dict): alerts.append(f'{n} status unreadable'); continue
    done += w['done']
    if not w['done'] and w['age'] > 120: alerts.append(f"{n} heartbeat stale {w['age']} s")
    if prev and isinstance(prev.get(n), dict) and (w['issues'] or 0) - (prev[n]['issues'] or 0) > 30:
        alerts.append(f"{n} issues +{w['issues'] - prev[n]['issues']} in 5 min")
rca = cur.get('rca')
if not isinstance(rca, dict) or rca['age'] > 180: alerts.append(f'rca stale/unreadable: {rca}')
if cur['nfs_free_gb'] < 15: alerts.append(f"NFS free {cur['nfs_free_gb']} GB")
if cur['tetra_getevents'] > 12: alerts.append(f"{cur['tetra_getevents']} tetra getevents processes (orphans?)")
print('ALERT ' + '; '.join(alerts) if alerts else ('DONE' if done == 3 else 'OK'))
PY
)
    case "$verdict" in ALERT*|DONE) echo "$verdict"; echo "$line"; exit 0 ;; esac
    prev=$line
  fi
  sleep 300
done
