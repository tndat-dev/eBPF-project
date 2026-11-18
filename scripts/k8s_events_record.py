#!/usr/bin/env python3
"""Record the cluster's Kubernetes events for a live run (improvement-round-v1 D10: operational triggers such as rollouts,
restarts and failovers, to label alert episodes after the run; events live one hour in the API, so they are polled).

Every --interval seconds, `kubectl get events -A -o json`; an event is written once per (uid, count, lastTimestamp) to
OUTPUT (JSON lines). Stops after --seconds.

    python3 k8s_events_record.py --output RUN/k8s-events.jsonl --seconds 162000 [--interval 30]
"""
# GHI SỰ KIỆN KUBERNETES SUỐT LƯỢT LIVE (để gắn nhãn đợt cảnh báo do vận hành: rollout, restart, failover).
import argparse
import json
from pathlib import Path
import subprocess
import time


def snapshot():
    out = subprocess.run(['kubectl', 'get', 'events', '-A', '-o', 'json'], capture_output=True, text=True, timeout=60)
    return json.loads(out.stdout).get('items', []) if out.returncode == 0 else []


def key(e):
    m = e.get('metadata', {})
    return (m.get('uid'), e.get('count'), e.get('lastTimestamp') or e.get('eventTime'))


def keep(e):
    o, m = e.get('involvedObject', {}), e.get('metadata', {})
    return dict(uid=m.get('uid'), namespace=m.get('namespace'), reason=e.get('reason'), type=e.get('type'),
                message=(e.get('message') or '')[:300], kind=o.get('kind'), name=o.get('name'),
                first=e.get('firstTimestamp'), last=e.get('lastTimestamp') or e.get('eventTime'), count=e.get('count'),
                source=(e.get('source') or {}).get('component') or e.get('reportingComponent'))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--seconds', type=float, required=True)
    ap.add_argument('--interval', type=float, default=30.0)
    a = ap.parse_args()
    seen, end = set(), time.time() + a.seconds
    with a.output.open('a') as out:
        while time.time() < end:
            for e in snapshot():
                k = key(e)
                if k not in seen:
                    seen.add(k)
                    out.write(json.dumps(dict(keep(e), recorded_at=time.time())) + '\n')
            out.flush()
            time.sleep(a.interval)


if __name__ == '__main__':
    main()
