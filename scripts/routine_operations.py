#!/usr/bin/env python3
"""Routine operator commands during a normal capture (protocol exec-identity-v1).

About every 10 minutes (seeded uniform 8-12 min) one command of the routine set runs through kubectl exec in a seeded
random container of a production workload (load generators excluded), as an operator's routine checks. A command the
image lacks fails and is recorded; nothing else is done. Every attempt is appended to ROUTINE.jsonl.

    python3 routine_operations.py --output RUN/ROUTINE.jsonl --seconds 172800 --seed 20261124
"""
# Lệnh vận hành định kỳ trong lượt thu normal (exec-identity-v1): mỗi ~10 phút một lệnh của tập định kỳ qua kubectl exec.
import argparse
import json
import random
import subprocess
import time
from pathlib import Path

# exec-identity-v1: five of the nine v6 operator commands other than ls_tmp (sha256 rank), the same argv as the campaign
ROUTINE = (('find', ['find', '/etc', '-maxdepth', '1', '-name', 'hosts']), ('grep', ['grep', '-c', 'root', '/etc/group']),
           ('sleep', ['sleep', '1']), ('stat', ['stat', '/']), ('wc', ['wc', '-l', '/etc/hostname']))
NAMESPACE = 'production'


def targets():
    """[(pod, container)] of running production pods, load generators excluded."""
    doc = json.loads(subprocess.run(['kubectl', 'get', 'pods', '-n', NAMESPACE, '-o', 'json'], capture_output=True,
                                    check=True, timeout=60).stdout)
    out = []
    for p in doc['items']:
        if p.get('status', {}).get('phase') != 'Running' or 'loadgen' in p['metadata']['name']:
            continue
        for c in p['spec']['containers']:
            out.append((p['metadata']['name'], c['name']))
    return sorted(out)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--seconds', type=float, required=True)
    ap.add_argument('--seed', type=int, required=True)
    a = ap.parse_args()
    rng = random.Random(a.seed)
    end = time.time() + a.seconds
    a.output.parent.mkdir(parents=True, exist_ok=True)
    while True:
        time.sleep(rng.uniform(480, 720))
        if time.time() >= end:
            break
        name, argv = rng.choice(ROUTINE)
        try:
            pod, container = rng.choice(targets())
        except (subprocess.SubprocessError, IndexError, ValueError) as exc:
            row = dict(at=time.time(), command=name, error=f'no target: {exc}'[:300])
        else:
            started = time.time()
            r = subprocess.run(['kubectl', 'exec', '-n', NAMESPACE, pod, '-c', container, '--', *argv],
                               capture_output=True, timeout=60, check=False)
            row = dict(at=started, command=name, pod=pod, container=container, returncode=r.returncode,
                       stderr=r.stderr.decode(errors='replace')[:200])
        with a.output.open('a') as handle:
            handle.write(json.dumps(row) + '\n')


if __name__ == '__main__':
    main()
