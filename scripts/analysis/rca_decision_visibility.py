#!/usr/bin/env python3
"""Compare decision visibility on .234: worker-side follower over SSH vs re-opening the NFS file.
Usage (on .234 as dat): python3 rca_decision_visibility.py <snapshot dir containing source/>"""
import json, os, subprocess, sys, time, glob, select, statistics
sys.path.insert(0, sys.argv[1] + '/source')
from sentinel_pulse.rca.service import DECISION_FOLLOWER
root = '/mnt/sentinel-pulse-archive/matched-r6-20261018/workers/k8s-worker1.local'
import shlex
remote = ' '.join(shlex.quote(a) for a in ['timeout', '25', 'python3', '-u', '-c', DECISION_FOLLOWER, root])
child = subprocess.Popen(['sshpass', '-f', '/home/dat/.pulse-recovery-credential-20261005', 'ssh', '-o', 'StrictHostKeyChecking=yes',
                          '-o', 'UserKnownHostsFile=/home/dat/.ssh/known_hosts', 'dat@10.1.16.237', remote], stdout=subprocess.PIPE)
nfs_path = sorted(glob.glob(root + '/segments/s*/decisions.jsonl'))[-1]
nfs = open(nfs_path, 'rb'); nfs.seek(0, 2); nbuf = b''; sbuf = b''
ssh_lag, nfs_lag = [], []
end = time.time() + 20
while time.time() < end:
    r = select.select([child.stdout], [], [], 0.05)[0]
    now = time.time()
    if r:
        chunk = os.read(child.stdout.fileno(), 1 << 20); *lines, sbuf = (sbuf + chunk).split(b'\n')
        for l in lines:
            d = json.loads(l)
            if d.get('preview_emitted_at'): ssh_lag.append(now - d['preview_emitted_at'])
    with open(nfs_path, 'rb') as probe:   # reopen like the RCA tail (close-to-open revalidation)
        probe.seek(nfs.tell()); chunk = probe.read()
    if chunk:
        nfs.seek(nfs.tell() + len(chunk)); *lines, nbuf = (nbuf + chunk).split(b'\n')
        for l in lines:
            d = json.loads(l)
            if d.get('preview_emitted_at'): nfs_lag.append(now - d['preview_emitted_at'])
    time.sleep(0.05)
child.terminate()
q = lambda v: dict(n=len(v), p50=round(statistics.median(v), 3), p95=round(sorted(v)[int(.95 * len(v)) - 1], 3)) if v else None
print(json.dumps(dict(schema='rca-decision-visibility-v1', node='k8s-worker1.local', seconds=20,
                      ssh_follower=q(ssh_lag), nfs_reopen_read=q(nfs_lag), measured_at_unix=time.time())))
