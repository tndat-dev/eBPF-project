#!/usr/bin/env python3
"""Application request latency with and without the Pulse probe (protocol app-overhead-v1).

Runs on k8s-master (.234) as dat, standard library only:
  python3 app_overhead_ab.py --credential /home/dat/.pulse-recovery-credential-20261005 --output /var/tmp/app-overhead
An open-loop client sends 8 requests/s through the Istio ingress NodePort for the whole run while the probe is
attached to / detached from the three workers in 300 s blocks (off-probe in odd rounds, probe-off in even rounds).
Writes requests.jsonl (one line per request) and blocks.jsonl (one line per block, with worker CPU and memory).
"""
import argparse
import concurrent.futures
import json
from pathlib import Path
import signal
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

WORKERS = ['10.1.16.237', '10.1.16.238', '10.1.16.239']
ENDPOINTS = ['/', '/api/health/', '/api/products/', '/api/products/?page=1']
PORT = 31088
LOADER = '/home/dat/pulse-matched-20261015/build/pulse_counter_extended_loader'
OBJECT = '/home/dat/pulse-matched-20261015/build/pulse_counter_extended.bpf.o'
UNIT = 'pulse-app-overhead-probe'
MIN_AVAILABLE_KB = 4 << 20
MAX_ERROR_SHARE = 0.20


class Lab:
    def __init__(self, credential):
        self.credential = credential

    def run(self, host, cmd, root=False, timeout=60):
        if root:
            cmd = "sudo -S -p '' sh -c " + json.dumps(cmd)
        with open(self.credential) as pw:   # sudo reads the password on stdin, as launch_run.sh does
            r = subprocess.run(['sshpass', '-f', self.credential, 'ssh', '-o', 'StrictHostKeyChecking=yes',
                                '-o', 'UserKnownHostsFile=/home/dat/.ssh/known_hosts', f'dat@{host}', cmd],
                               stdin=pw if root else subprocess.DEVNULL, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout.strip()

    def each(self, fn):
        with concurrent.futures.ThreadPoolExecutor(len(WORKERS)) as ex:
            return dict(zip(WORKERS, ex.map(fn, WORKERS)))


def node_state(lab, host):
    """(cpu jiffies busy, total) from /proc/stat, MemAvailable kB."""
    _, out = lab.run(host, "head -1 /proc/stat; grep MemAvailable /proc/meminfo")
    cpu, mem = out.splitlines()
    v = [int(x) for x in cpu.split()[1:]]
    total = sum(v[:8]); idle = v[3] + v[4]
    return dict(busy=total - idle, total=total, mem_available_kb=int(mem.split()[1]))


def precheck(lab, host):
    _, out = lab.run(host, "systemctl list-units --no-legend --plain --state=active 'pulse-matched-worker-*' "
                           "'sentinel-pulse-collector*' | wc -l; ps -eo comm= | grep -c '^pulse_counter' || true")
    units, loaders = (int(x) for x in out.split())
    return units == 0 and loaders == 0


def attach(lab, host):
    lab.run(host, f'systemctl reset-failed {UNIT} 2>/dev/null; systemd-run --unit={UNIT} --property=CPUAccounting=yes '
                  f'--property=StandardOutput=null {LOADER} --object {OBJECT} '
                  f'--allow-cgroup-file /run/sentinel-pulse/allowed-cgroups --interval-ms 500', root=True)
    time.sleep(3)
    return lab.run(host, f'systemctl is-active {UNIT}')[1] == 'active'


def detach(lab, host):
    """Stop the probe unit; returns its CPU nanoseconds (None when it was not running)."""
    _, out = lab.run(host, f'systemctl show -p CPUUsageNSec --value {UNIT}; systemctl stop {UNIT} 2>/dev/null; '
                           f'systemctl reset-failed {UNIT} 2>/dev/null; true', root=True)
    first = out.splitlines()[0] if out else ''
    return int(first) if first.isdigit() else None


class Client:
    def __init__(self, path, rate=8.0, threads=32, timeout=5.0):
        self.out = open(path, 'a'); self.lock = threading.Lock(); self.rate = rate; self.timeout = timeout
        self.pool = concurrent.futures.ThreadPoolExecutor(threads); self.stop = threading.Event()
        self.thread = threading.Thread(target=self.schedule, daemon=True)

    def one(self, k, scheduled):
        endpoint = ENDPOINTS[k % len(ENDPOINTS)]; host = WORKERS[(k // len(ENDPOINTS)) % len(WORKERS)]
        sent = time.time(); status = None; error = None; size = 0
        try:
            with urllib.request.urlopen(f'http://{host}:{PORT}{endpoint}', timeout=self.timeout) as r:
                size = len(r.read()); status = r.status
        except urllib.error.HTTPError as e:
            status = e.code
        except Exception as e:   # timeouts, resets: counted as errors, never retried
            error = type(e).__name__
        row = dict(k=k, endpoint=endpoint, host=host, scheduled=scheduled, sent=sent, done=time.time(),
                   status=status, error=error, bytes=size)
        with self.lock:
            self.out.write(json.dumps(row) + '\n')

    def schedule(self):
        t0 = time.time(); k = 0
        while not self.stop.is_set():
            at = t0 + k / self.rate
            delay = at - time.time()
            if delay > 0:
                time.sleep(delay)
            self.pool.submit(self.one, k, at); k += 1

    def flush_errors(self, start, end):
        """Share of failed requests scheduled in [start, end) (read back from the file)."""
        with self.lock:
            self.out.flush()
        n = bad = 0
        for line in open(self.out.name):
            d = json.loads(line)
            if start <= d['scheduled'] < end:
                n += 1; bad += d['status'] != 200
        return bad / n if n else 1.0

    def close(self):
        self.stop.set()
        if self.thread.ident:
            self.thread.join()
        self.pool.shutdown(wait=True)
        with self.lock:
            self.out.close()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--credential', required=True); ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--rounds', type=int, default=12); ap.add_argument('--block-seconds', type=float, default=300)
    ap.add_argument('--warmup-seconds', type=float, default=60)
    a = ap.parse_args()
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(1))   # systemctl stop -> finally detaches the probe
    lab = Lab(a.credential); a.output.mkdir(parents=True, exist_ok=True)
    blocks = open(a.output / 'blocks.jsonl', 'a')
    def log(**row):
        blocks.write(json.dumps(dict(row, at=time.time())) + '\n'); blocks.flush()
    if not all(lab.each(lambda h: precheck(lab, h)).values()):
        log(event='refused', reason='a live worker, the collector or a Pulse loader is active'); sys.exit(3)
    client = Client(a.output / 'requests.jsonl')
    log(event='start', rounds=a.rounds, block_seconds=a.block_seconds, rate=client.rate, endpoints=ENDPOINTS, workers=WORKERS)
    client.thread.start()
    try:
        time.sleep(a.warmup_seconds)
        for rnd in range(1, a.rounds + 1):
            for cond in (('off', 'probe') if rnd % 2 else ('probe', 'off')):
                before = lab.each(lambda h: node_state(lab, h))
                low = [h for h, s in before.items() if s['mem_available_kb'] < MIN_AVAILABLE_KB]
                if low:
                    log(event='stopped', reason='MemAvailable below 4 GiB', hosts=low); return
                if cond == 'probe' and not all(lab.each(lambda h: attach(lab, h)).values()):
                    log(event='stopped', reason='probe did not start on every worker'); return
                start = time.time(); time.sleep(a.block_seconds); end = time.time()
                cpu_ns = lab.each(lambda h: detach(lab, h)) if cond == 'probe' else None
                after = lab.each(lambda h: node_state(lab, h))
                errors = client.flush_errors(start, end - client.timeout)
                log(event='block', round=rnd, condition=cond, start=start, end=end, probe_cpu_ns=cpu_ns,
                    nodes={h: dict(busy=after[h]['busy'] - before[h]['busy'], total=after[h]['total'] - before[h]['total'],
                                   mem_available_kb=after[h]['mem_available_kb']) for h in WORKERS}, error_share=errors)
                if errors > MAX_ERROR_SHARE:
                    log(event='stopped', reason='more than 20 % of the block failed'); return
        log(event='finished')
    finally:
        lab.each(lambda h: detach(lab, h))
        client.close()
        log(event='closed')


if __name__ == '__main__':
    main()
