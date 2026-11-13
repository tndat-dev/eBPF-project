#!/usr/bin/env python3
"""Proof of the lineage tag of the token probe (ml-final-study-v1 amendment 2) on one worker, as root, on a test pod.

The pod's own command loops (`cat` and `sleep` children of pid 1): native lineage. The script then enters the container
through the runtime (`crictl exec`, the path of kubectl exec and of exec probes): session lineage. Phases:

  A  idle            only the container's own loop runs
  B  exec            sh -c 'ls /; cat /etc/hostname; sleep 1; ls /tmp'
  C  idle
  D  orphan          sh -c '(sleep 1.2; ls /; cat /etc/hostname) & exit 0': the child outlives its session parent and is
                     re-parented to the container's pid 1
  E  idle

Checks: no session event in A, C (after D's orphan ended) and E; session events with an execve token in B, and the
container's own loop still native there; session events in D after the exec command returned (the orphan keeps its
lineage); every window's session part is a subset of its grams; one token per syscall over the whole run.

    python3 lineage_probe_proof.py --build DIR --container-id ID --out DIR
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sentinel_pulse.collector.token_capture import check_grams, check_session  # noqa: E402

NR_EXECVE = 59
MARGIN = 0.6


def cgroup_of(container_id):
    hits = [p for p in Path('/sys/fs/cgroup').rglob(f'*{container_id}*') if p.is_dir()]
    if len(hits) != 1:
        sys.exit(f'container cgroup not found uniquely: {hits}')
    return hits[0]


def crictl_exec(container_id, script):
    t0 = time.time()
    subprocess.run(['crictl', 'exec', container_id, 'sh', '-c', script], check=True, capture_output=True, timeout=60)
    return t0, time.time()


def span(rows, a, b):
    return [r for r in rows if a <= r['window_end'] - 0.5 and r['window_end'] <= b]


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--build', type=Path, required=True)
    ap.add_argument('--container-id', required=True)
    ap.add_argument('--out', type=Path, required=True)
    a = ap.parse_args()
    if os.geteuid() != 0:
        sys.exit('run as root')
    a.out.mkdir(parents=True, exist_ok=False)
    cg = cgroup_of(a.container_id)
    cgid = os.stat(cg).st_ino
    (a.out / 'allowed-cgroup').write_text(f'{cgid}\n')
    raw, err = (a.out / 'raw.jsonl').open('w'), (a.out / 'loader.stderr').open('w')
    loader = subprocess.Popen([str(a.build / 'pulse_counter_tokens_loader'), '--object', str(a.build / 'pulse_counter_tokens.bpf.o'),
                               '--allow-cgroup-file', str(a.out / 'allowed-cgroup'), '--interval-ms', '500', '--tokens', 'grams'],
                              stdout=raw, stderr=err)
    t = {}
    try:
        for _ in range(600):
            if 'sentinel-pulse attached' in (a.out / 'loader.stderr').read_text():
                break
            if loader.poll() is not None:
                sys.exit('loader exited: ' + (a.out / 'loader.stderr').read_text())
            time.sleep(0.1)
        t['attached'] = time.time()
        time.sleep(4.0)
        t['b0'], t['b1'] = crictl_exec(a.container_id, 'ls / >/dev/null; cat /etc/hostname >/dev/null; sleep 1; ls /tmp >/dev/null')
        time.sleep(3.0)
        t['d0'], t['d1'] = crictl_exec(a.container_id, '(sleep 1.2; ls / >/dev/null; cat /etc/hostname >/dev/null) >/dev/null 2>&1 & exit 0')
        time.sleep(5.0)
        t['end'] = time.time()
        time.sleep(1.5)
    finally:
        loader.terminate()
        loader.wait(timeout=120)
        raw.close()
        err.close()
    rows = [json.loads(line) for line in (a.out / 'raw.jsonl').read_text().splitlines()]
    grams = [r for r in rows if r['type'] == 'token_grams' and r['cgroup_id'] == cgid]
    for r in grams:
        check_grams(r['grams'], r['events'])
        check_session(r['session'], r['session_events'], r['grams'])
    snaps = [r for r in rows if r['type'] == 'cgroup_snapshot_extended' and r['cgroup_id'] == cgid]
    first, last = snaps[0], snaps[-1]
    delta = sum(int(v) - int(first['full_counts'].get(k, 0)) for k, v in last['full_counts'].items())
    after_first = sum(r['events'] for r in grams if r['window_end'] > float(first['observed_at']) + 0.25)
    ses = lambda part: sum(r['session_events'] for r in part)
    nat = lambda part: sum(r['events'] - r['session_events'] for r in part)
    A = span(grams, t['attached'] + MARGIN, t['b0'] - MARGIN)
    B = span(grams, t['b0'] - MARGIN, t['b1'] + MARGIN)
    C = span(grams, t['b1'] + MARGIN + 0.5, t['d0'] - MARGIN)
    D = span(grams, t['d1'] + MARGIN, t['d1'] + 2.5)
    E = span(grams, t['d1'] + 3.5, t['end'])
    execve_in_session = any((g[3] >> 23) == NR_EXECVE for r in B for g in r['session'])
    execve_native = any((g[3] >> 23) == NR_EXECVE for r in A for g in r['grams'])     # A has no session event (checked below)
    checks = dict(
        native_only_before_exec=len(A) > 0 and ses(A) == 0 and nat(A) > 0,
        native_children_execve=execve_native,
        exec_is_session=ses(B) > 0 and execve_in_session,
        own_loop_stays_native_during_exec=nat(B) > 0,
        native_only_between=len(C) > 0 and ses(C) == 0 and nat(C) > 0,
        orphan_keeps_session_lineage=ses(D) > 0,
        native_only_at_the_end=len(E) > 0 and ses(E) == 0 and nat(E) > 0,
        one_token_per_syscall=after_first == delta)
    out = dict(schema='pulse-lineage-proof-v1', protocol='sentinel_pulse/protocol/ml-final-study-v1-amendment-2.json',
               valid=all(checks.values()), checks=checks, cgroup_id=cgid, cgroup_path=str(cg), times=t,
               phases={k: dict(windows=len(v), native_events=nat(v), session_events=ses(v))
                       for k, v in (('A', A), ('B', B), ('C', C), ('D', D), ('E', E))},
               token_events_after_first_snapshot=after_first, full_count_delta=delta)
    (a.out / 'RESULTS.json').write_text(json.dumps(out, indent=2, sort_keys=True) + '\n')
    print(json.dumps(dict(valid=out['valid'], checks=checks, phases=out['phases'])))
    sys.exit(0 if out['valid'] else 1)


if __name__ == '__main__':
    main()
