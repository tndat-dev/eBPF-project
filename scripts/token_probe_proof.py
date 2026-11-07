#!/usr/bin/env python3
"""Collector proof of the token probe build (make tokens) on one worker, as root, in an isolated cgroup.

The worker refuses a build without a valid proof bound to its kernel and artifact hashes (pipeline/matched_worker.py).
This proof repeats the matched build's checks and adds the token ones:

- seccomp path (as the 15/10 matched proof): the visibility fixture's 20 setns and 20 seccomp calls are counted and
  its 40 skipped-or-emulated calls appear in seccomp_skipped_or_emulated;
- one token per syscall: over the whole run the token events of the cgroup equal its full-ID count delta (every
  call entered in the cgroup gives exactly one token, at entry or at return; all fixture processes have exited);
- token values: syscall_bench openclose / read4k / futex and a cat of /etc/hostname and a missing file give
  openat:w:/tmp, read#12, futex, openat!2 and openat:r:/etc;
- no loss: no gram insert failure and no task-state insert failure.

    python3 token_probe_proof.py --build DIR --proof DIR --source-commit SHA [--token-exit sys_exit|fexit]
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import time

ARTIFACTS = ('pulse_counter_tokens.bpf.o', 'pulse_counter_tokens_loader', 'seccomp_fixture', 'syscall_bench')
NONE = 0xFFFFFFFF


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def fnv_dir(name):
    h = 2166136261
    for c in name.encode():
        h = ((h ^ c) * 16777619) & 0xFFFFFFFF
    h &= 0xFFFFF
    return h - 2 if h >= 0xFFFFE else h


def tok(nr, kind=0, detail=0):
    return (nr << 23) | (kind << 21) | detail


EXPECTED = {'openat:w:/tmp': tok(257, 3, (1 << 20) | fnv_dir('tmp')), 'read#12': tok(0, 2, 12), 'futex': tok(202),
            'openat!2': tok(257, 1, 2), 'openat:r:/etc': tok(257, 3, fnv_dir('etc'))}


def in_cgroup(cg, argv):
    return subprocess.run(['sh', '-c', f'echo $$ > {cg}/cgroup.procs && exec "$@"', 'sh', *argv],
                          capture_output=True, text=True, check=True)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--build', type=Path, required=True)
    ap.add_argument('--proof', type=Path, required=True)
    ap.add_argument('--source-commit', required=True)
    ap.add_argument('--token-exit', choices=('sys_exit', 'fexit'), default='sys_exit')
    a = ap.parse_args()
    if os.geteuid() != 0:
        sys.exit('run as root')
    a.proof.mkdir(parents=True, exist_ok=False)
    cg = Path('/sys/fs/cgroup/pulse-token-proof')
    cg.mkdir(exist_ok=False)
    cgid = os.stat(cg).st_ino
    (a.proof / 'allowed-cgroup').write_text(f'{cgid}\n')
    start = dict(schema='pulse-token-proof-start-v1', artifact_sha256={n: sha(a.build / n) for n in ARTIFACTS},
                 cgroup_id=cgid, cgroup_path=str(cg), isolated_cgroup_only=True, kernel=platform.release(),
                 modifies_production_policies=False, token_exit=a.token_exit, source_commit=a.source_commit, started_at_unix=time.time())
    (a.proof / 'START.json').write_text(json.dumps(start, indent=2, sort_keys=True) + '\n')
    raw = (a.proof / 'raw.jsonl').open('w')
    err = (a.proof / 'loader.stderr').open('w')
    loader = subprocess.Popen([str(a.build / 'pulse_counter_tokens_loader'), '--object', str(a.build / 'pulse_counter_tokens.bpf.o'),
                               '--allow-cgroup-file', str(a.proof / 'allowed-cgroup'), '--interval-ms', '500',
                               '--tokens', 'grams', '--token-exit', a.token_exit], stdout=raw, stderr=err)
    try:
        for _ in range(600):
            if 'sentinel-pulse attached' in (a.proof / 'loader.stderr').read_text():
                break
            if loader.poll() is not None:
                sys.exit('loader exited: ' + (a.proof / 'loader.stderr').read_text())
            time.sleep(0.1)
        time.sleep(1.5)
        fixture = in_cgroup(cg, [str(a.build / 'seccomp_fixture')])
        (a.proof / 'fixture.stdout').write_text(fixture.stdout)
        bench = [json.loads(in_cgroup(cg, [str(a.build / 'syscall_bench'), m, '0.3']).stdout) for m in ('openclose', 'read4k', 'futex')]
        in_cgroup(cg, ['sh', '-c', 'cat /etc/hostname /nonexistent-pulse-token-proof > /dev/null 2>&1; true'])
        time.sleep(2.0)                                 # the last windows close and are drained
    finally:
        loader.terminate()
        loader.wait(timeout=120)
        raw.close()
        err.close()
        cg.rmdir()
    rows = [json.loads(l) for l in (a.proof / 'raw.jsonl').read_text().splitlines()]
    snaps = [r for r in rows if r['type'] == 'cgroup_snapshot_extended' and r['cgroup_id'] == cgid]
    first, last = snaps[0], snaps[-1]
    delta = {k: int(v) - int(first['full_counts'].get(k, 0)) for k, v in last['full_counts'].items()}
    grams = [r for r in rows if r['type'] == 'token_grams' and r['cgroup_id'] == cgid]
    events = sum(r['events'] for r in grams)
    first_obs = float(first['observed_at'])
    events_after_first = sum(r['events'] for r in grams if r['window_end'] > first_obs + 0.25)
    seen = {}
    for r in grams:
        for *g, c in r['grams']:
            seen[g[3]] = seen.get(g[3], 0) + c
    drains = [r for r in rows if r['type'] == 'token_drain']
    stats = {r['name']: r['cumulative'] for r in rows if r['type'] == 'stat'}
    count_delta = sum(delta.values())
    checks = dict(
        seccomp_setns=delta.get('308', 0) == 20, seccomp_seccomp=delta.get('317', 0) == 20,
        seccomp_skipped=int(last['seccomp_skipped_or_emulated']) - int(first['seccomp_skipped_or_emulated']) == 40,
        one_token_per_syscall=events_after_first == count_delta,
        expected_tokens={k: seen.get(v, 0) > 0 for k, v in EXPECTED.items()},
        no_gram_insert_failure=drains[-1]['insert_fail_cumulative'] == 0 if drains else False,
        no_task_state_failure=int(stats.get('task_state_update_fail', 1)) == 0)
    valid = all(v if isinstance(v, bool) else all(v.values()) for v in checks.values())
    results = dict(schema='pulse-token-proof-v1', valid=valid, checks=checks, cgroup_id=cgid,
                   full_count_delta_total=count_delta, token_events_total=events, token_events_after_first_snapshot=events_after_first,
                   full_count_delta=delta, fixture=json.loads(fixture.stdout), bench=bench,
                   expected_token_counts={k: seen.get(v, 0) for k, v in EXPECTED.items()}, last_drain=drains[-1] if drains else None,
                   stats=stats, not_a_model_accuracy_measurement=True)
    (a.proof / 'RESULTS.json').write_text(json.dumps(results, indent=2, sort_keys=True) + '\n')
    print(json.dumps(dict(valid=valid, checks=checks, count_delta=count_delta, token_events=events,
                          token_events_after_first=events_after_first)))
    sys.exit(0 if valid else 1)


if __name__ == '__main__':
    main()
