#!/usr/bin/env python3
"""improvement-round-v1 D1 on one worker, as root: does a full gram map turn into an alert on the cgroup that filled it?

Two new cgroups are watched by a token loader: one runs testbed/bench/gram_stress at the given rate (every call a new
4-gram: map-capacity-v1 measured losses from 400,000 calls/s), the other a light loop (sleep 0.01 in sh). The loader's
lines are cut into frames at snapshot_end and every frame goes through collector/token_capture.MapOverflow exactly as the
worker does. Criterion: the first alert names the stress cgroup and comes within 1 s of the first insert failure; no
alert before any failure.

    python3 map_overflow_test.py --build DIR --out DIR [--rate 400000] [--threads 8] [--seconds 10]
"""
# KIỂM D1 TRÊN WORKER: map gram đầy có thành cảnh báo trên đúng cgroup gây đầy không, và trong bao lâu.
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sentinel_pulse.collector.token_capture import MapOverflow  # noqa: E402


def frames(lines):
    """[(drain record or None, [token_grams rows], snapshot_end observed_at)] in order."""
    out, drain, grams = [], None, []
    for line in lines:
        if line.startswith('{"type":"token_grams"'):
            r = json.loads(line)
            grams.append(dict(cgroup_id=r['cgroup_id'], window_end=r['window_end'], grams=range(len(r['grams']))))
        elif line.startswith('{"type":"token_drain"'):
            drain = json.loads(line)
        elif line.startswith('{"type":"snapshot_end"'):
            out.append((drain, grams, float(json.loads(line)['observed_at'])))
            drain, grams = None, []
    return out


def judge(fr, stress_id):
    """First failure time, first alert (time, cgroup), alerts before a failure."""
    o, first_fail, first_alert, early = MapOverflow(), None, None, 0
    for drain, grams, at in fr:
        heavy, incomplete = o.frame(drain, grams)
        if incomplete and first_fail is None:
            first_fail = at
        if heavy is not None:
            if first_fail is None:
                early += 1
            elif first_alert is None:
                first_alert = (at, grams[heavy]['cgroup_id'])
    return dict(first_failure_at=first_fail, first_alert_at=first_alert[0] if first_alert else None,
                alert_cgroup=first_alert[1] if first_alert else None, stress_cgroup=stress_id,
                delay=(first_alert[0] - first_fail) if first_alert and first_fail else None, alerts_before_failure=early,
                met=bool(first_alert and first_alert[1] == stress_id and first_alert[0] - first_fail <= 1.0 and early == 0))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--build', type=Path, required=True)
    ap.add_argument('--out', type=Path, required=True)
    ap.add_argument('--rate', type=int, default=400000)
    ap.add_argument('--threads', type=int, default=8)
    ap.add_argument('--seconds', type=float, default=10.0)
    a = ap.parse_args()
    if os.geteuid() != 0:
        sys.exit('run as root')
    a.out.mkdir(parents=True, exist_ok=False)
    cgs = [Path('/sys/fs/cgroup/pulse-overflow-stress'), Path('/sys/fs/cgroup/pulse-overflow-quiet')]
    for cg in cgs:
        cg.mkdir(exist_ok=False)
    ids = [os.stat(cg).st_ino for cg in cgs]
    (a.out / 'allowed-cgroup').write_text(''.join(f'{i}\n' for i in ids))
    raw, err = (a.out / 'raw.jsonl').open('w'), (a.out / 'loader.stderr').open('w')
    loader = subprocess.Popen([str(a.build / 'pulse_counter_tokens_loader'), '--object', str(a.build / 'pulse_counter_tokens.bpf.o'),
                               '--allow-cgroup-file', str(a.out / 'allowed-cgroup'), '--interval-ms', '500', '--tokens', 'grams'],
                              stdout=raw, stderr=err)
    quiet = None
    try:
        for _ in range(600):
            if 'sentinel-pulse attached' in (a.out / 'loader.stderr').read_text():
                break
            if loader.poll() is not None:
                sys.exit('loader exited: ' + (a.out / 'loader.stderr').read_text())
            time.sleep(0.1)
        quiet = subprocess.Popen(['sh', '-c', f'echo $$ > {cgs[1]}/cgroup.procs && while :; do sleep 0.01; done'])
        time.sleep(3.0)                                          # quiet frames first: no alert may come before a failure
        t0 = time.time()
        stress = subprocess.run(['sh', '-c', f'echo $$ > {cgs[0]}/cgroup.procs && exec "$@"', 'sh', str(a.build / 'gram_stress'),
                                 str(a.threads), str(max(64, a.rate // a.threads)), str(a.seconds)],
                                capture_output=True, text=True, check=True)
        t1 = time.time()
        time.sleep(3.0)
    finally:
        if quiet is not None:
            quiet.kill()
            quiet.wait()
        loader.terminate()
        loader.wait(timeout=120)
        raw.close()
        err.close()
        time.sleep(0.5)
        for cg in cgs:
            cg.rmdir()
    with (a.out / 'raw.jsonl').open() as stream:
        fr = frames(stream)
    (a.out / 'raw.jsonl').unlink()
    res = judge(fr, ids[0])
    doc = dict(schema='improvement-round-v1-map-overflow', protocol='sentinel_pulse/protocol/improvement-round-v1.json (D1)',
               rate=a.rate, threads=a.threads, seconds=a.seconds, stress_started_at=t0, stress_ended_at=t1,
               gram_stress=json.loads(stress.stdout), frames=len(fr), quiet_cgroup=ids[1], **res)
    (a.out / 'RESULTS.json').write_text(json.dumps(doc, indent=1))
    print(json.dumps(res))


if __name__ == '__main__':
    main()
