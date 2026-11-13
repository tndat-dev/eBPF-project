#!/usr/bin/env python3
"""Driver for protocol pulse-live-lidds-v1: run LID-DS 2021 scenarios on Kubernetes under the Pulse token probe.

Each scenario has a long-lived victim Deployment (one replica, name ``victim-<slug>``) in the ``lidds-live`` namespace;
the Pulse resolver watches it, so the victim's syscalls are scored by the token pipeline exactly as a production
workload. Normal traffic and the exploit reach the victim over the network from throwaway pods labelled ``lidds-gen`` /
``lidds-atk``, which the resolver excludes (EXCLUDED_MARKERS): the exploit is seen through the victim's own process
tree, as in the dataset.

A cycle (protocol): recreate the victim pod, wait until Ready, warm up, then a recording span during which
``user_count`` normal users send requests at wait times sampled from the scenario's own clients. In a live cycle the
exploit runs once at a time drawn in [0.3, 0.8] of the recording span. Every cycle is written to ``schedule.jsonl``
with its victim pod uid and, for exploit cycles, the exploit time; nothing here reads the worker's output.

    driver.py capture --scenarios-file scenarios.json --run-dir DIR --duration 43200 [--only a,b] [--seed N]
    driver.py live    --scenarios-file scenarios.json --run-dir DIR --duration 43200 [--only a,b] [--seed N]

Only ``capture`` and ``live`` differ: capture runs normal cycles only; live makes each cycle an exploit cycle with
probability 0.5 (seeded). Run ``capture`` first, fit the models (see README), then ``live``.
"""
import argparse
import json
import random
import re
import subprocess
from shlex import quote
import time
from pathlib import Path

NS = "lidds-live"
WARMUP = 30.0
RECORDING = 150.0
POLL = 2.0


def slug(name):
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")


def kubectl(*args, check=True, inp=None, timeout=120):
    return subprocess.run(["kubectl", "-n", NS, *args], capture_output=True, text=True,
                          check=check, input=inp, timeout=timeout)


def apply(doc):
    kubectl("apply", "-f", "-", inp=json.dumps(doc))


def victim_name(scn):
    return f"victim-{slug(scn)}"


def victim_deployment(scn, spec):
    v = spec["victim"]
    name = victim_name(scn)
    port = int(v["port"])
    probe = ({"tcpSocket": {"port": port}} if v["ready"]["type"] == "tcp"
             else {"httpGet": {"path": v["ready"].get("path", "/"), "port": port}})
    return {
        "apiVersion": "apps/v1", "kind": "Deployment",
        "metadata": {"name": name, "namespace": NS, "labels": {"lidds": "victim", "app": name}},
        "spec": {"replicas": 1, "selector": {"matchLabels": {"app": name}},
                 "template": {"metadata": {"labels": {"app": name, "lidds": "victim"}},
                              "spec": {"terminationGracePeriodSeconds": 2, "automountServiceAccountToken": False,
                                       "containers": [{"name": "victim", "image": v["image"], "imagePullPolicy": "Never",
                                                       "ports": [{"containerPort": port}],
                                                       "readinessProbe": dict(probe, initialDelaySeconds=3, periodSeconds=3,
                                                                              failureThreshold=40)}]}}}}


def runner_pod(name, image, entrypoint, argstr, label, victim_ip, mode, waits=None):
    """A throwaway pod that drives the victim over the network. restartPolicy Never.

    normal: the generic generator image runs the scenario's request once per sampled wait time.
    stdin:  the dataset exploit image, stdin-driven, fed one blank line.
    exec:   the dataset exploit image runs one command (its entrypoint is a sleep loop in the dataset).
    chain:  the dataset exploit image runs several commands in order.
    """
    sub = lambda t: t.replace("${victim}", victim_ip)
    if mode == "normal":
        req = sub(argstr)
        steps = " ".join(f"sleep {w:.3f}; sh -c {quote(req)};" for w in waits)
        command = f"set +e; {steps} true"
    elif mode == "stdin":
        command = "echo | exec " + " ".join(entrypoint) + (" " + sub(argstr) if argstr else "")
    elif mode == "exec":
        command = sub(argstr)                                   # a full command, not entry+args
    elif mode == "chain":
        command = "; ".join(sub(c) for c in argstr)
    else:
        raise ValueError(mode)
    return {"apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": name, "namespace": NS, "labels": {"lidds": label, "app": name}},
            "spec": {"restartPolicy": "Never", "terminationGracePeriodSeconds": 1, "automountServiceAccountToken": False,
                     "containers": [{"name": "run", "image": image, "imagePullPolicy": "Never",
                                     "command": ["/bin/sh", "-c", command]}]}}


def victim_ready(scn):
    name = victim_name(scn)
    try:
        kubectl("rollout", "status", f"deployment/{name}", "--timeout=180s", timeout=200)
    except subprocess.CalledProcessError:
        return None
    pod = kubectl("get", "pods", "-l", f"app={name}", "--field-selector=status.phase=Running",
                  "-o", "jsonpath={.items[0].metadata.uid} {.items[0].status.podIP} {.items[0].metadata.name}", check=False)
    parts = pod.stdout.split()
    return parts if len(parts) == 3 else None


def wait_times(users, length, rng):
    """Per user, a list of inter-arrival gaps over the recording span (uniform count, exponential-ish spacing)."""
    out = []
    for _ in range(users):
        n = rng.randint(max(2, length // 20), max(3, length // 4))
        gaps = sorted(rng.uniform(0, length) for _ in range(n))
        out.append([round(b - a, 3) for a, b in zip([0.0] + gaps, gaps)])
    return out


def run_cycle(scn, spec, rng, is_exploit, schedule, cid, gen_image):
    apply(victim_deployment(scn, spec))
    kubectl("rollout", "restart", f"deployment/{victim_name(scn)}", check=False)
    ready = victim_ready(scn)
    if not ready:
        schedule.write(json.dumps(dict(scenario=scn, cycle=cid, skipped="victim not ready")) + "\n")
        schedule.flush()
        return
    uid, ip, pod = ready
    time.sleep(WARMUP)
    rec_start = time.time()
    users = rng.randint(*spec["normal"]["users"])
    wts = wait_times(users, int(RECORDING), rng)
    pods = []
    for i, w in enumerate(wts):
        pname = f"lidds-gen-{slug(scn)}-{cid}-{i}"
        apply(runner_pod(pname, gen_image, [], spec["normal"]["request"],
                         "lidds-gen", ip, "normal", w or [1.0]))
        pods.append(pname)
    exploit_time = None
    if is_exploit:
        exploit_time = rec_start + rng.uniform(0.3 * RECORDING, 0.8 * RECORDING)
    row = dict(scenario=scn, cycle=cid, is_exploit=bool(is_exploit), victim_uid=uid, victim_pod=pod, victim_ip=ip,
               recording_start=rec_start, recording_seconds=RECORDING, warmup_seconds=WARMUP, users=users)
    e = spec["exploit"]
    while time.time() < rec_start + RECORDING:
        if exploit_time and time.time() >= exploit_time and "exploit_launched" not in row:
            ename = f"lidds-atk-{slug(scn)}-{cid}"
            payload = e.get("commands") if e["kind"] in ("exec", "chain") else e.get("args", "")
            apply(runner_pod(ename, e["image"], e.get("entrypoint", []),
                             payload[0] if e["kind"] == "exec" else payload, "lidds-atk", ip, e["kind"]))
            row["exploit_time"] = time.time()
            row["exploit_launched"] = ename
            pods.append(ename)
        time.sleep(POLL)
    schedule.write(json.dumps(row) + "\n")
    schedule.flush()
    for p in pods:
        kubectl("delete", "pod", p, "--grace-period=1", "--wait=false", check=False)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("phase", choices=["capture", "live"])
    ap.add_argument("--scenarios-file", type=Path, required=True)
    ap.add_argument("--run-dir", type=Path, required=True)
    ap.add_argument("--duration", type=float, required=True, help="seconds to run cycles for")
    ap.add_argument("--only", help="comma-separated scenario names")
    ap.add_argument("--seed", type=int, default=20261113)
    a = ap.parse_args()
    cfg = json.loads(a.scenarios_file.read_text())
    gen_image = cfg.get("_generator_image", "lidds-gen:latest")
    scns = [s for s in cfg if not s.startswith("_")]
    if a.only:
        scns = [s for s in scns if s in a.only.split(",")]
    a.run_dir.mkdir(parents=True, exist_ok=True)
    rng = random.Random(a.seed)
    schedule = (a.run_dir / f"schedule-{a.phase}.jsonl").open("a")
    (a.run_dir / f"START-{a.phase}.json").write_text(json.dumps(
        dict(phase=a.phase, scenarios=scns, seed=a.seed, started_at=time.time(), warmup=WARMUP, recording=RECORDING), indent=1))
    end = time.time() + a.duration
    cid = 0
    while time.time() < end:
        scn = scns[cid % len(scns)]
        is_exploit = a.phase == "live" and rng.random() < 0.5
        try:
            run_cycle(scn, cfg[scn], rng, is_exploit, schedule, cid, gen_image)
        except Exception as exc:                                # a scenario failure must not stop the run
            schedule.write(json.dumps(dict(scenario=scn, cycle=cid, error=str(exc))) + "\n")
            schedule.flush()
        cid += 1
    schedule.close()
    print(f"{a.phase} done: {cid} cycles")


if __name__ == "__main__":
    main()
