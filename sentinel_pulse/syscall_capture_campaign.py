"""Durable, separate AIMS full-ID collection; never interrupts a normal soak.

Selection and held-out frequency captures are sealed separately. Histograms
alone are NOT compatible inputs for the frozen 249-dimensional C2 model.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import time

from .syscall_histogram_pilot import atomic_json, append_jsonl

WORKERS = {"10.1.16.237": "k8s-worker1.local", "10.1.16.238": "k8s-worker4.local",
           "10.1.16.239": "k8s-worker3.local"}
REGIMES = ("steady", "toolmix", "peak", "burst", "recovery")
GENERATORS = tuple("aims-sentinel-" + x for x in
                   ("loadgen", "ingress-loadgen", "readmix-loadgen", "dependency-loadgen"))
SOURCE = "/home/dat/pulse-syscall-capture-c3/source"
REMOTE_ROOT = "/var/lib/pulse-syscall-capture-c3"
SOAK_ROOT = "/var/lib/sentinel-pulse-normal-normal-a1-20261013/capture"


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def soak_complete(state):
    terminal = state.get("terminal") or {}
    return (terminal.get("state") == "completed_observation"
            and terminal.get("boundary_observation_seconds", 0) >= 86400
            and not state.get("active_capture_processes"))


def phases():
    return [(split, regime) for split in ("selection", "holdout") for regime in REGIMES]


class Remote:
    def __init__(self, credential):
        self.credential = Path(credential)
        if self.credential.stat().st_mode & 0o077:
            raise ValueError("credential must be private")
        self.password = self.credential.read_text().rstrip("\n")
        if not self.password or "\n" in self.password:
            raise ValueError("invalid credential")

    def command(self, host, argv, payload=None, timeout=25):
        command = ["sshpass", "-f", str(self.credential), "ssh", "-o", "ConnectTimeout=8",
                   "-o", "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile=/home/dat/.ssh/known_hosts",
                   "-o", "ServerAliveInterval=5", "-o", "ServerAliveCountMax=2", "dat@" + host,
                   "sudo -S -p '' " + shlex.join(argv)]
        result = subprocess.run(command, input=self.password + "\n" + (payload or ""),
                                text=True, capture_output=True, timeout=timeout)
        if result.returncode:
            # Do not echo stdout/stderr from credential-bearing transports.
            raise RuntimeError(f"remote command failed: {host}, exit {result.returncode}")
        return result.stdout

    def inspect(self, host, run=None):
        script = '''import json,time,subprocess
from pathlib import Path
root=Path(%r)
def read(p):
 return json.loads(p.read_text()) if p.exists() else None
processes=subprocess.check_output(['ps','-eo','args='],text=True).splitlines()
active=[p for p in processes if ' -m sentinel_pulse.extended_collection ' in p and not 'python3 -c' in p]
out=dict(now=time.time(),terminal=read(root/'TERMINAL.json'),status=read(root/'STATUS.json'),active_capture_processes=active)
run=%r
if run:
 target=Path(%r)/run
 unit='pulse-syscall-c3-'+run
 out.update(run_terminal=read(target/'TERMINAL.json'),run_exists=target.exists(),
  unit_state=subprocess.run(['systemctl','is-active',unit],text=True,capture_output=True).stdout.strip())
print(json.dumps(out))
''' % (SOAK_ROOT, run, REMOTE_ROOT)
        return json.loads(self.command(host, ["python3", "-c", script]))

    def launch(self, host, run, receipt, source_commit):
        if not soak_complete(self.inspect(host)):
            raise RuntimeError("protected capture is still active")
        space_check = """import os
from pathlib import Path
p=Path(%r);p.mkdir(parents=True,exist_ok=True)
s=os.statvfs(p)
assert s.f_bavail*s.f_frsize > 4*1024**3, 'insufficient capture space'
assert sum(f.stat().st_size for f in p.rglob('*') if f.is_file()) < 4*1024**3, 'campaign storage budget reached; retain artifacts'
""" % REMOTE_ROOT
        self.command(host, ["python3", "-c", space_check])
        receipt_path = f"/home/dat/pulse-syscall-capture-c3/{run}.json"
        script = "import json,sys; from pathlib import Path; p=Path(sys.argv[1]); p.open('x').write(sys.stdin.read())"
        self.command(host, ["python3", "-c", script, receipt_path], json.dumps(receipt))
        self.command(host, ["systemd-run", "--unit=pulse-syscall-c3-" + run,
            "--property=RuntimeMaxSec=1500", "--property=CPUQuota=100%",
            "--property=MemoryMax=512M", "--property=Nice=15", "--property=TasksMax=32",
            "env", "PYTHONPATH=" + SOURCE, "/opt/sentinel-pulse/runtime-venv/bin/python",
            "-m", "sentinel_pulse.syscall_histogram_pilot",
            "--run-id", run, "--source-commit", source_commit,
            "--loader", SOURCE + "/build/syscall_histogram_loader",
            "--object", SOURCE + "/build/syscall_histogram.bpf.o",
            "--feature-loader", SOURCE + "/sentinel_pulse/ebpf/pulse_counter_projected_loader",
            "--feature-object", SOURCE + "/sentinel_pulse/ebpf/pulse_counter_projected.bpf.o",
            "--traffic-receipt", receipt_path, "--output", REMOTE_ROOT + "/" + run,
            "--owner-uid", "1000", "--owner-gid", "1000"])

    def copy(self, host, run, destination):
        # Stream only this experiment directory; no production capture copies.
        raw = self.command(host, ["python3", "-c",
            "import json;from pathlib import Path; p=Path(" + repr(REMOTE_ROOT + '/' + run) + ");"
            "print(json.dumps([f.name for f in p.iterdir() if f.is_file()]))"])
        allowed = {"START.json", "TERMINAL.json", "SHA256SUMS", "traffic-receipt.json",
                   "histogram.jsonl", "host-metrics.jsonl", "metadata-snapshots.jsonl", "loader.log",
                   "feature-raw.jsonl", "features.jsonl", "feature-loader.log", "FEATURE_CAPTURE.json"}
        names = json.loads(raw)
        if not set(names) <= allowed:
            raise ValueError("unexpected remote artifact")
        destination.mkdir(parents=True, exist_ok=True)
        for name in names:
            target = destination / name
            if target.exists():
                continue  # completed copies only; interrupted copies retain .partial
            command = ["sshpass", "-f", str(self.credential), "scp", "-q",
                "-o", "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile=/home/dat/.ssh/known_hosts",
                f"dat@{host}:{REMOTE_ROOT}/{run}/{name}", str(target) + ".partial"]
            subprocess.run(command, check=True, timeout=180, capture_output=True)
            os.replace(str(target) + ".partial", target)


def snapshot():
    command = ["kubectl", "--kubeconfig=/home/dat/.kube/config", "--request-timeout=15s"]
    def get(args):
        return json.loads(subprocess.check_output(command + args + ["-o", "json"], timeout=20))
    nodes = get(["get", "nodes"])
    deployments = get(["-n", "production", "get", "deploy", *GENERATORS])
    return {"at_unix": time.time(), "nodes": nodes, "deployments": deployments}


def healthy(snap):
    for node in snap["nodes"]["items"]:
        conditions = {c["type"]: c["status"] for c in node["status"]["conditions"]}
        if conditions.get("Ready") != "True" or any(conditions.get(k) != "False" for k in
                                                    ("DiskPressure", "MemoryPressure", "PIDPressure")):
            return False
    for item in snap["deployments"]["items"]:
        desired = item["spec"].get("replicas", 1)
        status = item.get("status", {})
        if (status.get("observedGeneration", 0) < item["metadata"]["generation"]
                or status.get("readyReplicas", 0) != desired
                or status.get("updatedReplicas", 0) != desired):
            return False
    return len(snap["nodes"]["items"]) == 6 and len(snap["deployments"]["items"]) == 4


def set_regime(source, regime, log):
    env = {**os.environ, "KUBECONFIG": "/home/dat/.kube/config", "NAMESPACE": "production"}
    with log.open("a") as stream:
        subprocess.run(["bash", str(source / "ml-service/set_aims_traffic_regime.sh"), regime],
                       env=env, stdout=stream, stderr=stream, check=True, timeout=600)


def run(args):
    root, source = args.root, args.source
    root.mkdir(parents=True, exist_ok=True)
    lock = (root / "campaign.lock").open("a")
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    remote = Remote(args.credential)
    start_path = root / "START.json"
    contract = dict(schema="pulse-syscall-multiregime-campaign-v1", source_commit=args.source_commit,
        controller_sha256=digest(__file__), traffic_script_sha256=digest(source / "ml-service/set_aims_traffic_regime.sh"),
        protected_soak=SOAK_ROOT, phases=phases(), workers=WORKERS, baseline_seconds=300,
        probe_seconds=600, post_seconds=300, histogram_interval_ms=1000, feature_interval_ms=500,
        feature_schema="sentinel-pulse-feature-v1", feature_rolling_windows=5,
        holdout_not_for_selection=True,
        attack_injection=False, frozen_models_modified=False,
        evidence_scope="full-ID frequency and legacy 249-dim normal features; blind evaluation registered separately")
    if start_path.exists():
        if json.loads(start_path.read_text())["contract"] != json.loads(json.dumps(contract)):
            raise ValueError("campaign code/config changed; use a new campaign")
    else:
        atomic_json(start_path, dict(registered_at_unix=time.time(), contract=contract))
    state_path = root / "STATUS.json"
    state = json.loads(state_path.read_text()) if state_path.exists() else dict(completed=[], attempts={}, active=None)
    if (root / "TERMINAL.json").exists():
        return
    def save(phase, **kwargs):
        state.update(state=phase, updated_at_unix=time.time(), **kwargs)
        atomic_json(state_path, state)
    while len(state["completed"]) < len(phases()):
        # This also protects against a new concurrent extended capture.
        with ThreadPoolExecutor(max_workers=3) as pool:
            observations = dict(zip(WORKERS, pool.map(remote.inspect, WORKERS)))
        if not all(soak_complete(s) for s in observations.values()):
            save("waiting_for_existing_soak", protected_soak_status=observations)
            time.sleep(60)
            continue
        if not state["active"]:
            snap = snapshot()
            if not healthy(snap):
                save("waiting_for_cluster_health")
                append_jsonl(root / "health-events.jsonl", snap)
                time.sleep(60)
                continue
            split, regime = phases()[len(state["completed"])]
            key = split + "-" + regime
            attempt = state["attempts"].get(key, 0) + 1
            state["attempts"][key] = attempt
            # Record intent before mutation/launch, so reboot cannot overwrite evidence.
            active = dict(key=key, split=split, regime=regime, attempt=attempt, runs={}, phase="preparing")
            save("preparing_traffic", active=active)
            set_regime(source, regime, root / "traffic-controller.log")
            snap = snapshot()
            if not healthy(snap):
                raise RuntimeError("traffic rollout not yet healthy")
            atomic_json(root / f"{key}-{attempt}-traffic.json", snap)
            now = time.time()
            for host, node in WORKERS.items():
                run_id = f"{key}-{attempt:03d}-{host.rsplit('.', 1)[-1]}"
                receipt = dict(schema="sentinel-pulse-traffic-receipt-v1", receipt_id=run_id,
                    node_name=node, registered_at_unix=now,
                    schedule=[dict(start_unix=now, end_unix=now + 1500, regime=regime)],
                    split=split, campaign_start_sha256=digest(start_path),
                    traffic_evidence_sha256=digest(root / f"{key}-{attempt}-traffic.json"))
                active["runs"][host] = run_id
                save("launching", active=active)
                remote.launch(host, run_id, receipt, args.source_commit)
            active["phase"] = "collecting"
            save("collecting", active=active)
        active = state["active"]
        statuses = {host: remote.inspect(host, run_id) for host, run_id in active["runs"].items()}
        if any(s.get("unit_state") in ("active", "activating", "deactivating") for s in statuses.values()):
            append_jsonl(root / "health-events.jsonl", snapshot())
            save("collecting", worker_status=statuses)
            time.sleep(30)
            continue
        # Interrupted attempts remain on disk. Never relabel them successful.
        complete = len(statuses) == 3 and all((s.get("run_terminal") or {}).get("state") == "completed"
                                            for s in statuses.values())
        if complete:
            from .syscall_histogram_analysis import summarize
            analyses = []
            for host, run_id in active["runs"].items():
                destination = root / active["split"] / run_id
                remote.copy(host, run_id, destination)
                analysis = summarize(destination)
                atomic_json(destination / "ANALYSIS.json", analysis)
                analyses.append(analysis)
            complete = all(x["capture_valid_for_feature_selection"] for x in analyses)
        append_jsonl(root / "attempts.jsonl", dict(at_unix=time.time(), attempt=active, accepted=complete,
                                                 worker_status=statuses))
        if complete:
            state["completed"].append(active["key"])
        set_regime(source, "steady", root / "traffic-controller.log")
        save("between_phases", active=None)
        if not complete:
            time.sleep(60)
    # Do NOT inspect/rank the held-out frequency distribution here.
    from .syscall_histogram_cohort import aggregate
    atomic_json(root / "SELECTION_COHORT.json", aggregate(sorted((root / "selection").glob("*/"))))
    atomic_json(root / "TERMINAL.json", dict(state="completed_frequency_collection", completed=state["completed"],
        finished_at_unix=time.time(), start_sha256=digest(start_path),
        holdout_sealed_not_ranked=True, blind_evaluation_complete=False, automatic_promotion=False))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for field in ("root", "source", "credential"):
        p.add_argument("--" + field, type=Path, required=True)
    p.add_argument("--source-commit", required=True)
    p.add_argument("--inspect-only", action="store_true")
    args = p.parse_args()
    if args.inspect_only:
        remote = Remote(args.credential)
        with ThreadPoolExecutor(max_workers=3) as pool:
            result = dict(zip(WORKERS, pool.map(remote.inspect, WORKERS)))
        print(json.dumps(result, indent=2))
        return
    run(args)


if __name__ == "__main__":
    main()
