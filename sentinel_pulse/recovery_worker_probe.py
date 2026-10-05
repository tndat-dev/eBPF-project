"""Root worker adapter for the separate preregistered recovery lifecycle.

Commands never grant PASS or touch production pods/control collectors.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time

from .integrity import sha256_file
from .recovery_formal import validate_marker, validate_worker_start, write_new, evaluate_node, validate_collector_timing
from .inspect_recovery_tail import inspect
from .recovery_deployment import render_unit
from .select_projected_collector import select, key
from .finalize_candidate import verify_model_bundle
from .telemetry_recovery import digest

COLLECTOR = "sentinel-pulse-collector-500ms-experiment.service"
DETECTOR = "sentinel-pulse-detector-candidate.service"
PREREG = Path("/var/lib/sentinel-pulse-recovery-formal")
CAPTURES = Path("/var/lib/sentinel-pulse-500ms/runs")


def service(name):
    result = subprocess.run(["systemctl", "show", name, "-p", "ActiveState", "-p", "Result",
                             "-p", "NRestarts", "-p", "ExecMainStatus"],
                            text=True, capture_output=True, check=True, timeout=5)
    return dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)


def environment(path):
    # Read values as data: never shell-source an operator-controlled file.
    return dict(line.split("=", 1) for line in path.read_text().splitlines()
                if line and not line.startswith("#") and "=" in line)


def clean_source(source):
    args = ["git", "-c", "safe.directory=" + str(source), "-C", str(source)]
    if subprocess.check_output(args + ["status", "--porcelain", "--untracked-files=all"], text=True).strip():
        raise ValueError("worker source is dirty")
    commit = subprocess.check_output(args + ["rev-parse", "HEAD"], text=True).strip()
    names = subprocess.check_output(args + ["ls-files", "sentinel_pulse"], text=True).splitlines()
    return commit, {name: sha256_file(source / name) for name in names}


def preflight(source, model, policy, safety):
    from .decision_policy import load_decision_policy
    commit, files = clean_source(source)
    manifest, candidates, collect_only = verify_model_bundle(model)
    if collect_only:
        raise ValueError("incomplete frozen model bundle")
    load_decision_policy(policy)
    for name in ("sentinel-pulse-collector.service", "sentinel-pulse-resolver.service"):
        if service(name)["ActiveState"] != "active":
            raise ValueError("control service is not active: " + name)
    for name in (COLLECTOR, DETECTOR):
        if service(name)["ActiveState"] != "inactive":
            raise ValueError("another experiment owns service: " + name)
    chosen = select(safety, model / "manifest.json", Path("/run/sentinel-pulse/cgroups.json"))
    metadata = json.loads(Path("/run/sentinel-pulse/cgroups.json").read_text())["cgroups"]
    workloads = sorted({key(v) for v in metadata.values()} & set(candidates))
    return {"node_name": socket.gethostname(), "source_commit": commit,
            "source_files_sha256": digest(files), "expected_workloads": workloads,
            "loader_sha256": chosen["loader_sha256"], "bpf_object_sha256": chosen["bpf_object_sha256"],
            "model_manifest_sha256": sha256_file(model / "manifest.json"),
            "decision_policy_sha256": sha256_file(policy), "checked_at_unix": time.time()}


def parent_unit(run_id):
    return "sentinel-pulse-recovery-worker-" + run_id + ".service"


def stage(source, model, policy, safety, host, marker, raw):
    validate_marker(marker)
    run_id = marker["run_id"]
    if marker["workers"][host]["node_name"] != socket.gethostname():
        raise ValueError("hostname differs from preregistration")
    info = preflight(source, model, policy, safety)
    for name in ("source_commit", "source_files_sha256", "model_manifest_sha256", "decision_policy_sha256"):
        if info[name] != marker[name]:
            raise ValueError("prelaunch identity drift: " + name)
    for name in ("node_name", "expected_workloads", "loader_sha256", "bpf_object_sha256"):
        if info[name] != marker["workers"][host][name]:
            raise ValueError("prelaunch worker binding drift: " + name)
    # All validation above precedes any write or service start.
    if (CAPTURES / run_id).exists():
        raise ValueError("run already exists")
    root = PREREG / run_id
    root.mkdir(mode=0o750, parents=True, exist_ok=False)
    with (root / "START.json").open("xb") as stream:
        stream.write(raw)
    (root / "START.json").chmod(0o444)
    command = ["systemd-run", "--quiet", "--unit=" + parent_unit(run_id),
               "--property=Restart=no", "--property=TimeoutStopSec=30",
               "--property=RuntimeMaxSec=" + str(marker["collector_duration_seconds"] + 150),
               "/usr/bin/env", "PYTHONDONTWRITEBYTECODE=1", "SOURCE_ROOT=" + str(source),
               "MODEL_SOURCE=" + str(model), "DECISION_POLICY_SOURCE=" + str(policy),
               "PROJECTED_CANARY_RUN_DIR=" + str(safety), "RUN_ID=" + run_id, "WORKER_IP=" + host,
               "/bin/bash", str(source / "sentinel_pulse/run_recovery_formal_worker.sh")]
    subprocess.run(command, check=True, timeout=10, capture_output=True)
    return {"launched": True, "run_id": run_id, "worker_ip": host,
            "marker_sha256": sha256_file(root / "START.json"), "unit": parent_unit(run_id)}


def check_runtime(source, root, marker, host):
    start = json.loads((root / "START.json").read_text())
    env = environment(Path("/etc/sentinel-pulse/500ms-experiment.env"))
    prefix = Path("/opt/sentinel-pulse/experiments") / marker["run_id"]
    if env.get("PULSE_500MS_RUN_ID") != marker["run_id"] or env.get("PULSE_500MS_COLLECTOR_VARIANT") != "projected":
        raise ValueError("live collector ownership drift")
    for name, filename in (("loader", "pulse_counter_projected_loader"), ("bpf_object", "pulse_counter_projected.bpf.o")):
        path = prefix / filename
        if (env.get("PULSE_500MS_" + name.upper()) != str(path)
                or start.get("collector_" + name) != str(path)
                or sha256_file(path) != marker["workers"][host][name + "_sha256"]):
            raise ValueError("private collector artifact/path drift")
    installed = Path("/etc/systemd/system") / COLLECTOR
    expected = render_unit((source / "sentinel_pulse/systemd" / COLLECTOR).read_text(), "collector",
                           str(root / "telemetry-recovery-profile.json"))
    unit_sha = hashlib.sha256(expected.encode()).hexdigest()
    if sha256_file(installed) != unit_sha or start["sha256"]["unit"] != unit_sha:
        raise ValueError("live collector unit drift")
    detector_env = environment(Path("/etc/sentinel-pulse-detector-candidate.env"))
    if (detector_env.get("PULSE_RUN_ID") != marker["run_id"]
            or detector_env.get("PULSE_FEATURES") != str(root / "features.jsonl")
            or sha256_file(Path(detector_env["PULSE_MODEL_DIR"]) / "manifest.json") != marker["model_manifest_sha256"]
            or sha256_file(Path(detector_env["PULSE_DECISION_POLICY"])) != marker["decision_policy_sha256"]):
        raise ValueError("live detector model/policy/ownership drift")
    expected = render_unit((source / "sentinel_pulse/systemd" / DETECTOR).read_text(), "detector",
                           detector_env["PULSE_TELEMETRY_RECOVERY_PROFILE"], True)
    if (Path("/etc/systemd/system") / DETECTOR).read_text() != expected:
        raise ValueError("live detector unit drift")
    # Installer copies the complete package. Verify those *executed* bytes,
    # not just the clean checkout used by the supervisor.
    for name, sha in marker["source_files"].items():
        if sha256_file(Path("/opt/sentinel-pulse") / name) != sha:
            raise ValueError("installed runtime source drift: " + name)


def probe(source, host, marker):
    validate_marker(marker)
    root, prereg = CAPTURES / marker["run_id"], PREREG / marker["run_id"]
    result = {"run_id": marker["run_id"], "worker_ip": host,
              "marker_sha256": sha256_file(prereg / "START.json"), "observed_at_unix": time.time()}
    if json.loads((prereg / "START.json").read_text()) != marker:
        raise ValueError("worker registration differs")
    terminal = prereg / "WORKER_TERMINAL.json"
    if terminal.exists():
        receipt = json.loads(terminal.read_text())
        if (receipt.get("schema") != "sentinel-pulse-recovery-formal-worker-terminal-v1"
                or receipt.get("run_id") != marker["run_id"] or receipt.get("worker_ip") != host
                or receipt.get("marker_sha256") != result["marker_sha256"]):
            raise ValueError("terminal worker binding mismatch")
        return {**result, "status": "finished", "collector_exit_status": receipt["exit_code"],
                "detector_restarts": int(service(DETECTOR)["NRestarts"]), "terminal": receipt}
    parent = service(parent_unit(marker["run_id"]))
    if parent["ActiveState"] != "active":
        raise ValueError("worker parent failed without terminal receipt")
    # Startup is explicitly unobservable, NEVER normal. A parent still alive
    # after the registered startup bound cannot hide a failed installation.
    detector = service(DETECTOR)
    if ((root / "FORMAL_WORKER_START.json").exists() and (root / "COLLECTOR_RUNTIME_START.json").exists()
            and detector["ActiveState"] == "inactive"):
        collector = service(COLLECTOR)
        started = validate_collector_timing(root, prereg / "START.json", host)
        if (collector["ActiveState"] == "inactive" and collector["Result"] == "success"
                and collector["ExecMainStatus"] == "0" and detector["Result"] == "success"
                and detector["NRestarts"] == "0"
                and time.time() >= started + marker["collector_duration_seconds"] - 2):
            validate_worker_start(root, prereg / "START.json", host)
            check_runtime(source, root, marker, host)
            # Parent cleanup stops the detector BEFORE copying/sealing raw
            # files and writing its terminal receipt. That short, verified
            # transition is unknown/bounded, not a failed startup or PASS.
            return {**result, "status": "unavailable", "reason": "worker_sealing"}
    if not (root / "FORMAL_WORKER_START.json").exists() or detector["ActiveState"] != "active":
        if time.time() <= marker["started_at_unix"] + 120:
            return {**result, "status": "unavailable", "reason": "worker_installing"}
        raise ValueError("worker did not complete startup within 120 seconds")
    validate_worker_start(root, prereg / "START.json", host)
    check_runtime(source, root, marker, host)
    return {**result, "status": "active", "detector_active": True,
            "detector_restarts": int(service(DETECTOR)["NRestarts"]),
            "capture_tail": inspect(root / "features.jsonl", marker["telemetry_recovery_contract"]["profile"])}


def stop_owned(marker, host):
    """Stop only the unique parent AFTER its immutable marker proves ownership."""
    path = PREREG / marker["run_id"] / "START.json"
    if not path.exists():
        return {"stopped": False, "reason": "no_registered_parent"}
    if json.loads(path.read_text()) != marker or host not in marker["workers"]:
        raise ValueError("refusing to stop a differently registered run")
    terminal = path.with_name("WORKER_TERMINAL.json")
    if terminal.exists():
        receipt = json.loads(terminal.read_text())
        if (receipt.get("schema") != "sentinel-pulse-recovery-formal-worker-terminal-v1"
                or receipt.get("run_id") != marker["run_id"] or receipt.get("worker_ip") != host
                or receipt.get("marker_sha256") != sha256_file(path)
                or type(receipt.get("exit_code")) is not int):
            raise ValueError("invalid terminal ownership receipt")
        return {"stopped": False, "reason": "worker_already_terminal"}
    subprocess.run(["systemctl", "stop", parent_unit(marker["run_id"])], check=True, timeout=40,
                   capture_output=True)
    return {"stopped": True, "unit": parent_unit(marker["run_id"])}


def finalize(model, host, marker, payload):
    prereg, root = PREREG / marker["run_id"], CAPTURES / marker["run_id"]
    if json.loads((prereg / "START.json").read_text()) != marker:
        raise ValueError("final marker drift")
    terminal = json.loads((prereg / "WORKER_TERMINAL.json").read_text())
    if terminal.get("exit_code") != 0:
        raise ValueError("worker ended abnormally")
    # Seal verification must succeed BEFORE reading any finalized raw stream.
    subprocess.run(["sha256sum", "--check", "--strict", "FORMAL_WORKER_SHA256SUMS"], cwd=root,
                   check=True, capture_output=True, timeout=900)
    verify_model_bundle(model)
    health = prereg / "dependency-health.jsonl"
    with health.open("x") as stream:
        stream.write(payload["health_journal"])
    health.chmod(0o444)
    result = evaluate_node(root, prereg / "START.json", host, model / "manifest.json", health)
    write_new(prereg / "NODE_REPORT.json", result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["preflight", "stage", "probe", "stop", "finalize"])
    for name in ("source", "model", "policy", "safety"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--worker-ip", required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise ValueError("root worker adapter required")
    if args.command == "preflight":
        result = preflight(args.source, args.model, args.policy, args.safety)
    else:
        payload = json.load(sys.stdin)
        marker = validate_marker(payload["marker"])
        if args.command == "stage":
            # Coordinator transports the exact START bytes, not a reserialization.
            import base64
            raw = base64.b64decode(payload["marker_bytes"], validate=True)
            if json.loads(raw) != marker:
                raise ValueError("marker payload and raw bytes differ")
            result = stage(args.source, args.model, args.policy, args.safety, args.worker_ip, marker, raw)
        elif args.command == "probe":
            try:
                result = probe(args.source, args.worker_ip, marker)
            except (ValueError, KeyError, OSError, subprocess.SubprocessError) as error:
                # A known integrity failure is NOT a connectivity timeout.
                result = {"status": "invalid", "run_id": marker["run_id"],
                          "reason": str(error), "worker_ip": args.worker_ip}
        elif args.command == "stop":
            result = stop_owned(marker, args.worker_ip)
        else:
            result = finalize(args.model, args.worker_ip, marker, payload)
    print(json.dumps(result, sort_keys=True, allow_nan=False))


if __name__ == "__main__":
    main()
