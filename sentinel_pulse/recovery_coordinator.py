"""Three-worker recovery coordinator; separate from legacy promotion gates.

Stages a NEW immutable marker, monitors bounded parallel SSH/API probes and
streams final evaluation on workers. Diagnostic success can NEVER be formal
PASS. Credentials live in a private local file, not config/marker/unit args.
"""
from __future__ import annotations

import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import fcntl
import gzip
import json
import os
from pathlib import Path
import re
import shlex
import signal
import stat
import subprocess
import time

from .collector_contract import WORKERS
from .integrity import sha256_file
from .operational_soak import bind, classify_health, observe, items
from .storage_health import duplicate_disk_uuids, colocated_running_replicas
from .recovery_formal import register, validate_marker, supervision_step, aggregate, write_new
from .telemetry_recovery import digest

QUERIES = {
    "nodes": ["get", "nodes"], "pods": ["-n", "production", "get", "pods"],
    "volumes": ["-n", "longhorn-system", "get", "volumes.longhorn.io"],
    "cnpg": ["-n", "production", "get", "clusters.postgresql.cnpg.io"],
    "storage_nodes": ["-n", "longhorn-system", "get", "nodes.longhorn.io"],
    "replicas": ["-n", "longhorn-system", "get", "replicas.longhorn.io"],
}


def validate_config(config):
    if config.get("schema") != "sentinel-pulse-recovery-coordinator-config-v1" or set(config.get("workers", {})) != WORKERS:
        raise ValueError("coordinator requires explicit three-worker config")
    if set(config) != {"schema", "workers", "source", "model", "policy"}:
        raise ValueError("unknown config fields (credentials must not be stored here)")
    for cfg in [config, *config["workers"].values()]:
        fields = {"source", "model", "policy"} if cfg is config else {"source", "model", "policy", "safety"}
        if cfg is not config and set(cfg) != fields:
            raise ValueError("unexpected worker config fields")
        for name in fields:
            value = cfg[name]
            if not isinstance(value, str) or not re.fullmatch(r"/[A-Za-z0-9/._-]+", value) or ".." in Path(value).parts:
                raise ValueError("unsafe absolute launch path: " + name)
        if not re.fullmatch(r"/home/dat/[A-Za-z0-9._-]+", cfg["source"]):
            raise ValueError("source must be isolated dat worktree")
        if cfg is not config and not re.fullmatch(r"/var/lib/sentinel-pulse-projection-canary/[A-Za-z0-9._-]+", cfg["safety"]):
            raise ValueError("unsafe collector safety path")
    return config


def secret(path):
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_uid != os.getuid()):
        raise ValueError("credential file must be owned private regular file")
    value = path.read_text().rstrip("\n")
    if not value or "\n" in value or "\r" in value:
        raise ValueError("invalid credential file")
    return value


class Remote:
    def __init__(self, config, password_file):
        self.config = validate_config(config)
        self.password_file = password_file
        self.password = secret(password_file)

    def call(self, host, command, payload=None, timeout=12):
        cfg = self.config["workers"][host]
        args = ["env", "PYTHONDONTWRITEBYTECODE=1", "PYTHONPATH=" + cfg["source"],
                "/opt/sentinel-pulse/runtime-venv/bin/python", "-m", "sentinel_pulse.recovery_worker_probe", command,
                "--source", cfg["source"], "--model", cfg["model"], "--policy", cfg["policy"],
                "--safety", cfg["safety"], "--worker-ip", host]
        transport = ["sshpass", "-f", str(self.password_file), "ssh", "-o", "ConnectTimeout=5",
                     "-o", "StrictHostKeyChecking=yes", "-o", "NumberOfPasswordPrompts=1",
                     "-o", "ServerAliveInterval=3", "-o", "ServerAliveCountMax=2", "dat@" + host,
                     "sudo -S -p '' " + shlex.join(args)]
        body = self.password + "\n" + (json.dumps(payload, allow_nan=False) if payload is not None else "")
        result = subprocess.run(transport, input=body, capture_output=True, text=True, timeout=timeout)
        if result.returncode:
            # Never echo raw SSH stderr/stdout: a remote installer may log env.
            raise RuntimeError("remote " + command + " failed on " + host + " (exit " + str(result.returncode) + ")")
        return json.loads(result.stdout)


def api_snapshot(arguments):
    result = subprocess.run(["kubectl", "--request-timeout=8s", *arguments, "-o", "json"],
                            check=True, text=True, capture_output=True, timeout=10)
    payload = json.loads(result.stdout)
    items(payload)
    return payload


def parallel_calls(calls):
    # Every callable must itself bound subprocess IO. No sequential 6x20s
    # health path and no hidden thread left running past the next poll.
    with ThreadPoolExecutor(max_workers=len(calls)) as pool:
        jobs = {name: pool.submit(fn) for name, fn in calls.items()}
        results, failures = {}, {}
        for name, job in jobs.items():
            try:
                results[name] = job.result()
            except (RuntimeError, ValueError, OSError, KeyError, subprocess.SubprocessError) as error:
                failures[name] = type(error).__name__
        return results, failures


def dependency_health(binding, snapshots, failures):
    missing = sorted(set(QUERIES) - set(snapshots))
    if missing:
        # Unknown API data is excluded and bounded by the existing health
        # recovery budget. It never becomes a fabricated healthy snapshot.
        return {"fatal": [], "transient": [{"reason": "dependency_api_unavailable", "resources": missing}],
                "warnings": []}
    result = classify_health(binding, snapshots["nodes"], snapshots["pods"], snapshots["volumes"], snapshots["cnpg"])
    result["fatal"].extend(duplicate_disk_uuids(snapshots["storage_nodes"]))
    result["fatal"].extend(colocated_running_replicas(snapshots["replicas"]))
    return result


def append(path, value):
    with path.open("a") as stream:
        stream.write(json.dumps(value, sort_keys=True, allow_nan=False) + "\n")
        stream.flush()
        os.fsync(stream.fileno())


@contextmanager
def coordinator_lock(root):
    """One writer per run, including resume; lock is outside sealed evidence.

    Never unlink the lock: replacing its inode could allow a second writer.
    Kernel releases flock automatically if the coordinator is killed.
    """
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", root.name):
        raise ValueError("unsafe coordinator lock run ID")
    directory = root.parent / ".coordinator-locks"
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError("coordinator lock directory must be owned and private")
    fd = os.open(directory / (root.name + ".lock"), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError("coordinator lock must be an owned private regular file")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise ValueError("another coordinator owns this run") from error
        yield
    finally:
        os.close(fd)


def validate_resume_runtime(marker, config):
    from .recovery_worker_probe import clean_source
    from .finalize_candidate import verify_model_bundle
    source, model, policy = (Path(config[name]) for name in ("source", "model", "policy"))
    if Path(__file__).resolve() != (source / "sentinel_pulse/recovery_coordinator.py").resolve():
        raise ValueError("resume executable is not the registered source")
    commit, files = clean_source(source)
    if commit != marker["source_commit"] or files != marker["source_files"]:
        raise ValueError("resume coordinator source differs from registration")
    _, candidates, collect_only = verify_model_bundle(model)
    if (collect_only or set(candidates) != set(marker["operational_evaluation_contract"]["expected_workloads"])
            or sha256_file(model / "manifest.json") != marker["model_manifest_sha256"]
            or sha256_file(policy) != marker["decision_policy_sha256"]
            or sha256_file(source / "sentinel_pulse/protocol/telemetry-recovery-v1.json")
                != marker["telemetry_recovery_contract"]["profile_file_sha256"]):
        raise ValueError("resume frozen model/policy/profile differs from registration")


def load_resume(root, config):
    if (root / "TERMINAL.json").exists():
        raise ValueError("terminal coordinator cannot be resumed")
    marker = validate_marker(json.loads((root / "START.json").read_text()))
    if marker["run_id"] != root.name:
        raise ValueError("resume directory differs from registered run ID")
    if marker.get("coordinator_config_sha256") != digest(config) or json.loads((root / "CONFIG.json").read_text()) != config:
        raise ValueError("resume launch config drift")
    health = [json.loads(line) for line in (root / "dependency-health.jsonl").read_text().splitlines()]
    states = [json.loads(line) for line in (root / "SUPERVISION.jsonl").read_text().splitlines()]
    # Independently replay the saved evidence before accepting continuation.
    from .recovery_formal import health_exclusions
    health_exclusions(marker, root / "dependency-health.jsonl")
    previous = None
    for value in states:
        expected = supervision_step(marker, sha256_file(root / "START.json"), previous,
                                    value["nodes"], value["state"]["checked_at_unix"])
        # Health fatality is recorded separately and never resumed.
        if expected != value["state"]:
            raise ValueError("persisted supervisor evidence differs from replay")
        previous = expected
    if not previous or previous["phase"] in {"rejected", "ready_to_finalize"}:
        raise ValueError("no resumable supervisor checkpoint")
    if health[-1]["fatal"]:
        raise ValueError("fatal dependency incident cannot be resumed")
    return marker, health, previous


def start(root, config, remote, run_id, duration, diagnostic, observation=False):
    snapshots, failures = parallel_calls({name: lambda args=args: api_snapshot(args) for name, args in QUERIES.items()})
    if failures:
        raise ValueError("preflight API snapshot incomplete")
    replies, failures = parallel_calls({host: lambda host=host: remote.call(host, "preflight", timeout=60) for host in sorted(WORKERS)})
    if failures:
        raise ValueError("worker preflight failed: " + ",".join(sorted(failures)))
    manifest = json.loads((Path(config["model"]) / "manifest.json").read_text())
    profile = json.loads((Path(config["source"]) / "sentinel_pulse/protocol/operational-soak-v1.json").read_text())
    binding = bind(profile, manifest, snapshots["pods"], api_snapshot(["get", "pv"]),
                   [r["node_name"] for r in replies.values()])
    health = dependency_health(binding, snapshots, {})
    if (health["fatal"] or health["transient"]) and not observation:
        raise ValueError("dependencies are not healthy at registration")
    workers = {host: {name: reply[name] for name in ("node_name", "expected_workloads", "loader_sha256", "bpf_object_sha256")}
               for host, reply in replies.items()}
    marker = register(run_id, Path(config["source"]), Path(config["model"]), Path(config["policy"]),
                      Path(config["source"]) / "sentinel_pulse/protocol/telemetry-recovery-v1.json",
                      binding, workers, duration, diagnostic)
    for host, reply in replies.items():
        for name in ("source_commit", "source_files_sha256", "model_manifest_sha256", "decision_policy_sha256"):
            if reply[name] != marker[name]:
                raise ValueError("worker preflight source/model differs: " + host + "/" + name)
    marker["coordinator_config_sha256"] = digest(config)
    if observation:
        marker['observational_segment'] = True
    root.mkdir(mode=0o750, parents=True, exist_ok=False)
    write_new(root / "CONFIG.json", config)
    write_new(root / "PREFLIGHT.json", {"workers": replies, "health": health, "registration_pending": False})
    write_new(root / "START.json", marker)
    return marker


def run(root, config, remote, run_id, duration, diagnostic, resume=False, observation=False):
    with coordinator_lock(root):
        return _run_owned(root, config, remote, run_id, duration, diagnostic, resume, observation)


def _run_owned(root, config, remote, run_id, duration, diagnostic, resume=False, observation=False):
    if resume:
        marker, health_rows, previous = load_resume(root, config)
        if (marker["run_id"] != run_id or marker["collector_duration_seconds"] != duration
                or marker["diagnostic_only"] is not diagnostic):
            raise ValueError("resume arguments differ from registered run/duration/classification")
        validate_resume_runtime(marker, config)
        append(root / "RESUME.jsonl", {"schema": "sentinel-pulse-recovery-coordinator-resume-v1",
            "run_id": run_id, "marker_sha256": sha256_file(root / "START.json"),
            "source_commit": marker["source_commit"], "resumed_at_unix": time.time(),
            "previous_checked_at_unix": previous["checked_at_unix"],
            "worker_relaunch": False, "registration_replaced": False})
    else:
        marker = (start(root, config, remote, run_id, duration, diagnostic, True) if observation
                  else start(root, config, remote, run_id, duration, diagnostic))
        health_rows, previous = [], None
    payload = {"marker": marker, "marker_bytes": base64.b64encode((root / "START.json").read_bytes()).decode()}
    marker_sha = sha256_file(root / "START.json")
    reason, final_report, stop_results = None, None, {}
    stopped = False

    def interrupted(signum, _frame):
        nonlocal stopped
        stopped = True
        if observation and callable(old_signals.get(signum)):
            old_signals[signum](signum, _frame)

    old_signals = {s: signal.signal(s, interrupted) for s in (signal.SIGINT, signal.SIGTERM)}
    try:
        if not resume:
            launched, failures = parallel_calls({host: lambda host=host: remote.call(host, "stage", payload, timeout=60)
                                                 for host in sorted(WORKERS)})
            write_new(root / "LAUNCH.json", {"workers": launched, "failures": failures})
            if failures:
                raise ValueError("not all preregistered worker legs launched")
        while not stopped:
            cycle_start = time.monotonic()
            calls = {name: lambda args=args: api_snapshot(args) for name, args in QUERIES.items()}
            calls.update({host: lambda host=host: remote.call(host, "probe", payload) for host in sorted(WORKERS)})
            results, failures = parallel_calls(calls)
            now = time.time()
            nodes = {host: results.get(host, {"status": "unavailable", "reason": failures.get(host, "missing_reply")})
                     for host in sorted(WORKERS)}
            state = supervision_step(marker, marker_sha, previous, nodes, now)
            health = observe(marker["operational_evaluation_contract"], health_rows,
                             dependency_health(marker["operational_evaluation_contract"], results, failures), now,
                             marker["started_at_unix"])
            append(root / "dependency-health.jsonl", health)
            health_rows.append(health)
            append(root / "SUPERVISION.jsonl", {"state": state, "nodes": nodes, "probe_failures": failures})
            # Preserve the actual API responses for RCA, compressed outside Git.
            with gzip.open(root / "API_SNAPSHOTS.jsonl.gz", "at") as stream:
                stream.write(json.dumps({"checked_at_unix": now, "snapshots": {k: results[k] for k in QUERIES if k in results}},
                                        sort_keys=True, allow_nan=False) + "\n")
            previous = state
            if state["phase"] == "rejected" or (health["fatal"] and not observation):
                raise ValueError("supervision/dependency gate rejected run")
            if state["phase"] == "ready_to_finalize":
                if health["degraded"] and not observation:
                    raise ValueError("dependency health degraded at terminal")
                break
            remaining = max(0, 10 - (time.monotonic() - cycle_start))
            # Short signal-responsive waits, never fabricate catch-up polls.
            until = time.monotonic() + remaining
            while not stopped and time.monotonic() < until:
                time.sleep(min(.25, max(0, until - time.monotonic())))
        if stopped:
            raise ValueError("coordinator interrupted")
        if observation:
            # Completed or failed legs are audited by the persistent campaign.
            # An alert/availability verdict never controls campaign scheduling.
            return_observation = True
        else:
            return_observation = False
        payload["health_journal"] = (root / "dependency-health.jsonl").read_text()
        if return_observation:
            raise ObservationComplete()
        reports, failures = parallel_calls({host: lambda host=host: remote.call(host, "finalize", payload, timeout=1800)
                                            for host in sorted(WORKERS)})
        for host, report in reports.items():
            write_new(root / ("NODE_REPORT_" + host + ".json"), report)
        if stopped:
            raise ValueError("coordinator interrupted during finalization")
        if failures:
            raise ValueError("worker finalization failed: " + ",".join(sorted(failures)))
        final_report = aggregate(root / "START.json", [root / ("NODE_REPORT_" + host + ".json") for host in sorted(WORKERS)])
        write_new(root / "REPORT.json", final_report)
        if not (final_report["formal_recovery_pass"] or (marker["diagnostic_only"] and final_report["diagnostic_integrity_gate"])):
            reason = "terminal evidence gate rejected run"
    except ObservationComplete:
        pass
    except (ValueError, RuntimeError, OSError, KeyError, subprocess.SubprocessError) as error:
        reason = str(error)
    finally:
        if reason:
            replies, failures = parallel_calls({host: lambda host=host: remote.call(host, "stop", payload, timeout=50)
                                                for host in sorted(WORKERS)})
            stop_results = {"workers": replies, "failures": failures}
        for sig, handler in old_signals.items():
            signal.signal(sig, handler)
        terminal = {"schema": "sentinel-pulse-recovery-coordinator-terminal-v1", "run_id": marker["run_id"],
                    "marker_sha256": marker_sha, "finished_at_unix": time.time(), "reason": reason,
                    "diagnostic_only": marker["diagnostic_only"],
                    "formal_recovery_pass": reason is None and bool(final_report and final_report["formal_recovery_pass"]),
                    "diagnostic_integrity_gate": reason is None and bool(final_report and final_report["diagnostic_integrity_gate"]),
                    "cleanup": stop_results, "automatic_promotion": False, "automatic_blind_evaluation": False,
                    "kernel_to_alert_claim_allowed": False}
        write_new(root / "TERMINAL.json", terminal)
        # Coordinator seal binds receipts and compressed API evidence, not raw
        # worker streams (those keep their independent worker seals).
        write_new(root / "SHA256.json", {p.name: sha256_file(p) for p in sorted(root.iterdir()) if p.is_file()})
    return terminal


class ObservationComplete(Exception):
    """Internal completion signal; observational verdict is evaluated later."""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--password-file", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--duration-seconds", type=int, default=89880)
    parser.add_argument("--diagnostic-only", action="store_true")
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", args.run_id):
        raise ValueError("unsafe run ID")
    config = validate_config(json.loads(args.config.read_text()))
    result = run(args.output_root / args.run_id, config, Remote(config, args.password_file), args.run_id,
                 args.duration_seconds, args.diagnostic_only, args.resume)
    print(json.dumps(result, sort_keys=True, allow_nan=False))
    raise SystemExit(0 if result["formal_recovery_pass"] or result["diagnostic_integrity_gate"] else 1)


if __name__ == "__main__":
    main()
