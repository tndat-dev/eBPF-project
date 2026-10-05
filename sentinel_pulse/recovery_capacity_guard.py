"""External storage safety supervisor; never changes a frozen soak verdict.

Run this file directly with PYTHONPATH pointing at the frozen coordinator
checkout. Its own source hash and storage budget are registered separately,
before starting a new coordinator child. It never deletes data or stops pods.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import math
import os
from pathlib import Path
import re
import shlex
import signal
import subprocess
import sys
import time

from sentinel_pulse.integrity import sha256_file
from sentinel_pulse.recovery_coordinator import secret, validate_config
from sentinel_pulse.recovery_formal import write_new
from sentinel_pulse.telemetry_recovery import digest

CONTRACT = {"schema": "sentinel-pulse-external-capacity-budget-v1",
            "minimum_available_bytes": 0, "maximum_used_percent": 90,
            "poll_seconds": 30, "maximum_unknown_seconds": 60,
            "automatic_deletion": False, "automatic_promotion": False,
            "changes_formal_evaluation_contract": False}
DISK_PROBE = """import json,os,time
result={}
for p in ['/var/lib/sentinel-pulse-500ms','/var/lib/sentinel-pulse-detector']:
 s=os.statvfs(p); u=(s.f_blocks-s.f_bfree)*s.f_frsize; a=s.f_bavail*s.f_frsize
 result[p]={'device':os.stat(p).st_dev,'used_bytes':u,'available_bytes':a,
 'size_bytes':s.f_blocks*s.f_frsize,'checked_at_unix':time.time()}
print(json.dumps(result))
"""
PATHS = {"/var/lib/sentinel-pulse-500ms", "/var/lib/sentinel-pulse-detector"}


def capacity(sample):
    if set(sample) != PATHS:
        raise ValueError("missing monitored filesystem")
    result = {}
    for path, row in sample.items():
        for name in ("device", "used_bytes", "available_bytes", "size_bytes"):
            if type(row[name]) is not int or row[name] < 0:
                raise ValueError("invalid filesystem observation")
        used, available, size = [row[n] for n in ("used_bytes", "available_bytes", "size_bytes")]
        if size <= 0 or used + available > size or used + available <= 0:
            raise ValueError("invalid filesystem accounting")
        stamp = row["checked_at_unix"]
        if isinstance(stamp, bool) or not isinstance(stamp, (int, float)) or not math.isfinite(stamp):
            raise ValueError("invalid disk observation timestamp")
        percent = 100 * used / (used + available)  # same reserved-block semantics as df
        result[path] = {**row, "used_percent": percent,
                       "safe": available > CONTRACT["minimum_available_bytes"]
                       and percent < CONTRACT["maximum_used_percent"]}
    return result


def probe(host, password_file):
    command = shlex.join(["python3", "-c", DISK_PROBE])
    args = ["sshpass", "-f", str(password_file), "ssh", "-o", "ConnectTimeout=5",
            "-o", "StrictHostKeyChecking=yes", "-o", "NumberOfPasswordPrompts=1",
            "-o", "ServerAliveInterval=3", "-o", "ServerAliveCountMax=2", "dat@" + host, command]
    value = subprocess.run(args, text=True, capture_output=True, timeout=12)
    if value.returncode:
        raise RuntimeError("disk probe failed: " + host)  # never print raw remote output
    return capacity(json.loads(value.stdout))


def observations(workers, password_file):
    with ThreadPoolExecutor(max_workers=len(workers)) as pool:
        jobs = {host: pool.submit(probe, host, password_file) for host in sorted(workers)}
        results, errors = {}, {}
        for host, job in jobs.items():
            try:
                results[host] = job.result()
            except (ValueError, KeyError, TypeError, RuntimeError, OSError, subprocess.SubprocessError) as error:
                errors[host] = type(error).__name__
    return results, errors


def append(path, row):
    with path.open("a") as stream:
        stream.write(json.dumps(row, sort_keys=True, allow_nan=False) + "\n")
        stream.flush()
        os.fsync(stream.fileno())


def stop_child(child):
    # Popen retains ownership of this exact child; no pid-file or name matching.
    if child.poll() is not None:
        return
    child.terminate()
    try:
        child.wait(timeout=55)  # frozen coordinator bounds owned-worker cleanup at 50 s
    except subprocess.TimeoutExpired:
        child.kill()
        child.wait(timeout=5)


def supervise(config_path, password_file, output_root, guard_root, run_id, duration,
              diagnostic=False):
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", run_id):
        raise ValueError("unsafe run ID")
    config = validate_config(json.loads(config_path.read_text()))
    lower, upper = (180, 1800) if diagnostic else (86400, 89880)
    if type(duration) is not int or not lower <= duration <= upper:
        raise ValueError("duration outside frozen diagnostic/formal bounds")
    secret(password_file)  # validate private ownership; never serialize it
    source = Path(config["source"])
    config_sha, script_sha = sha256_file(config_path), sha256_file(Path(__file__))
    if (output_root / run_id).exists():
        raise ValueError("only a NEW coordinator run is supported")
    results, errors = observations(config["workers"], password_file)
    if errors or any(not row["safe"] for sample in results.values() for row in sample.values()):
        raise ValueError("storage preflight rejected; no coordinator launched")
    devices = {host: {path: row["device"] for path, row in sample.items()}
               for host, sample in results.items()}
    root = guard_root / run_id
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    command = [sys.executable, "-u", "-m", "sentinel_pulse.recovery_coordinator",
               "--config", str(config_path), "--password-file", str(password_file),
               "--output-root", str(output_root), "--run-id", run_id,
               "--duration-seconds", str(duration)]
    if diagnostic:
        command.append("--diagnostic-only")
    write_new(root / "START.json", {"schema": "sentinel-pulse-capacity-guard-start-v1",
        "run_id": run_id, "started_at_unix": time.time(), "contract": CONTRACT,
        "diagnostic_only": diagnostic, "duration_seconds": duration,
        "config_sha256": config_sha, "guard_source_sha256": script_sha,
        "coordinator_source_sha256": sha256_file(source / "sentinel_pulse/recovery_coordinator.py"),
        "preflight": results})
    env = {**os.environ, "PYTHONPATH": str(source), "PYTHONDONTWRITEBYTECODE": "1"}
    child, reason, marker_sha, unknown = None, None, None, {}
    stopped = False

    def interrupted(_signal, _frame):
        nonlocal stopped
        stopped = True

    previous = {s: signal.signal(s, interrupted) for s in (signal.SIGINT, signal.SIGTERM)}
    try:
        child = subprocess.Popen(command, env=env, cwd=source)
        append(root / "OBSERVATIONS.jsonl", {"checked_at_unix": time.time(), "workers": results,
            "errors": {}, "coordinator_pid": child.pid, "phase": "launched"})
        while child.poll() is None:
            if stopped:
                raise RuntimeError("capacity guard interrupted")
            if sha256_file(config_path) != config_sha or sha256_file(Path(__file__)) != script_sha:
                raise ValueError("capacity guard source/config changed")
            marker = output_root / run_id / "START.json"
            if marker.exists():
                current = sha256_file(marker)
                if marker_sha is None:
                    value = json.loads(marker.read_text())
                    if (value["run_id"] != run_id or value["diagnostic_only"] is not diagnostic
                            or value["collector_duration_seconds"] != duration
                            or value["coordinator_config_sha256"] != digest(config)):
                        raise ValueError("coordinator marker ownership differs")
                    marker_sha = current
                    write_new(root / "COORDINATOR_BINDING.json", {"run_id": run_id,
                        "marker_sha256": current, "coordinator_pid": child.pid})
                elif current != marker_sha:
                    raise ValueError("coordinator marker changed")
            results, errors = observations(config["workers"], password_file)
            now = time.time()
            append(root / "OBSERVATIONS.jsonl", {"checked_at_unix": now, "workers": results,
                "errors": errors, "coordinator_pid": child.pid, "marker_sha256": marker_sha})
            if any(not row["safe"] for sample in results.values() for row in sample.values()):
                raise RuntimeError("registered capacity budget exceeded")
            if any(row["device"] != devices[host][path]
                   for host, sample in results.items() for path, row in sample.items()):
                raise ValueError("monitored filesystem device changed")
            for host in config["workers"]:
                if host in errors:
                    unknown.setdefault(host, time.monotonic())
                    if time.monotonic() - unknown[host] >= CONTRACT["maximum_unknown_seconds"]:
                        raise RuntimeError("capacity observation unavailable beyond budget")
                else:
                    unknown.pop(host, None)
            deadline = time.monotonic() + CONTRACT["poll_seconds"]
            while not stopped and child.poll() is None and time.monotonic() < deadline:
                time.sleep(.25)
        if child.returncode:
            reason = "coordinator exited unsuccessfully"
    except (ValueError, RuntimeError, OSError, KeyError, subprocess.SubprocessError) as error:
        reason = str(error)
    finally:
        if child is not None:
            stop_child(child)
        for sig, handler in previous.items():
            signal.signal(sig, handler)
        write_new(root / "TERMINAL.json", {"run_id": run_id, "finished_at_unix": time.time(),
            "reason": reason, "coordinator_exit_status": None if child is None else child.returncode,
            "marker_sha256": marker_sha, "formal_recovery_pass": False,
            "verdict_authority": "frozen coordinator REPORT.json, not storage guard",
            "automatic_deletion": False, "automatic_promotion": False})
        write_new(root / "SHA256.json", {p.name: sha256_file(p) for p in sorted(root.iterdir()) if p.is_file()})
    return 1 if reason else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("config", "password-file", "output-root", "guard-root"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--duration-seconds", type=int, default=89880)
    parser.add_argument("--diagnostic-only", action="store_true")
    args = parser.parse_args()
    return supervise(args.config, args.password_file, args.output_root, args.guard_root,
                     args.run_id, args.duration_seconds, args.diagnostic_only)


if __name__ == "__main__":
    raise SystemExit(main())
