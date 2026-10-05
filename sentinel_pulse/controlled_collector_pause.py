"""Preregistered diagnostic SIGSTOP/SIGCONT of ONE private loader via pidfd.

Never targets the control collector, pod processes or an arbitrary PID. This
is fault injection, not an attack, model training or permission to alter a run.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import time

from .integrity import sha256_file

PAUSE_MS = 1200
FAULT = {"schema": "sentinel-pulse-controlled-loader-pause-v1", "pause_ms": PAUSE_MS,
         "scheduled_after_preregistration_seconds": 120,
         "scope": "private_projected_loader_only", "signals": ["SIGSTOP", "SIGCONT"],
         "production_workloads_modified": False, "control_collector_modified": False}


def find_loader(run_id: str, group: str, proc: Path = Path("/proc"),
                cgroups: Path = Path("/sys/fs/cgroup")) -> int:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", run_id):
        raise ValueError("unsafe pause run ID")
    if group != "/system.slice/sentinel-pulse-collector-500ms-experiment.service":
        raise ValueError("refusing a cgroup other than private experiment service")
    expected = f"/opt/sentinel-pulse/experiments/{run_id}/pulse_counter_projected_loader"
    matched = []
    for raw in (cgroups / group.lstrip("/") / "cgroup.procs").read_text().splitlines():
        if not raw.isascii() or not raw.isdigit():
            raise ValueError("invalid cgroup process ID")
        pid = int(raw)
        if pid <= 1:
            raise ValueError("refusing system process")
        try:
            if os.readlink(proc / str(pid) / "exe") == expected:
                cmd = (proc / str(pid) / "cmdline").read_bytes().split(b"\0")
                if cmd[0].decode() != expected or b"--interval-ms" not in cmd:
                    raise ValueError("private loader command identity mismatch")
                matched.append(pid)
        except FileNotFoundError:
            continue
    if len(matched) != 1:
        raise ValueError("expected exactly ONE private projected loader")
    return matched[0]


def pause_pidfd(pid: int, expected_exe: str) -> dict:
    fd = os.pidfd_open(pid, 0)
    stopped = False
    began = time.time()
    monotonic = time.monotonic()
    def terminate(signum, frame):
        raise InterruptedError("pause interrupted; resuming private loader")
    old_term = signal.signal(signal.SIGTERM, terminate)
    try:
        # Check again after obtaining the process handle: never signal a PID
        # that exited/recycled during cgroup inspection.
        if os.readlink(f"/proc/{pid}/exe") != expected_exe:
            raise ValueError("loader identity changed before pidfd signal")
        stopped = True
        signal.pidfd_send_signal(fd, signal.SIGSTOP)
        time.sleep(PAUSE_MS / 1000)
    finally:
        try:
            if stopped:
                signal.pidfd_send_signal(fd, signal.SIGCONT)
        finally:
            try:
                os.close(fd)
            finally:
                signal.signal(signal.SIGTERM, old_term)
    return {"pid": pid, "started_at_unix": began, "resumed_at_unix": time.time(),
            "elapsed_monotonic_seconds": time.monotonic() - monotonic,
            "resume_sent": True}


def perform(root: Path) -> dict:
    if os.geteuid() != 0:
        raise ValueError("controlled loader pause requires root")
    run_id = root.name
    if root != Path("/var/lib/sentinel-pulse-500ms/runs") / run_id:
        raise ValueError("unsafe private capture root")
    prereg = Path("/var/lib/sentinel-pulse-recovery-smoke") / run_id / "START.json"
    registered = json.loads(prereg.read_text())
    if (registered.get("run_id") != run_id or registered.get("controlled_fault") != FAULT
            or registered.get("duration_seconds") != 1800):
        raise ValueError("pause was not preregistered for a NEW 1800s diagnostic")
    if time.time() < registered["started_at"] + FAULT["scheduled_after_preregistration_seconds"]:
        raise ValueError("pause scheduled before preregistered injection time")
    event = root / "CONTROLLED_FAULT_EVENT.json"
    if event.exists():
        raise ValueError("pause event already exists; no repeated injection")
    start = json.loads((root / "START.json").read_text())
    expected = f"/opt/sentinel-pulse/experiments/{run_id}/pulse_counter_projected_loader"
    if (start.get("collector_variant") != "projected" or start.get("collector_loader") != expected
            or sha256_file(Path(expected)) != start["sha256"]["loader"]):
        raise ValueError("private loader does not match capture START")
    group = subprocess.check_output(["systemctl", "show", "sentinel-pulse-collector-500ms-experiment.service",
                                     "-p", "ControlGroup", "--value"], text=True).strip()
    pid = find_loader(run_id, group)
    result = {"schema": "sentinel-pulse-controlled-loader-pause-event-v1", "run_id": run_id,
              "preregistration_sha256": sha256_file(prereg), "fault": FAULT,
              "loader": expected, "loader_sha256": start["sha256"]["loader"]}
    # Reserve exclusively BEFORE any signal, so two callers cannot inject
    # twice. Even a failed attempt remains visible and cannot be silently retried.
    with event.open("x") as stream:
        try:
            result.update(pause_pidfd(pid, expected))
        except BaseException as error:
            result.update(resume_sent=False, failure_type=type(error).__name__)
            raise
        finally:
            stream.write(json.dumps(result, indent=2, sort_keys=True) + "\n")
            event.chmod(0o444)
    return result


def validate_event(root: Path, registered: dict, prereg_path: Path) -> dict:
    event = json.loads((root / "CONTROLLED_FAULT_EVENT.json").read_text())
    start = json.loads((root / "START.json").read_text())
    if (registered.get("controlled_fault") != FAULT or registered.get("duration_seconds") != 1800
            or event.get("run_id") != root.name or event.get("fault") != FAULT
            or event.get("preregistration_sha256") != sha256_file(prereg_path)
            or event.get("resume_sent") is not True
            or event.get("loader") != start["collector_loader"]
            or event.get("loader_sha256") != start["sha256"]["loader"]):
        raise ValueError("controlled fault event differs from preregistration/loader")
    began, resumed, elapsed = (event[k] for k in ("started_at_unix", "resumed_at_unix", "elapsed_monotonic_seconds"))
    import math
    if (any(isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v) for v in (began, resumed, elapsed))
            or resumed < began or not 1.2 <= elapsed <= 5
            or began < registered["started_at"] + FAULT["scheduled_after_preregistration_seconds"]):
        raise ValueError("controlled pause clock/duration/schedule invalid")
    previous = None
    incident = None
    recovered = False
    with (root / "features.jsonl").open() as stream:
        for line in stream:
            row = json.loads(line)
            if row.get("schema") != "sentinel-pulse-recovery-snapshot-v1":
                continue
            end = row["observed_at"]
            if (previous is not None and previous < resumed and end >= began
                    and row["recovery"]["status"] == "quarantined"):
                incident = row["recovery"]["sequence"]
            if incident is not None and row["recovery"]["sequence"] > incident and row["recovery"]["can_score"]:
                recovered = True
            previous = end
    if incident is None or not recovered:
        raise ValueError("no quarantine and clean recovery observed across registered pause")
    return {"event_sha256": sha256_file(root / "CONTROLLED_FAULT_EVENT.json"),
            "quarantine_snapshot_sequence": incident, "clean_recovery_observed": recovered}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", required=True, type=Path)
    print(json.dumps(perform(parser.parse_args().run_dir), sort_keys=True))


if __name__ == "__main__":
    main()
