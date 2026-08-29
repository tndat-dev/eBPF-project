#!/usr/bin/env python3
"""Read-only status checker for an active Sentinel Pulse normal soak.

The historical filename is retained because the control-plane unit references
it, but the checker is run-agnostic. It never creates or modifies campaign
evidence and never appends to a tracked report: stdout/systemd-journal is the
monitoring sink.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import sys
import time


DEFAULT_EVIDENCE_ROOT = Path("/home/dat/sentinel-pulse-evidence")
EXPECTED_WORKERS = ("10.1.16.237", "10.1.16.239", "10.1.16.238")
TERMINAL_MARKERS = ("FAILED", "NORMAL_PASS", "ARCHIVE_COMPLETE")
MAX_MONITOR_AGE_SECONDS = 180.0


def parse_timestamp(value: str) -> float:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()


def active_runs(root: Path) -> list[Path]:
    if not root.is_dir():
        return []
    candidates = []
    for path in root.glob("pulse500-normal-soak-*"):
        if not path.is_dir() or not (path / "ACTIVE").is_file():
            continue
        if any((path / marker).exists() for marker in TERMINAL_MARKERS):
            continue
        if not (path / "SOAK_START.json").is_file():
            continue
        candidates.append(path)
    return sorted(candidates, key=lambda item: item.name)


def resolve_run(root: Path, run_id: str | None) -> Path:
    if run_id:
        if not run_id.startswith("pulse500-normal-soak-") or "/" in run_id:
            raise ValueError("unsafe normal-soak run ID")
        candidate = root / run_id
        if not candidate.is_dir():
            raise FileNotFoundError(f"run does not exist: {candidate}")
        return candidate
    runs = active_runs(root)
    if len(runs) != 1:
        raise RuntimeError(f"expected exactly one active normal soak, found {len(runs)}")
    return runs[0]


def latest_worker_rows(path: Path) -> dict[str, dict]:
    latest: dict[str, dict] = {}
    with path.open(encoding="utf-8") as source:
        for number, line in enumerate(source, 1):
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid monitor JSON at line {number}") from exc
            host = str(row.get("host", ""))
            if host in EXPECTED_WORKERS:
                latest[host] = row
    return latest


def kubernetes_summary() -> dict:
    command = ["kubectl", "-n", "production", "get", "pods", "-o", "json"]
    try:
        result = subprocess.run(
            command, check=True, capture_output=True, text=True, timeout=15
        )
        payload = json.loads(result.stdout)
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
        return {"available": False, "error": type(exc).__name__}
    phases: dict[str, int] = {}
    unready = 0
    for pod in payload.get("items", []):
        status = pod.get("status", {})
        phase = str(status.get("phase", "Unknown"))
        phases[phase] = phases.get(phase, 0) + 1
        if phase == "Running" and any(
            item.get("ready") is not True
            for item in status.get("containerStatuses", [])
        ):
            unready += 1
    return {"available": True, "phases": phases, "running_unready": unready}


def build_status(run: Path, now: float | None = None) -> tuple[dict, bool]:
    now = time.time() if now is None else now
    marker = json.loads((run / "SOAK_START.json").read_text(encoding="utf-8"))
    rows = latest_worker_rows(run / "MONITOR.jsonl")
    started = parse_timestamp(marker["started_not_before"])
    eligible = parse_timestamp(marker["eligible_finalize_after"])
    duration = eligible - started
    if duration <= 0:
        raise ValueError("invalid soak duration in marker")
    elapsed = max(0.0, now - started)
    worker_status = {}
    healthy = len(rows) == len(EXPECTED_WORKERS)
    for host in EXPECTED_WORKERS:
        row = rows.get(host)
        if row is None:
            worker_status[host] = {"status": "missing"}
            healthy = False
            continue
        row_healthy = (
            row.get("collector") == "active"
            and row.get("detector") == "active"
            and int(row.get("nrestarts", -1)) == 0
            and int(row.get("alerts", -1)) == 0
            and 0.0 <= now - float(row.get("checked_at_unix", 0.0))
            <= MAX_MONITOR_AGE_SECONDS
        )
        healthy = healthy and row_healthy
        worker_status[host] = {
            "status": "healthy" if row_healthy else "unhealthy",
            "checked_at_unix": row.get("checked_at_unix"),
            "age_seconds": max(
                0.0, now - float(row.get("checked_at_unix", 0.0))
            ),
            "collector": row.get("collector"),
            "detector": row.get("detector"),
            "decisions": int(row.get("decisions", 0)),
            "alerts": int(row.get("alerts", 0)),
            "nrestarts": int(row.get("nrestarts", 0)),
        }
    terminal = [name for name in TERMINAL_MARKERS if (run / name).exists()]
    active = (run / "ACTIVE").is_file() and not terminal
    healthy = healthy and active
    kubernetes = kubernetes_summary()
    kubernetes_healthy = (
        kubernetes.get("available") is True
        and int(kubernetes.get("running_unready", 0)) == 0
        and int(kubernetes.get("phases", {}).get("Failed", 0)) == 0
        and int(kubernetes.get("phases", {}).get("Unknown", 0)) == 0
        and int(kubernetes.get("phases", {}).get("Pending", 0)) == 0
    )
    healthy = healthy and kubernetes_healthy
    status = {
        "schema": "sentinel-pulse-read-only-check-v1",
        "checked_at": datetime.fromtimestamp(now, timezone.utc).isoformat(),
        "run_id": run.name,
        "active": active,
        "terminal_markers": terminal,
        "elapsed_hours": elapsed / 3600.0,
        "duration_progress_percent": min(100.0, elapsed / duration * 100.0),
        "workers": worker_status,
        "worker_decisions_total": sum(
            item.get("decisions", 0) for item in worker_status.values()
        ),
        "worker_alerts_total": sum(
            item.get("alerts", 0) for item in worker_status.values()
        ),
        "worker_restarts_total": sum(
            item.get("nrestarts", 0) for item in worker_status.values()
        ),
        "kubernetes": kubernetes,
        "healthy_snapshot": healthy,
        "accuracy_claim_allowed": False,
    }
    return status, healthy


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence-root", type=Path, default=DEFAULT_EVIDENCE_ROOT)
    parser.add_argument("--run-id")
    args = parser.parse_args(argv)
    try:
        run = resolve_run(args.evidence_root, args.run_id)
        status, healthy = build_status(run)
    except (FileNotFoundError, RuntimeError, ValueError, KeyError) as exc:
        print(json.dumps({"status": "not_checked", "error": str(exc)}, sort_keys=True))
        return 3
    print(json.dumps(status, sort_keys=True, separators=(",", ":")))
    return 0 if healthy else 4


if __name__ == "__main__":
    sys.exit(main())
