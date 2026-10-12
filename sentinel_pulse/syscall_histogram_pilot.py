"""Run a bounded exact syscall-ID histogram pilot with auditable context.

The pilot never trains/promotes a model and labels the traffic regime unknown
unless a separate preregistered receipt is supplied.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import re
import signal
import subprocess
import sys
import tempfile
import time


SCHEMA = "sentinel-pulse-syscall-histogram-pilot-v1"
RUN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$")
_stop = False


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_allowlist(path: Path) -> list[int]:
    ids = []
    for line_no, line in enumerate(path.read_text().splitlines(), 1):
        value = line.strip()
        if not value:
            continue
        if not value.isdecimal():
            raise ValueError(f"invalid cgroup ID on line {line_no}")
        parsed = int(value)
        if parsed <= 0 or parsed in ids:
            raise ValueError(f"invalid/duplicate cgroup ID on line {line_no}")
        ids.append(parsed)
    if not ids or len(ids) > 2048:
        raise ValueError("allow-list must contain 1..2048 distinct cgroup IDs")
    return sorted(ids)


def read_metadata(path: Path, expected_ids: set[int]) -> dict:
    raw = path.read_bytes()
    document = json.loads(raw)
    if document.get("schema") != "sentinel-pulse-cgroups-v1":
        raise ValueError("unsupported cgroup metadata schema")
    try:
        present = {int(value) for value in document["cgroups"]}
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("invalid cgroup metadata identities") from exc
    if present != expected_ids:
        raise ValueError("metadata and allow-list cgroup IDs differ")
    return {"document": document, "sha256": sha256_bytes(raw)}


def read_traffic_receipt(path: Path | None, node_name: str, registered_at: float) -> dict | None:
    if path is None:
        return None
    raw = path.read_bytes()
    receipt = json.loads(raw)
    if not isinstance(receipt, dict):
        raise ValueError("traffic receipt must be a JSON object")
    if receipt.get("schema") != "sentinel-pulse-traffic-receipt-v1":
        raise ValueError("unsupported traffic receipt schema")
    receipt_id = receipt.get("receipt_id")
    if not isinstance(receipt_id, str) or not receipt_id.strip():
        raise ValueError("traffic receipt ID is required")
    if receipt.get("node_name") != node_name:
        raise ValueError("traffic receipt node does not match resolver node")
    created = receipt.get("registered_at_unix")
    if (not isinstance(created, (int, float)) or not math.isfinite(created)
            or created > registered_at):
        raise ValueError("traffic receipt must be registered before probe attach")
    schedule = receipt.get("schedule")
    if not isinstance(schedule, list) or not schedule:
        raise ValueError("traffic receipt schedule is empty")
    previous_end = None
    normalized = []
    for row in schedule:
        if not isinstance(row, dict):
            raise ValueError("invalid traffic receipt schedule entry")
        begin, end, regime = row.get("start_unix"), row.get("end_unix"), row.get("regime")
        if (not isinstance(begin, (int, float)) or not isinstance(end, (int, float))
                or not math.isfinite(begin) or not math.isfinite(end) or begin >= end
                or not isinstance(regime, str) or not regime.strip()):
            raise ValueError("invalid traffic receipt interval")
        if previous_end is not None and begin < previous_end:
            raise ValueError("traffic receipt intervals overlap or are unordered")
        previous_end = end
        normalized.append({"start_unix": float(begin), "end_unix": float(end), "regime": regime})
    return {"document": receipt, "sha256": sha256_bytes(raw), "schedule": normalized}


def build_start(args, allow_ids: list[int], metadata: dict) -> dict:
    if not RUN_ID.fullmatch(args.run_id):
        raise ValueError("unsafe run ID")
    if not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", args.source_commit):
        raise ValueError("source commit must be a full Git SHA-1/SHA-256")
    if platform.machine() != "x86_64":
        raise ValueError("pilot currently supports native x86-64 hosts only")
    if not 1 <= args.duration_seconds <= 600:
        raise ValueError("pilot duration must be between 1 and 600 seconds")
    if args.interval_ms != 1000:
        raise ValueError("registered pilot cadence is fixed at 1000 ms")
    if args.baseline_seconds != 300 or args.post_seconds != 300:
        raise ValueError("pilot requires fixed 300-second baseline and post phases")
    registered_at = time.time()
    receipt = read_traffic_receipt(args.traffic_receipt,
                                   metadata["document"].get("node_name"), registered_at)
    return {
        "schema": SCHEMA,
        "run_id": args.run_id,
        "state": "registered_before_attach",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "source_commit": args.source_commit,
        "runner_sha256": sha256_file(Path(__file__)),
        "node_name": metadata["document"].get("node_name"),
        "kernel": platform.release(),
        "architecture": platform.machine(),
        "process_abi_scope": "native_x86_64_only; compat/x32 not verified",
        "object_sha256": sha256_file(args.object),
        "loader_sha256": sha256_file(args.loader),
        "allowlist_sha256": sha256_file(args.allowlist),
        "allowlist_cgroup_ids": allow_ids,
        "initial_metadata_sha256": metadata["sha256"],
        "initial_metadata_generated_at": metadata["document"].get("generated_at"),
        "duration_seconds": args.duration_seconds,
        "snapshot_interval_ms": args.interval_ms,
        "baseline_seconds": args.baseline_seconds,
        "post_seconds": args.post_seconds,
        "traffic_regime": "registered_schedule" if receipt else "unlabelled",
        "traffic_receipt_id": receipt["document"]["receipt_id"] if receipt else None,
        "traffic_receipt_sha256": receipt["sha256"] if receipt else None,
        "use_limit": "feature selection only when capture analysis verifies the preregistered receipt and all integrity checks",
        "no_attack_injection": True,
        "no_model_training_or_promotion": True,
    }


def proc_sample(phase: str, observed_at: float) -> dict:
    cpu = Path("/proc/stat").read_text().splitlines()[0].split()
    mem = {}
    for line in Path("/proc/meminfo").read_text().splitlines():
        key, _, value = line.partition(":")
        parts = value.strip().split()
        if parts and parts[0].isdigit():
            mem[key] = int(parts[0]) * (1024 if len(parts) > 1 and parts[1] == "kB" else 1)
    load = [float(value) for value in Path("/proc/loadavg").read_text().split()[:3]]
    def cgroup_metrics(relative):
        path = Path("/sys/fs/cgroup") / relative.lstrip("/")
        cpu_stat = {}
        cpu_file = path / "cpu.stat"
        if cpu_file.exists():
            for line in cpu_file.read_text().splitlines():
                key, value = line.split()
                cpu_stat[key] = int(value)
        memory_file = path / "memory.current"
        return cpu_stat, int(memory_file.read_text()) if memory_file.exists() else None

    own_cgroup = next((line.split(":", 2)[2] for line in Path("/proc/self/cgroup").read_text().splitlines()
                       if line.startswith("0::")), "/")
    pilot_cpu, pilot_memory = cgroup_metrics(own_cgroup)
    collector_cpu, collector_memory = cgroup_metrics("/system.slice/sentinel-pulse-collector.service")
    return {
        "schema": "sentinel-pulse-pilot-host-metric-v1",
        "observed_at": observed_at,
        "phase": phase,
        "host_cpu_counters": [int(value) for value in cpu[1:]],
        "memory_bytes": {key: mem.get(key) for key in ("MemTotal", "MemAvailable", "SwapTotal", "SwapFree")},
        "load_average_1_5_15": load,
        "pilot_unit_cgroup": own_cgroup,
        "pilot_unit_cpu_stat": pilot_cpu,
        "pilot_unit_memory_current_bytes": pilot_memory,
        "pulse_collector_cpu_stat": collector_cpu,
        "pulse_collector_memory_current_bytes": collector_memory,
    }


def append_jsonl(path: Path, value: dict) -> None:
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")
        stream.flush()
        os.fsync(stream.fileno())


def atomic_json(path: Path, value: dict) -> None:
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, indent=2, sort_keys=True, allow_nan=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def metadata_sample(allowlist_path: Path, metadata_path: Path, output: Path,
                    observed_at: float) -> None:
    error = None
    snapshot = None
    ids = None
    for attempt in range(3):
        try:
            ids = read_allowlist(allowlist_path)
            snapshot = read_metadata(metadata_path, set(ids))
            break
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            error = str(exc)
            if attempt < 2:
                time.sleep(0.2)
    row = {
        "observed_at": observed_at,
        "identity_match": snapshot is not None,
        "allowlist_sha256": sha256_file(allowlist_path) if allowlist_path.is_file() else None,
        "allowlist_cgroup_ids": ids,
        "error": error,
    }
    if snapshot is not None:
        row["metadata_sha256"] = snapshot["sha256"]
        row["document"] = snapshot["document"]
    elif metadata_path.is_file():
        raw = metadata_path.read_bytes()
        row["metadata_sha256"] = sha256_bytes(raw)
        try:
            row["document"] = json.loads(raw)
        except json.JSONDecodeError:
            row["document"] = None
    append_jsonl(output, row)


def _signal_handler(_signum, _frame):
    global _stop
    _stop = True


def _sample_phase(phase, seconds, metrics_path, allowlist_path, metadata_path,
                  metadata_out, interval, child=None):
    started = time.monotonic()
    next_metric = started
    next_metadata = started
    while not _stop:
        now_mono = time.monotonic()
        if child is not None and child.poll() is not None:
            break
        if seconds and now_mono - started >= seconds:
            break
        now = time.time()
        if now_mono >= next_metric:
            append_jsonl(metrics_path, proc_sample(phase, now))
            next_metric = now_mono + interval
        if now_mono >= next_metadata:
            metadata_sample(allowlist_path, metadata_path, metadata_out, now)
            next_metadata = now_mono + 15
        time.sleep(min(1, max(0.05, next_metric - time.monotonic())))


def run(args) -> int:
    global _stop
    _stop = False
    if os.geteuid() != 0:
        raise PermissionError("run pilot as root (eBPF attach needs node privileges)")
    for path in (args.loader, args.object, args.allowlist, args.metadata):
        if not path.is_file():
            raise FileNotFoundError(path)
    allow_ids = read_allowlist(args.allowlist)
    initial_metadata = read_metadata(args.metadata, set(allow_ids))
    if not initial_metadata["document"].get("node_name"):
        raise ValueError("node identity missing from resolver metadata")
    if args.output.exists():
        raise FileExistsError(args.output)
    start = build_start(args, allow_ids, initial_metadata)
    args.output.mkdir(parents=True, mode=0o700)
    start["output_dir"] = str(args.output)
    start["registered_wall_time"] = time.time()
    if args.traffic_receipt is not None:
        with (args.output / "traffic-receipt.json").open("xb") as stream:
            stream.write(args.traffic_receipt.read_bytes())
            stream.flush()
            os.fsync(stream.fileno())
    atomic_json(args.output / "START.json", start)
    metrics_path = args.output / "host-metrics.jsonl"
    metadata_out = args.output / "metadata-snapshots.jsonl"
    capture_path = args.output / "histogram.jsonl"
    stderr_path = args.output / "loader.log"
    exit_code = 1
    phase = "baseline"
    started_at = time.time()
    terminal_state = "failed"
    child = None
    probe_started_at = None
    probe_ended_at = None
    previous_handlers = {sig: signal.signal(sig, _signal_handler)
                         for sig in (signal.SIGTERM, signal.SIGINT)}
    try:
        _sample_phase(phase, args.baseline_seconds, metrics_path, args.allowlist,
                      args.metadata, metadata_out, args.metric_interval_seconds)
        if _stop:
            terminal_state = "interrupted_before_attach"
        else:
            phase = "probe"
            probe_started_at = time.time()
            command = [str(args.loader), "--object", str(args.object),
                       "--allow-cgroup-file", str(args.allowlist),
                       "--interval-ms", str(args.interval_ms),
                       "--duration-seconds", str(args.duration_seconds)]
            with capture_path.open("x", encoding="utf-8") as capture, stderr_path.open("x", encoding="utf-8") as stderr:
                child = subprocess.Popen(command, stdout=capture, stderr=stderr, text=True)
                _sample_phase(phase, args.duration_seconds + 30, metrics_path,
                              args.allowlist, args.metadata, metadata_out,
                              args.metric_interval_seconds, child)
                if child.poll() is None:
                    child.terminate()
                    try:
                        child.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        child.kill()
                exit_code = child.wait()
            probe_ended_at = time.time()
            phase = "post"
            if exit_code == 0 and not _stop:
                _sample_phase(phase, args.post_seconds, metrics_path, args.allowlist,
                              args.metadata, metadata_out, args.metric_interval_seconds)
            terminal_state = "completed" if exit_code == 0 and not _stop else "interrupted_or_failed"
    finally:
        try:
            if child is not None and child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    child.kill()
            ended_at = time.time()
            terminal = {
                "schema": "sentinel-pulse-syscall-histogram-pilot-terminal-v1",
                "run_id": args.run_id,
                "state": terminal_state,
                "exit_code": exit_code,
                "phase_at_end": phase,
                "started_at": started_at,
                "ended_at": ended_at,
                "wall_seconds": ended_at - started_at,
                "capture_bytes": capture_path.stat().st_size if capture_path.exists() else 0,
                "probe_started_at_unix": probe_started_at,
                "probe_ended_at_unix": probe_ended_at,
            }
            atomic_json(args.output / "TERMINAL.json", terminal)
            files = sorted(path for path in args.output.rglob("*") if path.is_file() and path.name != "SHA256SUMS")
            with (args.output / "SHA256SUMS").open("x", encoding="utf-8") as stream:
                stream.write("".join(f"{sha256_file(path)}  {path.relative_to(args.output)}\n" for path in files))
                stream.flush()
                os.fsync(stream.fileno())
            if args.owner_uid is not None:
                for path in [args.output, *args.output.rglob("*")]:
                    os.chown(path, args.owner_uid, args.owner_gid if args.owner_gid is not None else -1)
        finally:
            for sig, handler in previous_handlers.items():
                signal.signal(sig, handler)
    return 0 if terminal_state == "completed" else 1


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--loader", required=True, type=Path)
    parser.add_argument("--object", required=True, type=Path)
    parser.add_argument("--allowlist", type=Path, default=Path("/run/sentinel-pulse/allowed-cgroups"))
    parser.add_argument("--metadata", type=Path, default=Path("/run/sentinel-pulse/cgroups.json"))
    parser.add_argument("--traffic-receipt", type=Path,
                        help="pre-registered node traffic schedule JSON; omission labels capture unlabelled")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--duration-seconds", type=int, default=600)
    parser.add_argument("--interval-ms", type=int, default=1000)
    parser.add_argument("--baseline-seconds", type=int, default=300)
    parser.add_argument("--post-seconds", type=int, default=300)
    parser.add_argument("--metric-interval-seconds", type=int, default=10)
    parser.add_argument("--owner-uid", type=int)
    parser.add_argument("--owner-gid", type=int)
    args = parser.parse_args()
    if args.metric_interval_seconds < 1 or args.metric_interval_seconds > 60:
        parser.error("metric interval must be in [1,60]")
    try:
        sys.exit(run(args))
    except Exception as exc:
        print(f"pilot failed safely before/while collecting: {exc}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
