"""Measure one immutable overhead phase with repeated ApacheBench runs."""

import argparse
import json
import re
import statistics
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path


def percentile(values, q):
    values = sorted(values)
    position = (len(values) - 1) * q
    low = int(position)
    high = min(low + 1, len(values) - 1)
    return values[low] + (values[high] - values[low]) * (position - low)


def summarize(values):
    values = [float(value) for value in values]
    if not values:
        return None
    return {
        "count": len(values),
        "median": statistics.median(values),
        "p95": percentile(values, 0.95),
        "p99": percentile(values, 0.99),
        "min": min(values),
        "max": max(values),
    }


def cpu_millicores(value):
    if value.endswith("n"):
        return float(value[:-1]) / 1_000_000
    if value.endswith("u"):
        return float(value[:-1]) / 1_000
    if value.endswith("m"):
        return float(value[:-1])
    return float(value) * 1000


def memory_mib(value):
    units = {"Ki": 1 / 1024, "Mi": 1, "Gi": 1024, "Ti": 1024 * 1024}
    match = re.fullmatch(r"([0-9.]+)([A-Za-z]+)?", value)
    if not match:
        raise ValueError(value)
    amount = float(match.group(1))
    return amount * units.get(match.group(2), 1 / (1024 * 1024))


def top_snapshot():
    result = subprocess.run(
        ["kubectl", "top", "pods", "-A", "--no-headers"],
        text=True, capture_output=True,
    )
    rows = []
    if result.returncode == 0:
        for line in result.stdout.splitlines():
            fields = line.split()
            if len(fields) >= 4:
                rows.append({
                    "namespace": fields[0],
                    "pod": fields[1],
                    "cpu_millicores": cpu_millicores(fields[2]),
                    "memory_mib": memory_mib(fields[3]),
                })
    return {
        "ts": time.time(),
        "rows": rows,
        "error": result.stderr.strip() if result.returncode else "",
    }


def systemd_snapshot():
    result = subprocess.run(
        [
            "systemctl", "show", "sentinel-detector",
            "-p", "MainPID", "-p", "ActiveState", "-p", "MemoryCurrent",
            "-p", "CPUUsageNSec", "--no-pager",
        ],
        text=True, capture_output=True,
    )
    values = {}
    for line in result.stdout.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            values[key] = value
    return {"ts": time.time(), **values, "error": result.stderr.strip()}


def parse_ab(text):
    patterns = {
        "requests_per_second": r"Requests per second:\s+([0-9.]+)",
        "time_per_request_concurrent_ms": (
            r"Time per request:\s+([0-9.]+) \[ms\] \(mean, across all concurrent"
        ),
        "failed_requests": r"Failed requests:\s+(\d+)",
    }
    result = {}
    for key, pattern in patterns.items():
        match = re.search(pattern, text)
        result[key] = float(match.group(1)) if match else None
    latency = re.search(r"^\s*99%\s+(\d+)", text, re.MULTILINE)
    result["latency_p99_ms"] = float(latency.group(1)) if latency else None
    return result


def duration_ms(value):
    """Convert a wrk latency token to milliseconds."""
    match = re.fullmatch(r"([0-9.]+)(ns|us|ms|s)", value.strip())
    if not match:
        raise ValueError(value)
    amount = float(match.group(1))
    return amount * {"ns": 1e-6, "us": 1e-3, "ms": 1.0, "s": 1000.0}[
        match.group(2)
    ]


def parse_wrk(text):
    rps = re.search(r"^Requests/sec:\s+([0-9.]+)", text, re.MULTILINE)
    mean = re.search(r"^\s*Latency\s+([0-9.]+(?:ns|us|ms|s))", text, re.MULTILINE)
    p99 = re.search(r"^\s*99%\s+([0-9.]+(?:ns|us|ms|s))", text, re.MULTILINE)
    socket_errors = re.search(
        r"Socket errors: connect (\d+), read (\d+), write (\d+), timeout (\d+)",
        text,
    )
    non_success = re.search(r"Non-2xx or 3xx responses:\s+(\d+)", text)
    errors = sum(int(value) for value in socket_errors.groups()) if socket_errors else 0
    errors += int(non_success.group(1)) if non_success else 0
    return {
        "requests_per_second": float(rps.group(1)) if rps else None,
        "time_per_request_concurrent_ms": duration_ms(mean.group(1)) if mean else None,
        "failed_requests": float(errors),
        "latency_p99_ms": duration_ms(p99.group(1)) if p99 else None,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--phase", required=True)
    parser.add_argument("--url", required=True)
    parser.add_argument("--repeats", type=int, default=5)
    parser.add_argument("--requests", type=int, default=10000)
    parser.add_argument("--concurrency", type=int, default=10)
    parser.add_argument("--tool", choices=("ab", "wrk"), default="ab")
    parser.add_argument("--threads", type=int, default=4)
    parser.add_argument("--duration", type=int, default=30,
                        help="Seconds per wrk repetition")
    parser.add_argument("--output-root", default="overhead-results")
    parser.add_argument("--experiment-id", required=True,
                        help="Binds all phases in one controlled matrix run")
    args = parser.parse_args()

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output = Path(args.output_root) / f"{args.phase}-{stamp}"
    output.mkdir(parents=True, exist_ok=False)
    report = {
        "phase": args.phase,
        "experiment_id": args.experiment_id,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "url": args.url,
        "requests": args.requests,
        "concurrency": args.concurrency,
        "tool": args.tool,
        "threads": args.threads if args.tool == "wrk" else None,
        "duration_seconds": args.duration if args.tool == "wrk" else None,
        "runs": [],
        "top_snapshots": [],
        "systemd_snapshots": [],
    }

    # Unreported warm-up removes connection/cache initialization asymmetry.
    if args.tool == "wrk":
        warmup_command = [
            "wrk", "-t", str(args.threads), "-c", str(args.concurrency),
            "-d", "5s", "--latency", args.url,
        ]
    else:
        warmup_command = [
            "ab", "-n", "1000", "-c", str(args.concurrency), "-k", args.url,
        ]
    subprocess.run(
        warmup_command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        check=True,
    )
    for run_id in range(1, args.repeats + 1):
        report["top_snapshots"].append(top_snapshot())
        report["systemd_snapshots"].append(systemd_snapshot())
        started = time.time()
        if args.tool == "wrk":
            command = [
                "wrk", "-t", str(args.threads), "-c", str(args.concurrency),
                "-d", f"{args.duration}s", "--latency", args.url,
            ]
        else:
            command = [
                "ab", "-n", str(args.requests), "-c", str(args.concurrency),
                "-k", args.url,
            ]
        result = subprocess.run(command, text=True, capture_output=True)
        elapsed = time.time() - started
        raw_path = output / f"{args.tool}-{run_id}.txt"
        raw_path.write_text(result.stdout + "\nSTDERR\n" + result.stderr)
        report["runs"].append({
            "run": run_id,
            "exit_code": result.returncode,
            "wall_seconds": elapsed,
            "raw": str(raw_path),
            **(parse_wrk(result.stdout) if args.tool == "wrk" else parse_ab(result.stdout)),
        })
        report["top_snapshots"].append(top_snapshot())
        report["systemd_snapshots"].append(systemd_snapshot())
        time.sleep(2)

    for field in (
        "requests_per_second", "time_per_request_concurrent_ms",
        "latency_p99_ms", "wall_seconds",
    ):
        report[field] = summarize(
            run[field] for run in report["runs"] if run[field] is not None
        )
    report["failed_requests_total"] = sum(
        int(run["failed_requests"] or 0) for run in report["runs"]
    )

    tetragon_cpu, tetragon_memory = [], []
    nginx_cpu, nginx_memory = [], []
    for snapshot in report["top_snapshots"]:
        for row in snapshot["rows"]:
            if row["namespace"] == "kube-system" and row["pod"].startswith("tetragon-"):
                tetragon_cpu.append(row["cpu_millicores"])
                tetragon_memory.append(row["memory_mib"])
            if row["namespace"] == "production" and row["pod"].startswith("nginx-"):
                nginx_cpu.append(row["cpu_millicores"])
                nginx_memory.append(row["memory_mib"])
    report["tetragon_cpu_millicores"] = summarize(tetragon_cpu)
    report["tetragon_memory_mib"] = summarize(tetragon_memory)
    report["nginx_cpu_millicores"] = summarize(nginx_cpu)
    report["nginx_memory_mib"] = summarize(nginx_memory)
    report["completed_at"] = datetime.now(timezone.utc).isoformat()

    path = output / "report.json"
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(path)
    return 0 if all(run["exit_code"] == 0 for run in report["runs"]) else 7


if __name__ == "__main__":
    raise SystemExit(main())
