"""Bounded, read-only clock/PSI observer; not a detector or a health gate."""
from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path
import socket
import time

try:
    from .cgroup_pressure import sample as sample_cgroups
except ImportError:
    # record_node_pressure.sh invokes this standalone script from its source.
    from cgroup_pressure import sample as sample_cgroups


def clock_delta(previous: dict, current: dict, interval: float) -> dict:
    monotonic = current["monotonic"] - previous["monotonic"]
    realtime = current["realtime"] - previous["realtime"]
    boottime = current["boottime"] - previous["boottime"]
    return {
        "elapsed_monotonic_seconds": monotonic,
        "elapsed_realtime_seconds": realtime,
        "realtime_minus_monotonic_seconds": realtime - monotonic,
        "boottime_minus_monotonic_seconds": boottime - monotonic,
        "observer_late": monotonic > interval * 1.5,
        # This is evidence of an offset change, not proof of its cause.
        "clock_offset_changed": abs(realtime - monotonic) > 0.25,
    }


def sample() -> dict:
    started = time.monotonic()
    result = {
        "realtime": time.time(),
        "monotonic": started,
        "boottime": time.clock_gettime(time.CLOCK_BOOTTIME),
        "pressure": {},
        "read_errors": {},
    }
    for kind in ("cpu", "io", "memory"):
        try:
            result["pressure"][kind] = Path(f"/proc/pressure/{kind}").read_text().strip()
        except OSError as error:
            result["read_errors"][kind] = str(error)
    result["service_cgroups"] = sample_cgroups()
    result["sample_read_seconds"] = time.monotonic() - started
    return result


def positive_finite(value: str) -> float:
    number = float(value)
    if not math.isfinite(number) or number <= 0:
        raise argparse.ArgumentTypeError("must be positive and finite")
    return number


def run(output: Path, duration: float, interval: float) -> dict:
    if not 0 < duration <= 90000 or not 0.1 <= interval <= 60:
        raise ValueError("duration must be (0,90000], interval must be [0.1,60]")
    summary = {"record_type": "complete", "samples": 0, "late_samples": 0,
               "clock_offset_changes": 0, "max_elapsed_monotonic_seconds": 0.0}
    # Exclusive creation preserves previous observations. No process env or
    # application payload is recorded. Bounds use monotonic, not wall clock.
    with output.open("x", encoding="utf-8", buffering=1) as stream:
        def emit(value: dict) -> None:
            stream.write(json.dumps(value, sort_keys=True, allow_nan=False) + "\n")

        emit({"record_type": "start", "host": socket.getfqdn(),
              "duration_seconds": duration, "interval_seconds": interval,
              "source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "cgroup_probe_sha256": hashlib.sha256(Path(__file__).with_name("cgroup_pressure.py").read_bytes()).hexdigest(),
              "purpose": "infrastructure_diagnostic_only"})
        previous = None
        deadline = time.monotonic() + duration
        while time.monotonic() < deadline:
            current = sample()
            current["record_type"] = "sample"
            if previous is not None:
                delta = clock_delta(previous, current, interval)
                current.update(delta)
                summary["late_samples"] += int(delta["observer_late"])
                summary["clock_offset_changes"] += int(delta["clock_offset_changed"])
                summary["max_elapsed_monotonic_seconds"] = max(
                    summary["max_elapsed_monotonic_seconds"], delta["elapsed_monotonic_seconds"])
            emit(current)
            summary["samples"] += 1
            previous = current
            # Never fabricate catch-up samples after a stall.
            remaining = deadline - time.monotonic()
            if remaining > 0:
                time.sleep(min(interval, remaining))
        emit(summary)
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--duration-seconds", type=positive_finite, required=True)
    parser.add_argument("--interval-seconds", type=positive_finite, default=1.0)
    args = parser.parse_args()
    print(json.dumps(run(args.output, args.duration_seconds, args.interval_seconds)))


if __name__ == "__main__":
    main()
