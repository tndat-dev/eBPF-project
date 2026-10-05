"""Read bounded cgroup-v2 counters; never change limits or infer causality."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import time

SERVICES = (
    "sentinel-pulse-collector-500ms-experiment.service",
    "sentinel-pulse-detector-candidate.service",
    "sentinel-pulse-collector.service",
)
FILES = (
    "cpu.stat", "cpu.pressure", "memory.current", "memory.peak",
    "memory.high", "memory.max", "memory.events", "memory.stat",
    "memory.pressure", "io.stat", "io.pressure",
)
MAX_READ_BYTES = 16384


def sample(root: Path = Path("/sys/fs/cgroup/system.slice")) -> dict:
    result = {"schema": "sentinel-pulse-cgroup-pressure-v1",
              "observed_at": time.time(), "services": {}}
    for service in SERVICES:
        entry = {"cgroup_path": str(root / service), "files": {}, "read_errors": {}}
        for name in FILES:
            try:
                # Do not read arbitrary process environment, args or payload.
                with (root / service / name).open("rb") as stream:
                    data = stream.read(MAX_READ_BYTES + 1)
                if len(data) > MAX_READ_BYTES:
                    raise ValueError("cgroup diagnostic field exceeds read bound")
                entry["files"][name] = data.decode("utf-8").strip()
            except (OSError, ValueError, UnicodeError) as error:
                entry["read_errors"][name] = type(error).__name__ + ": " + str(error)
        result["services"][service] = entry
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    # Retain missing/unsupported fields explicitly; this is not a health gate.
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(sample(), stream, sort_keys=True, allow_nan=False)
        stream.write("\n")


if __name__ == "__main__":
    main()
