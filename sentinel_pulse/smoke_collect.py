"""Validate a recent collect-only slice before rolling Pulse to all workers."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import tempfile
import time

from .validate_capture import validate


def smoke(
    capture: Path,
    duration_seconds: float = 120.0,
    maximum_age_seconds: float = 5.0,
    maximum_ingest_p99_seconds: float = 0.30,
    maximum_snapshot_p99_seconds: float = 0.30,
    now: float | None = None,
) -> dict:
    headers = []
    features = []
    with capture.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            record = json.loads(line)
            if record.get("schema") == "sentinel-pulse-feature-schema-v1":
                headers.append(record)
            elif record.get("schema") == "sentinel-pulse-feature-v1":
                features.append(record)
            else:
                raise ValueError(f"line {line_number}: unsupported record")
    if not headers or not features:
        raise ValueError("capture has no schema or feature row")
    latest = max(float(record["window_end"]) for record in features)
    cutoff = latest - duration_seconds
    selected = [record for record in features if float(record["window_end"]) >= cutoff]
    earliest = min(float(record["window_end"]) for record in selected)
    with tempfile.TemporaryDirectory() as temporary:
        path = Path(temporary) / "smoke.jsonl"
        records = [headers[-1], *selected]
        path.write_text(
            "".join(json.dumps(record, separators=(",", ":")) + "\n" for record in records),
            encoding="utf-8",
        )
        validation = validate(path, minimum_rows_per_workload=1)
    observed_now = time.time() if now is None else now
    observed_span = latest - earliest
    node_names = sorted(
        {str(record.get("node_name", "")) for record in selected}
    )
    ingest_p99 = validation.get("ingest_lag_seconds", {}).get("p99")
    snapshot_p99 = validation.get("snapshot_read_seconds", {}).get("p99")
    gates = {
        "capture_integrity": validation["valid"],
        "fresh": 0.0 <= observed_now - latest <= maximum_age_seconds,
        "duration": observed_span >= duration_seconds * 0.80,
        "ingest_p99": ingest_p99 is not None and ingest_p99 <= maximum_ingest_p99_seconds,
        "snapshot_read_p99": (
            snapshot_p99 is not None and snapshot_p99 <= maximum_snapshot_p99_seconds
        ),
        "single_node_identity": len(node_names) == 1 and bool(node_names[0]),
    }
    return {
        "schema": "sentinel-pulse-collect-smoke-v1",
        "capture": str(capture),
        "valid": all(gates.values()),
        "gates": gates,
        "rows": len(selected),
        "workloads": validation["workloads"],
        "node_names": node_names,
        "latest_window_end": latest,
        "age_seconds": observed_now - latest,
        "observed_span_seconds": observed_span,
        "ingest_lag_seconds": validation["ingest_lag_seconds"],
        "snapshot_read_seconds": validation["snapshot_read_seconds"],
        "collector_max_drops": validation["collector_max_drops"],
        "errors": validation["errors"],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--capture", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--duration-seconds", type=float, default=120.0)
    parser.add_argument("--maximum-age-seconds", type=float, default=5.0)
    parser.add_argument("--maximum-ingest-p99-seconds", type=float, default=0.30)
    parser.add_argument("--maximum-snapshot-p99-seconds", type=float, default=0.30)
    args = parser.parse_args()
    report = smoke(
        args.capture,
        args.duration_seconds,
        args.maximum_age_seconds,
        args.maximum_ingest_p99_seconds,
        args.maximum_snapshot_p99_seconds,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    raise SystemExit(0 if report["valid"] else 1)


if __name__ == "__main__":
    main()
