"""Review a completed collector-only canary without promoting any runtime.

Recompute validation from raw capture; bind duration, explicit node coverage,
source hashes and terminal receipts. A good tail/exit code alone is not PASS.
"""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path

from .integrity import sha256_file, verify_sha256
from .validate_capture import validate


REQUIRED_SOURCE_PATHS = frozenset({
    "sentinel_pulse/ebpf/pulse_counter_projected_loader",
    "sentinel_pulse/ebpf/pulse_counter_projected.bpf.o",
    "sentinel_pulse/ebpf/pulse_counter.bpf.c",
    "sentinel_pulse/ebpf/pulse_counter_loader.c",
    "sentinel_pulse/ebpf/pulse_counter_projection.h",
    "sentinel_pulse/ebpf/pulse_counter_ids.h",
    "sentinel_pulse/capture.py", "sentinel_pulse/features.py",
    "sentinel_pulse/encoding.py", "sentinel_pulse/validate_capture.py",
    "sentinel_pulse/run_projected_counter_canary.sh",
})


def evaluate(run_dir: Path, expected_workload_keys: list[str]) -> dict:
    report = {
        "schema": "sentinel-pulse-projected-counter-canary-review-v1",
        "valid": False, "evidence_class": "nonformal_collector_safety_review",
        "ML_evaluation": False, "accuracy_claim_allowed": False,
        "automatic_promotion": False, "run_dir": str(run_dir), "errors": [],
        "duration_slack_seconds": 2.0,
    }
    errors = report["errors"]
    try:
        if (not isinstance(expected_workload_keys, list) or not expected_workload_keys or
                any(not isinstance(k, str) or not k for k in expected_workload_keys) or
                len(set(expected_workload_keys)) != len(expected_workload_keys)):
            raise ValueError("explicit, nonempty, unique node workload keys required")
        report["expected_workload_keys"] = sorted(expected_workload_keys)
        start = json.loads((run_dir / "START.json").read_text())
        terminal = json.loads((run_dir / "TERMINAL.json").read_text())
        stored = json.loads((run_dir / "VALIDATION.json").read_text())
        if start.get("schema") != "sentinel-pulse-projected-counter-canary-start-v1":
            raise ValueError("unsupported start receipt")
        if terminal.get("schema") != "sentinel-pulse-projected-counter-canary-terminal-v1":
            raise ValueError("unsupported terminal receipt")
        report["run_id"] = start["run_id"]
        for receipt in (start, terminal):
            if (receipt.get("ML_evaluation") is not False or
                    receipt.get("automatic_promotion") is not False):
                errors.append("receipt is not an isolated collector-only canary")
        if start.get("control_collector_remains_active") is not True:
            errors.append("control collector retention was not registered")
        if start.get("window_seconds") != 0.5:
            errors.append("canary cadence is not 500 ms")
        duration = start["registered_duration_seconds"]
        if type(duration) is not int or not 60 <= duration <= 3600:
            raise ValueError("invalid registered duration")
        started = float(start["started_at_unix"])
        ended = float(terminal["completed_at_unix"])
        if not all(math.isfinite(t) for t in (started, ended)):
            raise ValueError("nonfinite receipt timestamp")
        report["registered_duration_seconds"] = duration
        report["terminal_elapsed_seconds"] = ended - started
        if ended - started < duration:
            errors.append("terminal occurred before registered duration")
        if any(type(terminal.get(k)) is not int or terminal[k] != 0
               for k in ("capture_exit_code", "validation_exit_code")):
            errors.append("capture or validation exit code failed/missing")

        root = Path(start["source_root"]).resolve()
        hashes = start["sha256"]
        if not REQUIRED_SOURCE_PATHS <= hashes.keys():
            raise ValueError("source receipt omits required collector artifacts")
        for name, expected in hashes.items():
            relative = Path(name)
            artifact = (root / relative).resolve()
            if relative.is_absolute() or not artifact.is_relative_to(root):
                raise ValueError("source artifact path escapes source root")
            verify_sha256(artifact, expected)
        report["source_hashes_match"] = True
        capture = run_dir / "features.jsonl"
        verify_sha256(capture, stored["capture_sha256"])
        report["capture_sha256"] = sha256_file(capture)
        if stored.get("valid") is not True:
            errors.append("registered full validation was not valid")
        full = validate(capture, minimum_rows_per_workload=100,
                        interval_min_seconds=0.35, interval_max_seconds=0.80,
                        nominal_interval_seconds=0.5,
                        minimum_telemetry_availability=1.0,
                        maximum_single_gap_seconds=0.80)
        report["recomputed_validation"] = full
        errors.extend(full["errors"])
        if full["feature_dim"] != 249:
            errors.append("feature schema dimension is not 249")
        actual = set(full["workloads"])
        expected = set(expected_workload_keys)
        report["missing_workload_keys"] = sorted(expected - actual)
        report["unexpected_workload_keys"] = sorted(actual - expected)
        if actual != expected:
            errors.append("node workload coverage differs from explicit expectation")

        first, last = math.inf, -math.inf
        with capture.open() as stream:
            for line in stream:
                row = json.loads(line)
                if row.get("schema") == "sentinel-pulse-feature-v1":
                    first = min(first, float(row["window_start"]))
                    last = max(last, float(row["window_end"]))
        span = last - first
        if not all(math.isfinite(t) for t in (first, last, span)):
            raise ValueError("capture has no finite measured interval")
        report.update(first_window_start=first, last_window_end=last,
                      measured_span_seconds=span)
        if span < duration - report["duration_slack_seconds"]:
            errors.append("capture ended early despite successful terminal codes")
        if first < started or last > ended:
            errors.append("capture timestamps are outside registered run")
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as error:
        errors.append(str(error))
    report["valid"] = not errors
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--expected-workload-keys", type=Path, required=True,
                        help="JSON list: explicit workload/container keys on this node")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = evaluate(args.run_dir, json.loads(args.expected_workload_keys.read_text()))
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        with args.output.open("x") as stream:
            stream.write(rendered)
    else:
        print(rendered, end="")
    raise SystemExit(0 if report["valid"] else 1)


if __name__ == "__main__":
    main()
