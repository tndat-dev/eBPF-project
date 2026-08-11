"""Evaluate the frozen Tetragon sensitive-syscall rule on paired V8 replay."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path
import shutil
import tempfile
from typing import Any

from build_feature_replay_dataset import injection_intervals, load_rows
from validate_feature_capture import validate_capture


REPORT_SCHEMA = "sentinel-tetragon-rule-replay/v1"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def distribution(values: list[float]) -> dict[str, Any]:
    if not values:
        return {"count": 0}
    ordered = sorted(float(value) for value in values)

    def quantile(fraction: float) -> float:
        position = (len(ordered) - 1) * fraction
        lower, upper = math.floor(position), math.ceil(position)
        if lower == upper:
            return ordered[lower]
        return ordered[lower] + (
            ordered[upper] - ordered[lower]
        ) * (position - lower)

    return {
        "count": len(ordered),
        "minimum": ordered[0],
        "median": quantile(0.50),
        "p95": quantile(0.95),
        "p99": quantile(0.99),
        "maximum": ordered[-1],
    }


def wilson_interval(successes: int, total: int,
                    z: float = 1.959963984540054) -> dict[str, float]:
    if total <= 0 or not 0 <= successes <= total:
        raise ValueError("invalid rule-only detection counts")
    estimate = successes / total
    z2 = z * z
    denominator = 1.0 + z2 / total
    center = (estimate + z2 / (2.0 * total)) / denominator
    radius = z * math.sqrt(
        estimate * (1.0 - estimate) / total
        + z2 / (4.0 * total * total)
    ) / denominator
    return {
        "estimate": estimate,
        "lower": max(0.0, center - radius),
        "upper": min(1.0, center + radius),
        "confidence_level": 0.95,
        "method": "Wilson score interval",
    }


def first_sensitive_event(row: dict, sensitive: set[str]) -> dict | None:
    sequence = row.get("syscall_sequence")
    if not isinstance(sequence, list) or not sequence:
        raise ValueError("Tetragon rule replay requires sequence capture")
    for index, syscall in enumerate(sequence):
        if syscall in sensitive:
            start, end = float(row["window_start"]), float(row["window_end"])
            timestamp = start + (index + 1) / len(sequence) * (end - start)
            return {
                "pod_key": row["pod_key"],
                "run_id": row["run_id"],
                "phase_id": row["phase_id"],
                "traffic_regime": row["traffic_regime"],
                "window_start": start,
                "window_end": end,
                "rule": f"sensitive_syscall:{syscall}",
                "syscall": syscall,
                "estimated_event_ts": timestamp,
                "timestamp_method": "uniform position within captured window",
            }
    return None


def phase_exposure_hours(rows: list[dict]) -> float:
    ranges: dict[tuple[str, str], list[float]] = {}
    for row in rows:
        key = (row["run_id"], row["phase_id"])
        if key not in ranges:
            ranges[key] = [float(row["window_start"]), float(row["window_end"])]
        else:
            ranges[key][0] = min(ranges[key][0], float(row["window_start"]))
            ranges[key][1] = max(ranges[key][1], float(row["window_end"]))
    return sum(end - start for start, end in ranges.values()) / 3600.0


def evaluate_rule_replay(normal_capture: Path, attack_capture: Path,
                         protocol: dict, *, expected_trials: int = 200,
                         horizon_seconds: float = 30.0) -> tuple[dict, list[dict]]:
    normal_validation = validate_capture(normal_capture)
    attack_validation = validate_capture(attack_capture)
    if not normal_validation["valid"]:
        raise ValueError(f"invalid normal capture: {normal_validation['errors']}")
    if not attack_validation["valid"]:
        raise ValueError(f"invalid attack capture: {attack_validation['errors']}")
    if protocol.get("schema") != "sentinel-syscall-evaluation-protocol/v1":
        raise ValueError("invalid syscall evaluation protocol")
    method = protocol.get("methods", {}).get("tetragon_rule_only", {})
    sensitive = set(method.get("sensitive_syscalls", []))
    if not sensitive:
        raise ValueError("Tetragon rule protocol has no sensitive syscalls")

    normal_rows = [
        row for row in load_rows(normal_capture)
        if row.get("kind") == "feature_window"
        and row.get("run_id") in set(
            protocol["shared_replay"]["normal_run_ids"]
        )
    ]
    run_ids = sorted({row["run_id"] for row in normal_rows})
    phases = sorted({(row["run_id"], row["phase_id"]) for row in normal_rows})
    if len(run_ids) != 5 or len(phases) != 20:
        raise ValueError("rule replay requires exactly five runs and 20 phases")
    normal_alerts = [
        alert for row in normal_rows
        if (alert := first_sensitive_event(row, sensitive)) is not None
    ]
    phase_outcomes = []
    for run_id, phase_id in phases:
        phase_rows = [
            row for row in normal_rows
            if row["run_id"] == run_id and row["phase_id"] == phase_id
        ]
        phase_alerts = [
            row for row in normal_alerts
            if row["run_id"] == run_id and row["phase_id"] == phase_id
        ]
        phase_outcomes.append({
            "phase": phase_id,
            "run_id": run_id,
            "windows": len(phase_rows),
            "false_alerts": len(phase_alerts),
            "exposure_seconds": (
                max(float(row["window_end"]) for row in phase_rows)
                - min(float(row["window_start"]) for row in phase_rows)
            ),
        })

    attack_source_rows = load_rows(attack_capture)
    intervals = injection_intervals(attack_source_rows)
    if len(intervals) != expected_trials:
        raise ValueError(
            f"expected {expected_trials} attack intervals, got {len(intervals)}"
        )
    if any(interval.get("attack_exit_code") != 0 for interval in intervals):
        raise ValueError("rule replay attack capture contains failed injection")
    attack_alerts = [
        alert for row in attack_source_rows
        if row.get("kind") == "feature_window"
        and (alert := first_sensitive_event(row, sensitive)) is not None
    ]
    outcomes = []
    latencies = []
    matched_alerts = []
    for interval in intervals:
        matches = [
            alert for alert in attack_alerts
            if alert["pod_key"] == interval["pod_key"]
            and interval["start"] <= alert["estimated_event_ts"]
            <= interval["end"] + horizon_seconds
        ]
        first = min(matches, key=lambda item: item["estimated_event_ts"]) \
            if matches else None
        latency = (
            first["estimated_event_ts"] - interval["start"]
            if first is not None else None
        )
        if latency is not None:
            latencies.append(latency)
            matched_alerts.append({
                "injection_id": interval["injection_id"], **first,
                "latency_seconds": latency,
            })
        outcomes.append({
            "injection_id": interval["injection_id"],
            "pod_key": interval["pod_key"],
            "scenario": interval["scenario"],
            "rate": interval["rate"],
            "seed": interval["seed"],
            "detected": first is not None,
            "first_rule": first["rule"] if first else None,
            "latency_seconds": latency,
        })

    detected = sum(item["detected"] for item in outcomes)
    exposure_hours = phase_exposure_hours(normal_rows)
    report = {
        "schema": REPORT_SCHEMA,
        "release_id": protocol["release_id"],
        "method": "tetragon_rule_only",
        "completed": True,
        "paired_replay": True,
        "labels_used_for_training_or_tuning": False,
        "normal": {
            "independent_runs": len(run_ids),
            "phases": len(phases),
            "windows": len(normal_rows),
            "false_alerts": len(normal_alerts),
            "exposure_hours": exposure_hours,
            "phase_outcomes": phase_outcomes,
            "alerts_per_hour": (
                len(normal_alerts) / exposure_hours if exposure_hours else None
            ),
        },
        "attack": {
            "trials": len(outcomes),
            "detected": detected,
            "recall": wilson_interval(detected, len(outcomes)),
            "post_attack_horizon_seconds": horizon_seconds,
            "outcomes": outcomes,
        },
        "latency_seconds": distribution(latencies),
        "sensitive_syscalls": sorted(sensitive),
        "normal_capture": {
            "path": str(normal_capture.resolve()), "sha256": sha256(normal_capture),
            "validation": normal_validation,
        },
        "attack_capture": {
            "path": str(attack_capture.resolve()), "sha256": sha256(attack_capture),
            "validation": attack_validation,
        },
        "evaluation_protocol_sha256": None,
        "limitations": [
            "syscall event timestamps are estimated from sequence position within each window",
            "rule-only baseline cannot use process arguments or binary identity because V8 excludes them",
        ],
    }
    return report, normal_alerts + matched_alerts


def publish(output_root: Path, report: dict, alerts: list[dict],
            protocol_path: Path) -> None:
    if output_root.exists():
        checksum = output_root / "SHA256SUMS"
        if not checksum.is_file():
            raise ValueError("existing rule-only output is incomplete")
        expected_names = {
            "tetragon-rule-alerts.jsonl", "tetragon-rule-replay.report.json",
        }
        seen = set()
        for line in checksum.read_text().splitlines():
            digest, name = line.split(maxsplit=1)
            name = name.strip()
            path = output_root / name
            if name not in expected_names or not path.is_file():
                raise ValueError("existing rule-only checksum contains invalid path")
            if sha256(path) != digest:
                raise ValueError("existing rule-only output checksum mismatch")
            seen.add(name)
        if seen != expected_names:
            raise ValueError("existing rule-only checksum is incomplete")
        existing = json.loads(
            (output_root / "tetragon-rule-replay.report.json").read_text()
        )
        if existing.get("evaluation_protocol_sha256") != sha256(protocol_path):
            raise ValueError("existing rule-only evaluation protocol mismatch")
        return
    report["evaluation_protocol_sha256"] = sha256(protocol_path)
    output_root.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(
        prefix=f".{output_root.name}.", dir=output_root.parent,
    ))
    try:
        report_path = temporary / "tetragon-rule-replay.report.json"
        alert_path = temporary / "tetragon-rule-alerts.jsonl"
        report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        alert_path.write_text("".join(
            json.dumps(row, sort_keys=True) + "\n" for row in alerts
        ))
        checksum = temporary / "SHA256SUMS"
        checksum.write_text(
            f"{sha256(alert_path)}  {alert_path.name}\n"
            f"{sha256(report_path)}  {report_path.name}\n"
        )
        temporary.replace(output_root)
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--normal-capture", type=Path, required=True)
    parser.add_argument("--attack-capture", type=Path, required=True)
    parser.add_argument("--protocol", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--expected-trials", type=int, default=200)
    parser.add_argument("--post-attack-horizon", type=float, default=30.0)
    args = parser.parse_args()
    protocol = json.loads(args.protocol.read_text())
    report, alerts = evaluate_rule_replay(
        args.normal_capture, args.attack_capture, protocol,
        expected_trials=args.expected_trials,
        horizon_seconds=args.post_attack_horizon,
    )
    publish(args.output_root, report, alerts, args.protocol)
    print(args.output_root)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
