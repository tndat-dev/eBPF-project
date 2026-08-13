"""Freeze Falco rule-only outcomes for the V8 blind attack intervals."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import math
import os
from pathlib import Path
import shutil
import tempfile
import time
from typing import Any

from build_feature_replay_dataset import injection_intervals, load_rows
from falco_evidence_finalizer import (
    EvidenceError, EvidenceNotSettled, read_json, sha256, validate_alert,
    validate_collector,
)
from validate_feature_capture import validate_capture


REPORT_SCHEMA = "sentinel-falco-attack-evidence/v2"


def distribution(values: list[float]) -> dict[str, Any]:
    if not values:
        return {"count": 0}
    data = sorted(float(value) for value in values)

    def quantile(fraction: float) -> float:
        position = (len(data) - 1) * fraction
        lower = math.floor(position)
        upper = math.ceil(position)
        if lower == upper:
            return data[lower]
        return data[lower] + (data[upper] - data[lower]) * (position - lower)

    return {
        "count": len(data),
        "minimum": data[0],
        "median": quantile(0.50),
        "p95": quantile(0.95),
        "p99": quantile(0.99),
        "maximum": data[-1],
    }


def wilson_interval(successes: int, total: int, z: float = 1.959963984540054
                    ) -> dict[str, float]:
    if total <= 0 or not 0 <= successes <= total:
        raise EvidenceError("invalid Falco attack detection counts")
    proportion = successes / total
    z2 = z * z
    denominator = 1.0 + z2 / total
    center = (proportion + z2 / (2.0 * total)) / denominator
    radius = z * math.sqrt(
        proportion * (1.0 - proportion) / total + z2 / (4.0 * total * total)
    ) / denominator
    return {
        "estimate": proportion,
        "lower": max(0.0, center - radius),
        "upper": min(1.0, center + radius),
        "confidence_level": 0.95,
        "method": "Wilson score interval",
    }


def load_falco_rows(falco_root: Path, release_id: str) -> tuple[list[dict], str | None]:
    path = falco_root / "falco-alerts.jsonl"
    if not path.is_file():
        return [], None
    rows = []
    seen = set()
    for line in path.read_text().splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except (ValueError, TypeError) as exc:
            raise EvidenceError("malformed Falco attack source row") from exc
        if not isinstance(row, dict):
            raise EvidenceError("Falco attack source row must be an object")
        validate_alert(row, release_id)
        if row["event_id"] in seen:
            raise EvidenceError("duplicate Falco attack source event ID")
        seen.add(row["event_id"])
        rows.append(row)
    return rows, sha256(path)


def existing_report(output_root: Path) -> dict[str, Any] | None:
    checksum = output_root / "SHA256SUMS"
    report_path = output_root / "falco-attack-evidence.report.json"
    alert_path = output_root / "falco-attack-alerts.jsonl"
    if not output_root.exists():
        return None
    if not all(path.is_file() for path in (checksum, report_path, alert_path)):
        raise EvidenceError("existing Falco attack derivative is incomplete")
    expected = {}
    for line in checksum.read_text().splitlines():
        digest, name = line.split(maxsplit=1)
        expected[name.strip()] = digest
    if (
        expected.get(report_path.name) != sha256(report_path)
        or expected.get(alert_path.name) != sha256(alert_path)
    ):
        raise EvidenceError("existing Falco attack derivative checksum mismatch")
    report = json.loads(report_path.read_text())
    if report.get("schema") != REPORT_SCHEMA or report.get("valid") is not True:
        raise EvidenceError("existing Falco attack report is invalid")
    return report


def finalize(
    attack_capture: Path,
    falco_root: Path,
    collection_contract: Path,
    output_root: Path,
    *,
    expected_trials: int = 200,
    post_attack_horizon: float = 30.0,
    next_injection_guard: float = 1.0,
    minimum_settle_seconds: float = 30.0,
    max_state_age: float = 120.0,
    now: float | None = None,
) -> dict[str, Any]:
    if post_attack_horizon < 0 or next_injection_guard < 0:
        raise EvidenceError("Falco attribution horizons/guard must be non-negative")
    output_root = output_root.resolve()
    prior = existing_report(output_root)
    if prior is not None:
        return prior
    now = time.time() if now is None else now
    attack_capture = attack_capture.resolve()
    validation = validate_capture(attack_capture)
    if not validation["valid"]:
        raise EvidenceError(f"invalid paired attack capture: {validation['errors']}")
    rows = load_rows(attack_capture)
    try:
        intervals = injection_intervals(rows)
    except ValueError as exc:
        raise EvidenceError(str(exc)) from exc
    if len(intervals) != expected_trials:
        raise EvidenceError(
            f"Falco attack interval count mismatch: {len(intervals)}/{expected_trials}"
        )
    if any(item.get("attack_exit_code") != 0 for item in intervals):
        raise EvidenceError("Falco attack evidence contains a failed injection")
    intervals.sort(key=lambda item: (item["start"], item["injection_id"]))
    by_pod: dict[str, list[dict[str, Any]]] = {}
    for interval in intervals:
        by_pod.setdefault(str(interval["pod_key"]), []).append(interval)
    for pod_intervals in by_pod.values():
        for index, interval in enumerate(pod_intervals):
            next_start = (
                float(pod_intervals[index + 1]["start"])
                if index + 1 < len(pod_intervals) else None
            )
            if next_start is not None and float(interval["end"]) > next_start:
                raise EvidenceError("Falco attack intervals overlap on one pod")
            requested_end = float(interval["end"]) + post_attack_horizon
            guarded_next_start = (
                max(float(interval["end"]), next_start - next_injection_guard)
                if next_start is not None else None
            )
            attribution_end = (
                min(requested_end, guarded_next_start)
                if guarded_next_start is not None else requested_end
            )
            if attribution_end <= float(interval["start"]):
                raise EvidenceError("Falco attribution interval is empty")
            interval["attribution_end"] = attribution_end
            interval["requested_attribution_end"] = requested_end
            interval["effective_post_attack_horizon_seconds"] = max(
                0.0, attribution_end - float(interval["end"])
            )
            interval["horizon_right_censored_by_next_injection"] = bool(
                attribution_end < requested_end
            )
            interval["next_injection_guard_applied"] = bool(
                next_start is not None and attribution_end < requested_end
            )

    contract, _ = read_json(collection_contract)
    release_id = str(contract.get("release_id", ""))
    evidence_intervals = [
        (float(item["start"]), float(item["attribution_end"]))
        for item in intervals
    ]
    state, provenance, failure_scope = validate_collector(
        falco_root.resolve(), release_id=release_id,
        first_phase_start=float(intervals[0]["start"]),
        last_phase_end=max(float(item["attribution_end"]) for item in intervals),
        evidence_intervals=evidence_intervals,
        now=now, max_state_age=max_state_age,
        minimum_settle_seconds=minimum_settle_seconds,
    )
    falco_rows, falco_sha = load_falco_rows(falco_root.resolve(), release_id)
    if not falco_rows and int(state.get("privacy_safe_rows_written", -1)) != 0:
        raise EvidenceError("Falco state reports alerts but the source file is absent")

    by_id = {item["injection_id"]: {
        **item, "detected": False, "alert_count": 0,
        "first_alert_latency_seconds": None, "rules": [],
    } for item in intervals}
    matched_rows = []
    for row in falco_rows:
        timestamp = float(row["event_ts"])
        pod_key = f"{row['target_namespace']}/{row['target_pod']}"
        matches = [
            interval for interval in intervals
            if interval["pod_key"] == pod_key
            and interval["start"] <= timestamp < interval["attribution_end"]
        ]
        if len(matches) > 1:
            raise EvidenceError("Falco alert maps to multiple blind trials")
        if not matches:
            continue
        interval = matches[0]
        item = by_id[interval["injection_id"]]
        latency = max(0.0, timestamp - interval["start"])
        item["detected"] = True
        item["alert_count"] += 1
        item["rules"].append(str(row["rule"]))
        if item["first_alert_latency_seconds"] is None:
            item["first_alert_latency_seconds"] = latency
        else:
            item["first_alert_latency_seconds"] = min(
                item["first_alert_latency_seconds"], latency
            )
        matched_rows.append({
            **row,
            "injection_id": interval["injection_id"],
            "scenario": interval["scenario"],
            "trial_seed": interval["seed"],
            "trial_rate": interval["rate"],
            "latency_seconds": latency,
        })

    trials = []
    for item in by_id.values():
        item["rules"] = sorted(set(item["rules"]))
        trials.append(item)
    trials.sort(key=lambda item: (item["start"], item["injection_id"]))
    detected = sum(item["detected"] for item in trials)
    latencies = [
        float(item["first_alert_latency_seconds"])
        for item in trials if item["first_alert_latency_seconds"] is not None
    ]
    report: dict[str, Any] = {
        "schema": REPORT_SCHEMA,
        "valid": True,
        "created_at": datetime.fromtimestamp(now, timezone.utc).isoformat(),
        "release_id": release_id,
        "method": (
            "Falco rule-only; first privacy-safe alert per non-overlapping "
            "same-pod injection horizon"
        ),
        "trial_count": len(trials),
        "detected_trials": detected,
        "recall": wilson_interval(detected, len(trials)),
        "latency_seconds": distribution(latencies),
        "matched_alert_count": len(matched_rows),
        "source_falco_alert_count": len(falco_rows),
        "post_attack_horizon_seconds": post_attack_horizon,
        "next_injection_boundary_guard_seconds": next_injection_guard,
        "horizon_attribution_policy": (
            "[injection_start, min(injection_end + requested_horizon, "
            "next_same_pod_injection_start - boundary_guard)); never censor "
            "before injection_end; right-censor before a later injection"
        ),
        "right_censored_trial_count": sum(
            bool(item["horizon_right_censored_by_next_injection"])
            for item in trials
        ),
        "effective_post_attack_horizon_seconds": distribution([
            float(item["effective_post_attack_horizon_seconds"])
            for item in trials
        ]),
        "trials": trials,
        "coverage": {
            "expected_readers": state["expected_readers"],
            "active_readers": state["active_readers"],
            "stream_failures": failure_scope["in_scope_count"],
            "lifetime_stream_failures": failure_scope["lifetime_count"],
            "out_of_scope_stream_failures": failure_scope["out_of_scope_count"],
            "stream_failure_scope": failure_scope,
            "stream_reconnects": int(state.get("stream_reconnects", 0)),
            "raw_lines_observed": state["lines_seen"],
            "healthy_at_finalization": True,
        },
        "privacy": {
            "raw_falco_output_stored": False,
            "command_arguments_stored": False,
            "file_paths_stored": False,
            "network_payloads_stored": False,
        },
        "provenance_sha256": {
            "attack_capture": sha256(attack_capture),
            "falco_collection_contract": sha256(collection_contract),
            **provenance,
            **({"source_falco_alerts": falco_sha} if falco_sha else {}),
        },
        "claim_scope": (
            "Falco rule-only recall on the frozen V8 blind attack intervals; "
            "same-pod post-attack horizons are right-censored at the next "
            "injection to prevent ambiguous attribution; normal alert rate is "
            "reported by the separate normal finalizer."
        ),
    }

    output_root.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{output_root.name}-", dir=output_root.parent))
    try:
        alert_path = staging / "falco-attack-alerts.jsonl"
        alert_path.write_text("".join(
            json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n"
            for row in matched_rows
        ))
        report_path = staging / "falco-attack-evidence.report.json"
        report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        (staging / "SHA256SUMS").write_text(
            f"{sha256(alert_path)}  {alert_path.name}\n"
            f"{sha256(report_path)}  {report_path.name}\n"
        )
        for path in staging.iterdir():
            os.chmod(path, 0o600)
        staging.replace(output_root)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--attack-capture", required=True, type=Path)
    parser.add_argument("--falco-root", required=True, type=Path)
    parser.add_argument("--collection-contract", required=True, type=Path)
    parser.add_argument("--output-root", required=True, type=Path)
    parser.add_argument("--expected-trials", type=int, default=200)
    parser.add_argument("--post-attack-horizon", type=float, default=30.0)
    parser.add_argument("--next-injection-guard", type=float, default=1.0)
    args = parser.parse_args()
    try:
        report = finalize(
            args.attack_capture, args.falco_root, args.collection_contract,
            args.output_root, expected_trials=args.expected_trials,
            post_attack_horizon=args.post_attack_horizon,
            next_injection_guard=args.next_injection_guard,
        )
    except EvidenceNotSettled as exc:
        print(f"WAITING: {exc}")
        return 75
    except EvidenceError as exc:
        print(f"REFUSING: {exc}")
        return 4
    print(json.dumps({
        "valid": report["valid"], "trial_count": report["trial_count"],
        "detected_trials": report["detected_trials"],
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
