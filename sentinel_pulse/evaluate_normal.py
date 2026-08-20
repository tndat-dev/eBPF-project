"""Evaluate an independent normal soak without tuning the frozen candidate."""

from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import json
import math
from pathlib import Path

from .integrity import sha256_file


SCORED_STATUSES = frozenset({"normal", "alert", "suppressed"})


def _sha256_identity(value: object) -> str | None:
    identity = str(value or "")
    if len(identity) != 64 or any(
        character not in "0123456789abcdef" for character in identity
    ):
        return None
    return identity


def _timestamp(value: object, field: str) -> float:
    try:
        parsed = datetime.fromisoformat(str(value))
    except ValueError as error:
        raise ValueError(f"soak marker has invalid {field}") from error
    if parsed.tzinfo is None:
        raise ValueError(f"soak marker {field} must include a timezone")
    return parsed.timestamp()


def load_soak_marker(
    path: Path,
    minimum_duration_hours: float,
    minimum_coverage_ratio: float,
    maximum_alerts: int,
) -> dict:
    marker = json.loads(path.read_text(encoding="utf-8"))
    if not str(marker.get("schema", "")).startswith(
        "sentinel-pulse-semantic-soak-start-"
    ):
        raise ValueError("unsupported Sentinel Pulse soak marker")
    if marker.get("blind_evaluation_started") is not False:
        raise ValueError("soak marker indicates blind evaluation already started")
    model_sha256 = _sha256_identity(marker.get("model_manifest_sha256"))
    policy_sha256 = _sha256_identity(marker.get("decision_policy_sha256"))
    run_id = str(marker.get("run_id", ""))
    if model_sha256 is None or policy_sha256 is None or not run_id:
        raise ValueError("soak marker has invalid candidate identity")
    started_at = _timestamp(marker.get("started_not_before"), "started_not_before")
    eligible_at = _timestamp(
        marker.get("eligible_finalize_after"), "eligible_finalize_after"
    )
    marker_duration = float(marker.get("minimum_duration_hours_per_workload", 0.0))
    marker_coverage = float(marker.get("minimum_coverage_ratio_per_workload", 0.0))
    marker_alerts = int(marker.get("maximum_alerts", -1))
    if (
        not math.isfinite(marker_duration)
        or not math.isfinite(marker_coverage)
        or marker_duration <= 0.0
        or not 0.0 < marker_coverage <= 1.0
        or marker_alerts < 0
        or marker_duration < minimum_duration_hours
        or marker_coverage < minimum_coverage_ratio
        or marker_alerts > maximum_alerts
        or eligible_at - started_at < marker_duration * 3600.0
    ):
        raise ValueError("soak marker weakens the requested normal protocol")
    return {
        "sha256": sha256_file(path),
        "model_manifest_sha256": model_sha256,
        "decision_policy_sha256": policy_sha256,
        "run_id": run_id,
        "started_at": started_at,
        "eligible_at": eligible_at,
        "started_not_before": marker["started_not_before"],
        "eligible_finalize_after": marker["eligible_finalize_after"],
    }


def load_model_manifest(path: Path) -> dict:
    manifest = json.loads(path.read_text(encoding="utf-8"))
    workloads = manifest.get("workloads")
    if not isinstance(workloads, dict) or not workloads:
        raise ValueError("model manifest has no workload mapping")
    expected = sorted(str(workload) for workload in workloads)
    if any(not workload or workload == "unknown" for workload in expected):
        raise ValueError("model manifest contains an invalid workload key")
    return {
        "sha256": sha256_file(path),
        "expected_workloads": expected,
    }


def wilson_interval(successes: int, trials: int, z: float = 1.959963984540054) -> tuple[float, float]:
    if trials <= 0:
        return 0.0, 1.0
    proportion = successes / trials
    denominator = 1.0 + z * z / trials
    centre = (proportion + z * z / (2.0 * trials)) / denominator
    margin = z * math.sqrt(
        proportion * (1.0 - proportion) / trials + z * z / (4.0 * trials * trials)
    ) / denominator
    lower = 0.0 if successes == 0 else max(0.0, centre - margin)
    upper = 1.0 if successes == trials else min(1.0, centre + margin)
    return lower, upper


def evaluate(
    path: Path,
    maximum_alerts: int = 0,
    minimum_scored_windows: int = 86400,
    minimum_duration_hours: float = 24.0,
    minimum_coverage_ratio: float = 0.95,
    soak_marker_path: Path | None = None,
    now: float | None = None,
    model_manifest_path: Path | None = None,
) -> dict:
    if maximum_alerts < 0:
        raise ValueError("maximum alerts must be non-negative")
    if minimum_scored_windows <= 0:
        raise ValueError("minimum scored windows must be positive")
    if not math.isfinite(minimum_duration_hours) or minimum_duration_hours <= 0.0:
        raise ValueError("minimum duration hours must be finite and positive")
    if not 0.0 < minimum_coverage_ratio <= 1.0:
        raise ValueError("minimum coverage ratio must be in (0, 1]")
    statuses = Counter()
    workload_scored = Counter()
    workload_alerts = Counter()
    workload_bounds: dict[str, list[float]] = {}
    workload_second_buckets: dict[str, set[int]] = {}
    model_identities = set()
    decision_policy_identities = set()
    run_identities = set()
    excluded_before_marker = 0
    marker = (
        load_soak_marker(
            soak_marker_path,
            minimum_duration_hours,
            minimum_coverage_ratio,
            maximum_alerts,
        )
        if soak_marker_path is not None
        else None
    )
    model_manifest = (
        load_model_manifest(model_manifest_path)
        if model_manifest_path is not None
        else None
    )
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            try:
                record = json.loads(line)
            except json.JSONDecodeError as error:
                raise ValueError(f"line {line_number}: invalid JSON: {error}") from error
            status = str(record.get("status", "unknown"))
            is_decision = record.get("schema") == "sentinel-pulse-decision-v1"
            if is_decision and status not in SCORED_STATUSES | {"warming"}:
                raise ValueError(
                    f"line {line_number}: unsupported decision status: {status}"
                )
            is_scored = (
                is_decision and status in SCORED_STATUSES
            )
            if is_scored:
                try:
                    end = float(record["window_end"])
                except (KeyError, TypeError, ValueError) as error:
                    raise ValueError(
                        f"line {line_number}: scored decision has invalid window_end"
                    ) from error
                if not math.isfinite(end):
                    raise ValueError(
                        f"line {line_number}: scored decision has invalid window_end"
                    )
                if marker is not None and end < marker["started_at"]:
                    excluded_before_marker += 1
                    continue
            statuses[status] += 1
            if not is_scored:
                continue
            model_identities.add(str(record.get("model_manifest_sha256", "")))
            policy_identity = record.get("decision_policy_sha256")
            if policy_identity is not None:
                decision_policy_identities.add(str(policy_identity))
            run_identities.add(str(record.get("run_id", "")))
            workload = str(record.get("workload_key", "unknown"))
            workload_scored[workload] += 1
            if "window_end" in record:
                end = float(record["window_end"])
                bounds = workload_bounds.setdefault(workload, [end, end])
                bounds[0] = min(bounds[0], end)
                bounds[1] = max(bounds[1], end)
                workload_second_buckets.setdefault(workload, set()).add(math.floor(end))
            if status == "alert":
                workload_alerts[workload] += 1

    scored = statuses["normal"] + statuses["alert"] + statuses["suppressed"]
    alerts = statuses["alert"]
    lower, upper = wilson_interval(alerts, scored)
    workload_reports = {}
    for workload, count in sorted(workload_scored.items()):
        workload_count_alerts = workload_alerts[workload]
        workload_lower, workload_upper = wilson_interval(workload_count_alerts, count)
        bounds = workload_bounds.get(workload)
        duration_hours = (bounds[1] - bounds[0]) / 3600.0 if bounds else 0.0
        buckets = workload_second_buckets.get(workload, set())
        span_seconds = (
            math.floor(bounds[1]) - math.floor(bounds[0]) + 1 if bounds else 0
        )
        coverage_seconds = len(buckets)
        coverage_ratio = coverage_seconds / span_seconds if span_seconds else 0.0
        workload_reports[workload] = {
            "scored_windows": count,
            "alerts": workload_count_alerts,
            "observed_false_alert_rate": workload_count_alerts / count,
            "false_alert_rate_wilson_95": [workload_lower, workload_upper],
            "observed_duration_hours": duration_hours,
            "duration_gate": duration_hours >= minimum_duration_hours,
            "observed_second_buckets": coverage_seconds,
            "span_seconds": span_seconds,
            "coverage_ratio": coverage_ratio,
            "coverage_gate": (
                coverage_seconds >= minimum_duration_hours * 3600.0 * minimum_coverage_ratio
                and coverage_ratio >= minimum_coverage_ratio
            ),
        }
    duration_gate = bool(workload_reports) and all(
        item["duration_gate"] for item in workload_reports.values()
    )
    coverage_gate = bool(workload_reports) and all(
        item["coverage_gate"] for item in workload_reports.values()
    )
    model_identity_gate = (
        len(model_identities) == 1
        and len(next(iter(model_identities))) == 64
        and all(character in "0123456789abcdef" for character in next(iter(model_identities)))
    )
    model_manifest_sha256 = next(iter(model_identities)) if model_identity_gate else None
    decision_policy_identity_gate = (
        len(decision_policy_identities) == 1
        and len(next(iter(decision_policy_identities))) == 64
        and all(
            character in "0123456789abcdef"
            for character in next(iter(decision_policy_identities))
        )
    )
    decision_policy_sha256 = (
        next(iter(decision_policy_identities))
        if decision_policy_identity_gate
        else None
    )
    run_identity_gate = len(run_identities) == 1 and bool(next(iter(run_identities), ""))
    run_id = next(iter(run_identities)) if run_identity_gate else None
    observed_workloads = set(workload_reports)
    expected_workloads = (
        set(model_manifest["expected_workloads"])
        if model_manifest is not None
        else set()
    )
    missing_workloads = sorted(expected_workloads - observed_workloads)
    unexpected_workloads = sorted(observed_workloads - expected_workloads)
    expected_workload_gate = bool(
        model_manifest is not None
        and not missing_workloads
        and not unexpected_workloads
    )
    model_manifest_gate = bool(
        model_manifest is not None
        and model_identity_gate
        and model_manifest["sha256"] == model_manifest_sha256
        and (
            marker is None
            or model_manifest["sha256"] == marker["model_manifest_sha256"]
        )
    )
    marker_time_gate = marker is not None and (
        datetime.now(timezone.utc).timestamp() if now is None else now
    ) >= marker["eligible_at"]
    soak_marker_gate = bool(
        marker is not None
        and marker_time_gate
        and model_identity_gate
        and model_manifest_sha256 == marker["model_manifest_sha256"]
        and decision_policy_identity_gate
        and decision_policy_sha256 == marker["decision_policy_sha256"]
        and run_identity_gate
        and run_id == marker["run_id"]
        and model_manifest_gate
    )
    core_gate = (
        scored >= minimum_scored_windows
        and alerts <= maximum_alerts
        and duration_gate
        and coverage_gate
        and model_identity_gate
        and model_manifest_gate
        and expected_workload_gate
    )
    return {
        "schema": "sentinel-pulse-normal-soak-report-v1",
        "path": str(path),
        "decisions_sha256": sha256_file(path),
        "soak_marker_sha256": marker["sha256"] if marker is not None else None,
        "soak_started_not_before": (
            marker["started_not_before"] if marker is not None else None
        ),
        "soak_eligible_finalize_after": (
            marker["eligible_finalize_after"] if marker is not None else None
        ),
        "excluded_scored_windows_before_marker": excluded_before_marker,
        "minimum_scored_windows": minimum_scored_windows,
        "minimum_duration_hours_per_workload": minimum_duration_hours,
        "minimum_coverage_ratio_per_workload": minimum_coverage_ratio,
        "maximum_alerts": maximum_alerts,
        "scored_windows": scored,
        "alerts": alerts,
        "observed_false_alert_rate": alerts / scored if scored else None,
        "false_alert_rate_wilson_95": [lower, upper],
        "statuses": dict(sorted(statuses.items())),
        "model_manifest_sha256": model_manifest_sha256,
        "model_identity_gate": model_identity_gate,
        "model_manifest_input_sha256": (
            model_manifest["sha256"] if model_manifest is not None else None
        ),
        "model_manifest_gate": model_manifest_gate,
        "expected_workloads": sorted(expected_workloads),
        "observed_workloads": sorted(observed_workloads),
        "missing_workloads": missing_workloads,
        "unexpected_workloads": unexpected_workloads,
        "expected_workload_gate": expected_workload_gate,
        "decision_policy_sha256": decision_policy_sha256,
        "decision_policy_identity_gate": decision_policy_identity_gate,
        "run_id": run_id,
        "run_identity_gate": run_identity_gate,
        "marker_time_gate": marker_time_gate,
        "soak_marker_gate": soak_marker_gate,
        "suppressed_raw_anomalies": statuses["suppressed"],
        "workloads": workload_reports,
        "duration_gate": duration_gate,
        "coverage_gate": coverage_gate,
        "normal_gate": core_gate and (soak_marker_gate if marker is not None else True),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--decisions", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--maximum-alerts", type=int, default=0)
    parser.add_argument("--minimum-scored-windows", type=int, default=86400)
    parser.add_argument("--minimum-duration-hours", type=float, default=24.0)
    parser.add_argument("--minimum-coverage-ratio", type=float, default=0.95)
    parser.add_argument("--soak-marker", type=Path)
    parser.add_argument("--model-manifest", type=Path)
    args = parser.parse_args()
    report = evaluate(
        args.decisions,
        args.maximum_alerts,
        args.minimum_scored_windows,
        args.minimum_duration_hours,
        args.minimum_coverage_ratio,
        args.soak_marker,
        model_manifest_path=args.model_manifest,
    )
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    raise SystemExit(0 if report["normal_gate"] else 1)


if __name__ == "__main__":
    main()
