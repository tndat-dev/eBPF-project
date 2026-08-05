"""Generate publication-oriented statistics from immutable validation reports."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import random
import statistics
from pathlib import Path
from typing import Callable, Iterable, Sequence


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def percentile(values: Iterable[float], fraction: float) -> float | None:
    ordered = sorted(float(value) for value in values)
    if not ordered:
        return None
    position = (len(ordered) - 1) * fraction
    low = int(position)
    high = min(low + 1, len(ordered) - 1)
    return ordered[low] + (ordered[high] - ordered[low]) * (position - low)


def wilson_interval(successes: int, trials: int, z: float = 1.959963984540054) -> list[float] | None:
    """Two-sided 95% Wilson score interval for a Bernoulli proportion."""
    if trials <= 0 or successes < 0 or successes > trials:
        return None
    estimate = successes / trials
    denominator = 1.0 + z * z / trials
    centre = (estimate + z * z / (2 * trials)) / denominator
    radius = z * math.sqrt(
        estimate * (1 - estimate) / trials + z * z / (4 * trials * trials)
    ) / denominator
    lower = 0.0 if successes == 0 else max(0.0, centre - radius)
    upper = 1.0 if successes == trials else min(1.0, centre + radius)
    return [lower, upper]


def bootstrap_interval(
    values: Iterable[float],
    statistic: Callable[[list[float]], float] = statistics.median,
    *,
    iterations: int = 10_000,
    seed: int = 20260802,
) -> list[float] | None:
    sample = [float(value) for value in values]
    if not sample:
        return None
    rng = random.Random(seed)
    estimates = []
    for _ in range(iterations):
        resample = [rng.choice(sample) for _ in sample]
        estimates.append(float(statistic(resample)))
    return [
        float(percentile(estimates, 0.025)),
        float(percentile(estimates, 0.975)),
    ]


def distribution(values: Iterable[float]) -> dict:
    sample = [float(value) for value in values]
    return {
        "count": len(sample),
        "minimum": min(sample) if sample else None,
        "p50": percentile(sample, 0.50),
        "p90": percentile(sample, 0.90),
        "p95": percentile(sample, 0.95),
        "p99": percentile(sample, 0.99),
        "maximum": max(sample) if sample else None,
        "median_bootstrap_95ci": bootstrap_interval(sample),
    }


def attack_trials(report: dict) -> list[dict]:
    rows = []
    for workload, workload_item in sorted(report.get("workloads", {}).items()):
        nested = workload_item.get("report", workload_item)
        for scenario, item in sorted(nested.get("scenarios", {}).items()):
            rows.append(
                {
                    "workload": workload,
                    "scenario": scenario,
                    "detected": bool(item.get("detected")),
                    "detection_latency_seconds": item.get("detection_latency_seconds"),
                    "fast_path_latency_seconds": item.get("fast_path_latency_seconds"),
                    "inference_median_ms": item.get("inference_median_ms"),
                    "sensor_health_healthy": item.get("sensor_health_healthy"),
                    "normal_alerts_before_attack": item.get("normal_alerts_before_attack"),
                    "fast_path_expected": item.get("fast_path_expected"),
                    "fast_path_expected_matched": item.get("fast_path_expected_matched"),
                    "attack_acknowledged": item.get("attack_acknowledged"),
                }
            )
    return rows


def _resolve_trial_report(aggregate_path: Path, item: dict) -> Path:
    """Resolve a blind-trial report while retaining relocation support."""
    recorded = Path(str(item.get("report_path", "")))
    candidates = [recorded]
    if recorded.name:
        candidates.extend(
            aggregate_path.parent.glob(f"**/{recorded.parent.name}/{recorded.name}")
        )
    for candidate in candidates:
        if candidate.is_file() and sha256(candidate) == item.get("report_sha256"):
            return candidate
    raise ValueError(
        f"missing or hash-invalid blind trial report: "
        f"{item.get('target')} trial {item.get('trial')}"
    )


def load_blind_attack_rows(aggregate_path: Path, aggregate: dict) -> list[dict]:
    """Load and cryptographically validate every row in a blind matrix."""
    rows = []
    trial_items = aggregate.get("trials", [])
    if len(trial_items) != int(aggregate.get("completed_trials", -1)):
        raise ValueError("blind aggregate completed-trial count is inconsistent")
    for trial_item in trial_items:
        report_path = _resolve_trial_report(aggregate_path, trial_item)
        report = json.loads(report_path.read_text())
        scenarios = report.get("scenarios", {})
        if len(scenarios) != int(trial_item.get("total", -1)):
            raise ValueError(f"invalid scenario count in {report_path}")
        detected = sum(bool(item.get("detected")) for item in scenarios.values())
        if detected != int(trial_item.get("detected", -1)):
            raise ValueError(f"invalid detected count in {report_path}")
        if report.get("runtime_binary_sha256") != aggregate.get("runtime_binary_sha256"):
            raise ValueError(f"runtime binary drift in {report_path}")
        for scenario, scenario_item in sorted(scenarios.items()):
            rows.append(
                {
                    "workload": trial_item["target"],
                    "scenario": scenario,
                    "trial": int(trial_item["trial"]),
                    "rate": int(trial_item["rate"]),
                    "seed": int(trial_item["seed"]),
                    "detected": bool(scenario_item.get("detected")),
                    "detection_latency_seconds": scenario_item.get(
                        "detection_latency_seconds"
                    ),
                    "fast_path_latency_seconds": scenario_item.get(
                        "fast_path_latency_seconds"
                    ),
                    "inference_median_ms": scenario_item.get("inference_median_ms"),
                    "sensor_health_healthy": scenario_item.get(
                        "sensor_health_healthy"
                    ),
                    "normal_alerts_before_attack": scenario_item.get(
                        "normal_alerts_before_attack"
                    ),
                    "fast_path_expected": scenario_item.get("fast_path_expected"),
                    "fast_path_expected_matched": scenario_item.get(
                        "fast_path_expected_matched"
                    ),
                    "attack_acknowledged": scenario_item.get("attack_acknowledged"),
                    "report_sha256": trial_item["report_sha256"],
                    "validation_harness_sha256": report.get(
                        "validation_harness_sha256"
                    ),
                }
            )
    expected = int(aggregate.get("expected_scenario_trials", -1))
    if len(rows) != expected or sum(row["detected"] for row in rows) != int(
        aggregate.get("detected", -1)
    ):
        raise ValueError("blind aggregate scenario totals are inconsistent")
    return rows


def _binary_metrics(successes: int, total: int) -> dict:
    return {
        "successes": successes,
        "trials": total,
        "estimate": successes / total if total else None,
        "wilson_95ci": wilson_interval(successes, total),
    }


def _group_detection(rows: list[dict], field: str) -> dict:
    groups = {}
    for name in sorted({row[field] for row in rows}):
        subset = [row for row in rows if row[field] == name]
        detected = sum(row["detected"] for row in subset)
        groups[name] = {
            "recall": _binary_metrics(detected, len(subset)),
            "detection_latency_seconds": distribution(
                row["detection_latency_seconds"]
                for row in subset
                if row["detected"] and row["detection_latency_seconds"] is not None
            ),
        }
    return groups


def _normal_summary(normal_reports: Sequence[dict]) -> tuple[int, int, bool, list]:
    normal_windows = 0
    false_alerts = 0
    phases = []
    passed = True
    for report in normal_reports:
        if "eligible_decision_windows" in report:
            windows = int(report.get("eligible_decision_windows", 0))
        else:
            windows = sum(
                int(item.get("windows", 0))
                for item in report.get("models", {}).values()
            )
        alerts = int(report.get("detections", report.get("alerts", 0)))
        if windows <= 0 or alerts < 0 or alerts > windows:
            raise ValueError("normal report has an invalid evaluated-window count")
        normal_windows += windows
        false_alerts += alerts
        passed = passed and report.get("passed") is True
        phases.extend(report.get("completed_phases", []))
    if len(phases) != len(set(phases)):
        raise ValueError("normal reports contain overlapping evaluation phases")
    return normal_windows, false_alerts, passed, phases


def build_report(normal: dict | Sequence[dict], attack: dict,
                 rows: list[dict] | None = None) -> dict:
    normal_reports = [normal] if isinstance(normal, dict) else list(normal)
    rows = attack_trials(attack) if rows is None else rows
    if not rows:
        raise ValueError("attack report contains no workload/scenario trials")
    normal_windows, false_alerts, normal_passed, normal_phases = _normal_summary(
        normal_reports
    )
    true_positives = sum(row["detected"] for row in rows)
    false_negatives = len(rows) - true_positives
    true_negatives = normal_windows - false_alerts
    precision_denominator = true_positives + false_alerts
    precision = true_positives / precision_denominator if precision_denominator else None
    recall = true_positives / len(rows)
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision is not None and precision + recall
        else None
    )
    detection_latencies = [
        row["detection_latency_seconds"] for row in rows
        if row["detected"] and row["detection_latency_seconds"] is not None
    ]
    fast_latencies = [
        row["fast_path_latency_seconds"] for row in rows
        if row["fast_path_latency_seconds"] is not None
    ]
    inference_medians = [
        row["inference_median_ms"] for row in rows
        if row["inference_median_ms"] is not None
    ]
    return {
        "schema": "sentinel-paper-statistics/v2",
        "sample_units": {
            "normal": "eligible workload window",
            "attack": "workload-scenario trial",
            "latency": "detected workload-scenario trial",
        },
        "confusion_counts": {
            "true_positive": true_positives,
            "false_negative": false_negatives,
            "false_positive": false_alerts,
            "true_negative": true_negatives,
        },
        "metrics": {
            "precision": {
                "estimate": precision,
                "wilson_95ci": wilson_interval(true_positives, precision_denominator),
            },
            "recall": _binary_metrics(true_positives, len(rows)),
            "f1": f1,
            "false_alert_rate_per_window": _binary_metrics(false_alerts, normal_windows),
        },
        "latency_seconds": {
            "confirmed_ml": distribution(detection_latencies),
            "fast_path_early_warning": distribution(fast_latencies),
        },
        "per_trial_inference_median_ms": distribution(inference_medians),
        "by_workload": _group_detection(rows, "workload"),
        "by_scenario": _group_detection(rows, "scenario"),
        "by_rate": _group_detection(rows, "rate") if all(
            "rate" in row for row in rows
        ) else {},
        "evidence_health": {
            "normal_reports_passed": normal_passed,
            "normal_phase_count": len(normal_phases),
            "attack_report_passed": attack.get("all_passed") is True,
            "all_attack_sensor_samples_healthy": all(
                row["sensor_health_healthy"] is True for row in rows
            ),
            "all_attacks_acknowledged": all(
                row.get("attack_acknowledged") is not False for row in rows
            ),
            "fast_path_expected_trials": sum(
                row.get("fast_path_expected") is True for row in rows
            ),
            "fast_path_expected_matched": sum(
                row.get("fast_path_expected_matched") is True for row in rows
            ),
            "validated_trial_report_hashes": len({
                row["report_sha256"] for row in rows if row.get("report_sha256")
            }),
            "validation_harness_hashes": sorted({
                row["validation_harness_sha256"] for row in rows
                if row.get("validation_harness_sha256")
            }),
            "pre_injection_alerts": sum(
                int(row["normal_alerts_before_attack"] or 0) for row in rows
            ),
        },
        "limitations": [
            "A zero observed false-alert count is not a mathematical zero-risk guarantee.",
            "Wilson intervals assume Bernoulli trials; temporally correlated normal windows require run-level block bootstrap once independent soak runs are available.",
            "Latency bootstrap treats scenario trials as independent; report cluster/run-level sensitivity analysis before a final paper claim.",
            "Precision combines attack-scenario positives with normal-window false alerts and is therefore descriptive across two different sampling units.",
        ],
    }


def markdown(report: dict) -> str:
    metrics = report["metrics"]
    confirmed = report["latency_seconds"]["confirmed_ml"]
    fast = report["latency_seconds"]["fast_path_early_warning"]
    return "\n".join(
        [
            "# Publication statistics",
            "",
            "| Metric | Estimate | 95% interval |",
            "|---|---:|---:|",
            f"| Precision | {metrics['precision']['estimate']:.6f} | {metrics['precision']['wilson_95ci']} |",
            f"| Recall | {metrics['recall']['estimate']:.6f} | {metrics['recall']['wilson_95ci']} |",
            f"| F1 | {metrics['f1']:.6f} | descriptive |",
            f"| False alerts/window | {metrics['false_alert_rate_per_window']['estimate']:.6f} | {metrics['false_alert_rate_per_window']['wilson_95ci']} |",
            "",
            "| Path | n | p50 | p95 | p99 | max | bootstrap 95% CI of median |",
            "|---|---:|---:|---:|---:|---:|---:|",
            f"| Confirmed ML | {confirmed['count']} | {confirmed['p50']:.6f}s | {confirmed['p95']:.6f}s | {confirmed['p99']:.6f}s | {confirmed['maximum']:.6f}s | {confirmed['median_bootstrap_95ci']} |",
            f"| Fast early warning | {fast['count']} | {fast['p50']:.6f}s | {fast['p95']:.6f}s | {fast['p99']:.6f}s | {fast['maximum']:.6f}s | {fast['median_bootstrap_95ci']} |",
            "",
            "Các khoảng Wilson dùng đơn vị thử nghiệm ghi trong JSON. Cửa sổ normal có tương quan thời gian; kết quả paper cuối phải bổ sung block bootstrap theo run độc lập.",
            "",
        ]
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--normal", type=Path, required=True, action="append")
    parser.add_argument("--attack", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    normal = [json.loads(path.read_text()) for path in args.normal]
    attack = json.loads(args.attack.read_text())
    rows = None
    if "trials" in attack and "expected_scenario_trials" in attack:
        rows = load_blind_attack_rows(args.attack, attack)
    report = build_report(normal, attack, rows)
    report["sources"] = {
        # Absolute paths differ between the author VM and an artifact reviewer.
        # Stable names plus content digests retain provenance while making the
        # derived JSON byte-for-byte reproducible across checkout locations.
        "normal": [
            {"name": path.name, "sha256": sha256(path)} for path in args.normal
        ],
        "attack": {"name": args.attack.name, "sha256": sha256(args.attack)},
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    args.output.with_suffix(".md").write_text(markdown(report))
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
