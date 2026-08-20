"""Post-campaign pilot analysis for the frozen 500 ms OFF/ON overhead run."""

from __future__ import annotations

import argparse
from itertools import product
import hashlib
import json
from pathlib import Path
import statistics


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def summary(values: list[float]) -> dict:
    if not values:
        raise ValueError("empty metric sample")
    return {
        "count": len(values),
        "mean": statistics.mean(values),
        "median": statistics.median(values),
        "minimum": min(values),
        "maximum": max(values),
    }


def exact_sign_flip_pvalue(values: list[float]) -> float:
    """Two-sided exact paired randomization p-value using mean effect."""
    if not values:
        raise ValueError("empty paired effect sample")
    observed = abs(statistics.mean(values))
    extreme = 0
    assignments = 0
    for signs in product((-1.0, 1.0), repeat=len(values)):
        candidate = abs(statistics.mean(sign * value for sign, value in zip(signs, values)))
        assignments += 1
        if candidate + 1e-12 >= observed:
            extreme += 1
    return extreme / assignments


def analyze(root: Path) -> dict:
    result_path = root / "RESULT.json"
    index_path = root / "SHA256SUMS"
    result = json.loads(result_path.read_text(encoding="utf-8"))
    if (
        result.get("schema") != "sentinel-pulse-500ms-overhead-result-v1"
        or result.get("mode") != "full"
        or result.get("valid") is not True
        or len(result.get("pairs", [])) != 4
    ):
        raise ValueError("frozen full overhead result is incomplete")

    by_condition = {"off": [], "on": []}
    latency_by_condition = {"off": [], "on": []}
    for record in result["records"]:
        condition = record["condition"]
        by_condition[condition].append(float(record["rps_median"]))
        latency_by_condition[condition].append(
            float(record["latency_p99_ms_median"])
        )
    if any(len(values) != 4 for values in by_condition.values()):
        raise ValueError("expected four phase blocks per condition")

    throughput_effects = [
        float(item["throughput_loss_percent"]) for item in result["pairs"]
    ]
    latency_effects = [
        float(item["p99_latency_increase_percent"]) for item in result["pairs"]
    ]

    treatment = []
    for path in sorted(root.glob("p*-on-finalize.json")):
        report = json.loads(path.read_text(encoding="utf-8"))
        if report.get("valid") is not True:
            raise ValueError(f"invalid treatment telemetry: {path.name}")
        treatment.append(report)
    if len(treatment) != 4:
        raise ValueError("expected four treatment telemetry reports")

    throughput_p = exact_sign_flip_pvalue(throughput_effects)
    latency_p = exact_sign_flip_pvalue(latency_effects)
    return {
        "schema": "sentinel-pulse-500ms-overhead-pilot-analysis-v1",
        "campaign_id": result["campaign_id"],
        "exploratory_posthoc": True,
        "frozen_result_sha256": sha256(result_path),
        "frozen_sha256sums_sha256": sha256(index_path),
        "phase_block_metrics": {
            "off_rps": summary(by_condition["off"]),
            "on_rps": summary(by_condition["on"]),
            "off_p99_latency_ms": summary(latency_by_condition["off"]),
            "on_p99_latency_ms": summary(latency_by_condition["on"]),
        },
        "paired_effects": {
            "throughput_loss_percent": {
                **summary(throughput_effects),
                "exact_two_sided_sign_flip_pvalue": throughput_p,
            },
            "p99_latency_increase_percent": {
                **summary(latency_effects),
                "exact_two_sided_sign_flip_pvalue": latency_p,
            },
        },
        "treatment_telemetry": {
            "runs": len(treatment),
            "rows": summary([float(item["rows"]) for item in treatment]),
            "interval_p99_seconds": summary(
                [float(item["interval_seconds"]["p99"]) for item in treatment]
            ),
            "ingest_lag_p99_seconds": summary(
                [float(item["ingest_lag_seconds"]["p99"]) for item in treatment]
            ),
            "collector_cpu_cores": summary(
                [float(item["experiment_average_cpu_cores"]) for item in treatment]
            ),
            "collector_memory_peak_bytes": summary(
                [float(item["experiment_memory_peak_bytes"]) for item in treatment]
            ),
            "all_integrity_gates_passed": all(
                not any(int(value) for value in item["collector_max_drops"].values())
                for item in treatment
            ),
        },
        "interpretation": {
            "alpha": 0.05,
            "throughput_difference_significant": throughput_p < 0.05,
            "p99_latency_difference_significant": latency_p < 0.05,
            "equivalence_established": False,
            "reason": (
                "Four paired blocks from one cluster-day have low power; failure to "
                "reject zero effect is not evidence of equivalence."
            ),
        },
        "limitations": [
            "The exact sign-flip tests were added post-campaign and are exploratory.",
            "All four pairs came from one cluster, one worker, one endpoint and one day.",
            "A preregistered multi-day replication and an equivalence margin are required.",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = analyze(args.root)
    args.output.parent.mkdir(parents=True, exist_ok=False)
    args.output.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    main()
