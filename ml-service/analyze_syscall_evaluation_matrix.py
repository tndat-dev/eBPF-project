"""Compute paired paper statistics from a validated syscall result matrix."""

from __future__ import annotations

import argparse
from collections import defaultdict
from datetime import datetime, timezone
import hashlib
import itertools
import json
import math
from pathlib import Path
import random
from typing import Any, Iterable


CDF_THRESHOLDS_SECONDS = (1.0, 2.0, 5.0, 10.0, 20.0, 30.0)


def quantile(values: Iterable[float], fraction: float) -> float | None:
    ordered = sorted(float(value) for value in values)
    if not ordered:
        return None
    position = (len(ordered) - 1) * fraction
    lower = int(position)
    upper = min(len(ordered) - 1, lower + 1)
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (
        position - lower
    )


def distribution(values: Iterable[float]) -> dict[str, Any]:
    observed = [float(value) for value in values]
    return {
        "sample_count": len(observed),
        "minimum": min(observed) if observed else None,
        "median": quantile(observed, 0.50),
        "p95": quantile(observed, 0.95),
        "p99": quantile(observed, 0.99),
        "maximum": max(observed) if observed else None,
    }


def exact_mcnemar_p(a_only: int, b_only: int) -> float:
    if a_only < 0 or b_only < 0:
        raise ValueError("discordant counts must be non-negative")
    discordant = a_only + b_only
    if discordant == 0:
        return 1.0
    lower = min(a_only, b_only)
    tail = sum(math.comb(discordant, value) for value in range(lower + 1))
    return min(1.0, 2.0 * tail / (2 ** discordant))


def holm_adjust(pairs: list[dict[str, Any]]) -> None:
    ordered = sorted(enumerate(pairs), key=lambda item: item[1]["mcnemar_p"])
    running = 0.0
    total = len(ordered)
    for rank, (index, item) in enumerate(ordered):
        running = max(running, min(1.0, (total - rank) * item["mcnemar_p"]))
        pairs[index]["mcnemar_holm_p"] = running
        pairs[index]["significant_at_0_05"] = running < 0.05


def block_bootstrap_interval(
    values_by_block: dict[str, list[float]], *, iterations: int, seed: int,
) -> dict[str, Any]:
    blocks = sorted(values_by_block)
    if not blocks or iterations < 1:
        raise ValueError("block bootstrap requires blocks and iterations")
    observed_values = [value for block in blocks for value in values_by_block[block]]
    block_totals = {
        block: (sum(values_by_block[block]), len(values_by_block[block]))
        for block in blocks
    }
    generator = random.Random(seed)
    estimates = []
    for _ in range(iterations):
        sampled = [generator.choice(blocks) for _ in blocks]
        total = sum(block_totals[block][0] for block in sampled)
        count = sum(block_totals[block][1] for block in sampled)
        estimates.append(total / count)
    return {
        "estimate": sum(observed_values) / len(observed_values),
        "lower": quantile(estimates, 0.025),
        "upper": quantile(estimates, 0.975),
        "confidence_level": 0.95,
        "iterations": iterations,
        "blocks": len(blocks),
        "block_unit": "workload/pod_key",
        "seed": seed,
    }


def read_results(root: Path, expected_ids: set[str] | None = None) -> dict[str, dict]:
    results = {}
    for path in sorted(root.glob("syscall__*/result.json")):
        result = json.loads(path.read_text())
        experiment_id = str(result.get("experiment_id", ""))
        if not experiment_id or experiment_id in results:
            raise ValueError("missing or duplicate experiment identity")
        outcomes = result.get("attack", {}).get("outcomes", [])
        if len(outcomes) != int(result.get("attack", {}).get("trials", -1)):
            raise ValueError(f"{experiment_id}: incomplete paired outcomes")
        results[experiment_id] = result
    if expected_ids is not None and set(results) != expected_ids:
        raise ValueError("paired statistics experiment set mismatch")
    if len(results) < 2:
        raise ValueError("paired statistics requires at least two methods")
    return results


def indexed_outcomes(result: dict[str, Any]) -> dict[str, dict[str, Any]]:
    indexed = {}
    for row in result["attack"]["outcomes"]:
        injection_id = str(row["injection_id"])
        if injection_id in indexed:
            raise ValueError("duplicate injection identity")
        indexed[injection_id] = row
    return indexed


def validate_pairing(indexed: dict[str, dict[str, dict]]) -> list[str]:
    methods = sorted(indexed)
    reference = indexed[methods[0]]
    fields = ("pod_key", "scenario", "seed", "rate", "censor_seconds")
    for method in methods[1:]:
        if set(indexed[method]) != set(reference):
            raise ValueError(f"{method}: injection set is not paired")
        for injection_id, row in indexed[method].items():
            if any(row.get(field) != reference[injection_id].get(field) for field in fields):
                raise ValueError(f"{method}: trial metadata mismatch for {injection_id}")
    return sorted(reference)


def method_summary(result: dict[str, Any]) -> dict[str, Any]:
    outcomes = result["attack"]["outcomes"]
    detected_latencies = [
        float(row["latency_seconds"])
        for row in outcomes if row["detected"] and row["latency_seconds"] is not None
    ]
    restricted_latencies = [
        float(row["latency_seconds"])
        if row["detected"] and row["latency_seconds"] is not None
        else float(row["censor_seconds"])
        for row in outcomes
    ]
    return {
        "trials": len(outcomes),
        "detected": sum(bool(row["detected"]) for row in outcomes),
        "recall_point": result["attack"]["recall_point"],
        "recall_wilson_95": result["attack"]["recall"],
        "normal_false_alerts": result["normal"]["false_alerts"],
        "normal_exposure_hours": result["normal"]["exposure_hours"],
        "detected_latency_seconds": distribution(detected_latencies),
        "detected_latency_cdf": {
            str(threshold): (
                sum(value <= threshold for value in detected_latencies)
                / len(detected_latencies) if detected_latencies else None
            )
            for threshold in CDF_THRESHOLDS_SECONDS
        },
        "restricted_time_to_detection_seconds": distribution(
            restricted_latencies
        ),
    }


def pairwise_comparison(
    method_a: str, method_b: str, outcomes_a: dict[str, dict],
    outcomes_b: dict[str, dict], injection_ids: list[str], *,
    iterations: int, seed: int,
) -> dict[str, Any]:
    a_only = sum(
        bool(outcomes_a[key]["detected"]) and not outcomes_b[key]["detected"]
        for key in injection_ids
    )
    b_only = sum(
        bool(outcomes_b[key]["detected"]) and not outcomes_a[key]["detected"]
        for key in injection_ids
    )
    recall_by_workload: dict[str, list[float]] = defaultdict(list)
    restricted_by_workload: dict[str, list[float]] = defaultdict(list)
    codetected_differences = []
    for key in injection_ids:
        left, right = outcomes_a[key], outcomes_b[key]
        workload = str(left["pod_key"])
        recall_by_workload[workload].append(
            float(bool(left["detected"])) - float(bool(right["detected"]))
        )
        left_time = (
            float(left["latency_seconds"])
            if left["detected"] and left["latency_seconds"] is not None
            else float(left["censor_seconds"])
        )
        right_time = (
            float(right["latency_seconds"])
            if right["detected"] and right["latency_seconds"] is not None
            else float(right["censor_seconds"])
        )
        restricted_by_workload[workload].append(left_time - right_time)
        if (
            left["detected"] and right["detected"]
            and left["latency_seconds"] is not None
            and right["latency_seconds"] is not None
        ):
            codetected_differences.append(
                float(left["latency_seconds"]) - float(right["latency_seconds"])
            )
    return {
        "method_a": method_a,
        "method_b": method_b,
        "a_only_detected": a_only,
        "b_only_detected": b_only,
        "both_detected": sum(
            outcomes_a[key]["detected"] and outcomes_b[key]["detected"]
            for key in injection_ids
        ),
        "neither_detected": sum(
            not outcomes_a[key]["detected"] and not outcomes_b[key]["detected"]
            for key in injection_ids
        ),
        "mcnemar_p": exact_mcnemar_p(a_only, b_only),
        "recall_difference_a_minus_b": block_bootstrap_interval(
            recall_by_workload, iterations=iterations, seed=seed,
        ),
        "restricted_time_difference_a_minus_b_seconds": block_bootstrap_interval(
            restricted_by_workload, iterations=iterations, seed=seed + 1,
        ),
        "codetected_latency_difference_a_minus_b_seconds": {
            **distribution(codetected_differences),
            "interpretation": "descriptive only; conditioning on co-detection can bias comparison",
        },
    }


def analyze_matrix(
    root: Path, expected_ids: set[str] | None = None, *,
    bootstrap_iterations: int = 10_000, seed: int = 20260811,
) -> dict[str, Any]:
    results = read_results(root, expected_ids)
    indexed = {method: indexed_outcomes(result) for method, result in results.items()}
    injection_ids = validate_pairing(indexed)
    comparisons = []
    for index, (left, right) in enumerate(itertools.combinations(sorted(results), 2)):
        pair_seed = seed + index * 2
        comparisons.append(pairwise_comparison(
            left, right, indexed[left], indexed[right], injection_ids,
            iterations=bootstrap_iterations, seed=pair_seed,
        ))
    holm_adjust(comparisons)
    identity = {
        field: sorted({result[field] for result in results.values()})
        for field in (
            "release_id", "normal_capture_sha256", "capture_sha256",
            "split_sha256", "evaluation_protocol_sha256", "environment_sha256",
        )
    }
    if any(len(values) != 1 for values in identity.values()):
        raise ValueError("matrix identity differs across paired methods")
    return {
        "schema": "sentinel-syscall-paired-statistics/v1",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "methods": len(results),
        "trials_per_method": len(injection_ids),
        "pairwise_comparisons": len(comparisons),
        "bootstrap_iterations": bootstrap_iterations,
        "multiple_comparison_correction": "Holm-Bonferroni",
        "pairing_identity": {field: values[0] for field, values in identity.items()},
        "method_summaries": {
            method: method_summary(result) for method, result in sorted(results.items())
        },
        "comparisons": comparisons,
        "limitations": [
            "McNemar tests detection discordance only and does not test false-alert rates.",
            "Workload-block bootstrap has eight workload blocks; report this finite-block limitation.",
            "Detected-only latency is descriptive because conditioning on co-detection can bias it.",
            "Restricted time-to-detection assigns each miss its frozen attribution censor time.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("matrix_root", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--bootstrap-iterations", type=int, default=10_000)
    parser.add_argument("--seed", type=int, default=20260811)
    args = parser.parse_args()
    report = analyze_matrix(
        args.matrix_root.resolve(),
        bootstrap_iterations=args.bootstrap_iterations, seed=args.seed,
    )
    output = args.output or args.matrix_root / "paired_statistics.json"
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
