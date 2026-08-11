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


def holm_adjust(
    pairs: list[dict[str, Any]], *, p_field: str = "mcnemar_p",
    adjusted_field: str = "mcnemar_holm_p",
    significant_field: str = "significant_at_0_05",
) -> None:
    ordered = sorted(enumerate(pairs), key=lambda item: item[1][p_field])
    running = 0.0
    total = len(ordered)
    for rank, (index, item) in enumerate(ordered):
        running = max(running, min(1.0, (total - rank) * item[p_field]))
        pairs[index][adjusted_field] = running
        pairs[index][significant_field] = running < 0.05


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


def rate_block_bootstrap_interval(
    counts_by_run: dict[str, tuple[int, float]], *, iterations: int, seed: int,
) -> dict[str, Any]:
    runs = sorted(counts_by_run)
    if not runs or iterations < 1:
        raise ValueError("rate bootstrap requires independent runs")
    generator = random.Random(seed)
    estimates = []
    for _ in range(iterations):
        sampled = [generator.choice(runs) for _ in runs]
        count = sum(counts_by_run[run][0] for run in sampled)
        exposure = sum(counts_by_run[run][1] for run in sampled)
        estimates.append(count / exposure)
    count = sum(value[0] for value in counts_by_run.values())
    exposure = sum(value[1] for value in counts_by_run.values())
    return {
        "estimate_per_hour": count / exposure,
        "lower_per_hour": quantile(estimates, 0.025),
        "upper_per_hour": quantile(estimates, 0.975),
        "confidence_level": 0.95,
        "iterations": iterations,
        "blocks": len(runs),
        "block_unit": "independent normal run",
        "seed": seed,
    }


def exact_sign_flip_p(run_differences: list[float]) -> float:
    if not run_differences:
        raise ValueError("sign-flip test requires run differences")
    observed = abs(sum(run_differences) / len(run_differences))
    tolerance = 1e-15
    extreme = 0
    total = 2 ** len(run_differences)
    for mask in range(total):
        estimate = sum(
            value if mask & (1 << index) else -value
            for index, value in enumerate(run_differences)
        ) / len(run_differences)
        extreme += abs(estimate) + tolerance >= observed
    return extreme / total


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


def indexed_normal_phases(result: dict[str, Any]) -> dict[str, dict[str, Any]]:
    indexed = {}
    for row in result["normal"].get("phase_outcomes", []):
        phase = str(row["phase"])
        if phase in indexed:
            raise ValueError("duplicate normal phase identity")
        indexed[phase] = row
    if len(indexed) != int(result["normal"]["phases"]):
        raise ValueError("normal phase outcomes are incomplete")
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


def validate_normal_pairing(indexed: dict[str, dict[str, dict]]) -> list[str]:
    methods = sorted(indexed)
    reference = indexed[methods[0]]
    fields = ("run_id", "traffic_regime", "exposure_seconds")
    for method in methods[1:]:
        if set(indexed[method]) != set(reference):
            raise ValueError(f"{method}: normal phase set is not paired")
        for phase, row in indexed[method].items():
            if any(row.get(field) != reference[phase].get(field) for field in fields):
                raise ValueError(f"{method}: normal phase metadata mismatch for {phase}")
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
        "normal_run_alerts": {
            run_id: sum(
                int(row["false_alerts"])
                for row in result["normal"]["phase_outcomes"]
                if row["run_id"] == run_id
            )
            for run_id in sorted({
                row["run_id"] for row in result["normal"]["phase_outcomes"]
            })
        },
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
    outcomes_b: dict[str, dict], injection_ids: list[str],
    normal_a: dict[str, dict], normal_b: dict[str, dict],
    normal_phases: list[str], *,
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
    normal_counts_by_run: dict[str, tuple[int, float]] = {}
    normal_run_differences = []
    run_ids = sorted({normal_a[phase]["run_id"] for phase in normal_phases})
    for run_id in run_ids:
        phases = [
            phase for phase in normal_phases
            if normal_a[phase]["run_id"] == run_id
        ]
        count_difference = sum(
            int(normal_a[phase]["false_alerts"])
            - int(normal_b[phase]["false_alerts"])
            for phase in phases
        )
        exposure_hours = sum(
            float(normal_a[phase]["exposure_seconds"]) for phase in phases
        ) / 3600.0
        normal_counts_by_run[run_id] = (count_difference, exposure_hours)
        normal_run_differences.append(count_difference / exposure_hours)
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
        "normal_false_alert_rate_difference_a_minus_b": rate_block_bootstrap_interval(
            normal_counts_by_run, iterations=iterations, seed=seed + 2,
        ),
        "normal_run_sign_flip_p": exact_sign_flip_p(normal_run_differences),
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
    normal_indexed = {
        method: indexed_normal_phases(result) for method, result in results.items()
    }
    normal_phases = validate_normal_pairing(normal_indexed)
    comparisons = []
    for index, (left, right) in enumerate(itertools.combinations(sorted(results), 2)):
        pair_seed = seed + index * 2
        comparisons.append(pairwise_comparison(
            left, right, indexed[left], indexed[right], injection_ids,
            normal_indexed[left], normal_indexed[right], normal_phases,
            iterations=bootstrap_iterations, seed=pair_seed,
        ))
    holm_adjust(comparisons)
    holm_adjust(
        comparisons, p_field="normal_run_sign_flip_p",
        adjusted_field="normal_run_sign_flip_holm_p",
        significant_field="normal_significant_at_0_05",
    )
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
            "Normal false-alert inference uses five run blocks, so exact sign-flip power is limited.",
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
