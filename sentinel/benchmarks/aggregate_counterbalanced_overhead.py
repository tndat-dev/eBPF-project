"""Aggregate all six phase orders as experiment-level paired blocks."""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import statistics
from pathlib import Path


PHASES = ("no_tracing", "tetragon_only", "full_pipeline")
EXPECTED_ORDERS = {tuple(order.split(",")) for order in (
    "no_tracing,tetragon_only,full_pipeline",
    "no_tracing,full_pipeline,tetragon_only",
    "tetragon_only,no_tracing,full_pipeline",
    "tetragon_only,full_pipeline,no_tracing",
    "full_pipeline,no_tracing,tetragon_only",
    "full_pipeline,tetragon_only,no_tracing",
)}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def portable_phase_report(root: Path, recorded_path: str) -> Path:
    """Resolve a report inside a copied artifact bundle, never outside it."""
    reported = Path(recorded_path)
    directory = reported.parent.name
    if not directory or directory in (".", ".."):
        raise ValueError(f"unsafe phase report path: {recorded_path!r}")
    candidate = (root / directory / "report.json").resolve()
    if not candidate.is_relative_to(root.resolve()):
        raise ValueError(f"phase report escapes artifact root: {recorded_path!r}")
    return candidate


def portable_root_file(root: Path, recorded_path: str) -> Path:
    """Resolve a recorded top-level artifact inside a copied bundle."""
    name = Path(recorded_path).name
    if not name or name in (".", ".."):
        raise ValueError(f"unsafe artifact path: {recorded_path!r}")
    candidate = (root / name).resolve()
    if not candidate.is_relative_to(root.resolve()):
        raise ValueError(f"artifact escapes artifact root: {recorded_path!r}")
    return candidate


def percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    position = (len(ordered) - 1) * fraction
    low = int(position)
    high = min(low + 1, len(ordered) - 1)
    return ordered[low] + (ordered[high] - ordered[low]) * (position - low)


def paired_effect(treatment: float, control: float, kind: str) -> float:
    if control == 0:
        raise ValueError("zero control metric")
    if kind == "throughput_loss":
        return 100.0 * (1.0 - treatment / control)
    return 100.0 * (treatment / control - 1.0)


def block_summary(values: list[float], seed: int = 20260805) -> dict:
    if not values:
        raise ValueError("empty overhead block sample")
    rng = random.Random(seed)
    estimates = []
    for _ in range(10_000):
        estimates.append(statistics.median(rng.choice(values) for _ in values))
    return {
        "experiment_blocks": len(values),
        "values_percent": values,
        "median_percent": statistics.median(values),
        "block_bootstrap_95ci_percent": [
            percentile(estimates, 0.025), percentile(estimates, 0.975),
        ],
    }


def aggregate(root: Path, campaign_prefix: str) -> dict:
    records = []
    orders = set()
    evidence_releases = set()
    prerequisite_hashes = set()
    for comparison_path in sorted(
        root.glob(f"comparison-wrk-{campaign_prefix}-p*.json")
    ):
        comparison = json.loads(comparison_path.read_text())
        experiment_id = comparison.get("experiment_id")
        protocol_path = root / f"protocol-{experiment_id}.json"
        if not protocol_path.is_file():
            raise ValueError(f"missing protocol for {experiment_id}")
        protocol = json.loads(protocol_path.read_text())
        protocol_digest = sha256(protocol_path)
        if comparison.get("protocol_sha256") != protocol_digest:
            raise ValueError(f"protocol digest mismatch: {experiment_id}")
        environment_path = root / f"environment-{experiment_id}.txt"
        if (
            not environment_path.is_file()
            or comparison.get("environment_sha256") != sha256(environment_path)
        ):
            raise ValueError(f"environment digest mismatch: {experiment_id}")
        evidence_release = str(protocol.get("evidence_release", "v7"))
        if evidence_release not in ("v7", "v8"):
            raise ValueError(f"unsupported evidence release: {evidence_release}")
        evidence_releases.add(evidence_release)
        prerequisite_record = None
        if evidence_release == "v8":
            prerequisite = protocol.get("prerequisite") or {}
            prerequisite_path = portable_root_file(
                root, str(prerequisite.get("path", "")),
            )
            if (
                not prerequisite_path.is_file()
                or prerequisite.get("sha256") != sha256(prerequisite_path)
            ):
                raise ValueError(f"V8 prerequisite digest mismatch: {experiment_id}")
            prerequisite_document = json.loads(prerequisite_path.read_text())
            if (
                prerequisite_document.get("valid") is not True
                or prerequisite_document.get("release_id")
                != "v8-paired-replay-20260811"
                or prerequisite_document.get("automatic_promotion") is not False
            ):
                raise ValueError(f"invalid V8 prerequisite: {experiment_id}")
            prerequisite_hashes.add(sha256(prerequisite_path))
            prerequisite_record = {
                "name": prerequisite_path.name,
                "sha256": sha256(prerequisite_path),
            }
        order = tuple(protocol.get("phase_order", []))
        if order not in EXPECTED_ORDERS or order in orders:
            raise ValueError(f"invalid or duplicate phase order: {order}")
        orders.add(order)
        expected_repetitions = int(protocol.get("repetitions_per_phase", 0))
        if expected_repetitions <= 0:
            raise ValueError(f"invalid repetition contract for {experiment_id}")
        phases = comparison.get("phases", {})
        if set(phases) != set(PHASES):
            raise ValueError(f"incomplete phases for {experiment_id}")
        phase_reports = {}
        for phase, summary in phases.items():
            report_path = portable_phase_report(
                root, str(summary.get("path", "")),
            )
            if not report_path.is_file():
                raise ValueError(f"missing phase report for {experiment_id}/{phase}")
            phase_report = json.loads(report_path.read_text())
            if (
                phase_report.get("experiment_id") != experiment_id
                or phase_report.get("phase") != phase
                or phase_report.get("quality_gate", {}).get("passed") is not True
                or len(phase_report.get("runs", [])) != expected_repetitions
                or int(phase_report.get("failed_requests_total", -1)) != 0
            ):
                raise ValueError(
                    f"phase quality/integrity gate failed: {experiment_id}/{phase}"
                )
            report_digest = sha256(report_path)
            if summary.get("report_sha256") != report_digest:
                raise ValueError(f"phase digest mismatch: {experiment_id}/{phase}")
            phase_reports[phase] = {
                "name": report_path.parent.name + "/report.json",
                "sha256": report_digest,
                "repetitions": len(phase_report["runs"]),
                "failed_requests": phase_report["failed_requests_total"],
            }
        records.append({
            "experiment_id": experiment_id,
            "phase_order": list(order),
            "comparison_sha256": sha256(comparison_path),
            "protocol_sha256": protocol_digest,
            "environment_sha256": sha256(environment_path),
            "evidence_release": evidence_release,
            "prerequisite": prerequisite_record,
            "phases": phases,
            "phase_reports": phase_reports,
        })
    if orders != EXPECTED_ORDERS:
        raise ValueError(
            f"counterbalanced campaign incomplete: {len(orders)}/6 orders"
        )
    if len(evidence_releases) != 1:
        raise ValueError("mixed evidence releases in one overhead campaign")
    evidence_release = evidence_releases.pop()
    if evidence_release == "v8" and len(prerequisite_hashes) != 1:
        raise ValueError("V8 experiment blocks do not share one prerequisite")

    effects = {}
    for name, treatment in (
        ("tetragon_vs_no_tracing", "tetragon_only"),
        ("full_pipeline_vs_no_tracing", "full_pipeline"),
        ("detector_increment_vs_tetragon", "full_pipeline"),
    ):
        control = "tetragon_only" if name.startswith("detector_") else "no_tracing"
        throughput = [
            paired_effect(
                row["phases"][treatment]["rps_median"],
                row["phases"][control]["rps_median"],
                "throughput_loss",
            )
            for row in records
        ]
        latency = [
            paired_effect(
                row["phases"][treatment]["latency_p99_ms_median"],
                row["phases"][control]["latency_p99_ms_median"],
                "latency_increase",
            )
            for row in records
        ]
        effects[name] = {
            "throughput_loss": block_summary(throughput),
            "p99_latency_increase": block_summary(latency, seed=20260806),
        }
    return {
        "schema": "sentinel-aims-overhead-counterbalanced/v1",
        "campaign_prefix": campaign_prefix,
        "evidence_release": evidence_release,
        "design": {
            "phase_orders": 6,
            "repetitions_per_phase_per_order": 10,
            "total_repetitions_per_phase": 60,
            "inference_unit": "phase-order experiment block",
        },
        "experiments": records,
        "effects": effects,
        "limitations": [
            "Six order blocks support order counterbalancing but remain one cluster campaign.",
            "Metrics Server CPU/RAM samples are lagged resource snapshots.",
        ],
    }


def markdown(report: dict) -> str:
    lines = [
        "# AIMS counterbalanced overhead", "",
        "| Effect | Throughput loss | 95% block CI | p99 increase | 95% block CI |",
        "|---|---:|---:|---:|---:|",
    ]
    for name, item in report["effects"].items():
        throughput = item["throughput_loss"]
        latency = item["p99_latency_increase"]
        lines.append(
            f"| {name} | {throughput['median_percent']:.3f}% | "
            f"{throughput['block_bootstrap_95ci_percent']} | "
            f"{latency['median_percent']:.3f}% | "
            f"{latency['block_bootstrap_95ci_percent']} |"
        )
    lines.extend(["", "CI bootstrap theo sáu phase-order block đã ghép cặp.", ""])
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--campaign-prefix", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = aggregate(args.root, args.campaign_prefix)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    args.output.with_suffix(".md").write_text(markdown(report))
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
