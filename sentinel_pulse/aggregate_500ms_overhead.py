"""Validate and aggregate paired OFF/ON Sentinel Pulse 500 ms overhead blocks."""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import re
import statistics
from pathlib import Path


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    position = (len(ordered) - 1) * fraction
    low = int(position)
    high = min(low + 1, len(ordered) - 1)
    return ordered[low] + (ordered[high] - ordered[low]) * (position - low)


def bootstrap_median(values: list[float], seed: int) -> dict:
    if not values:
        raise ValueError("empty paired effect sample")
    rng = random.Random(seed)
    samples = [
        statistics.median(rng.choice(values) for _ in values)
        for _ in range(10_000)
    ]
    return {
        "pairs": len(values),
        "values_percent": values,
        "median_percent": statistics.median(values),
        "bootstrap_95ci_percent": [
            percentile(samples, 0.025),
            percentile(samples, 0.975),
        ],
    }


def verify_pipeline_inputs(root: Path, protocol: dict) -> dict:
    binding = protocol.get("candidate_binding", {})
    required = {
        "candidate_decision_sha256": root / "frozen-inputs/CANDIDATE_DECISION.json",
        "model_manifest_sha256": root / "frozen-inputs/model-manifest.json",
        "decision_policy_sha256": root / "frozen-inputs/decision-policy.json",
        "overhead_contract_sha256": root / "frozen-inputs/pipeline-overhead-contract.json",
    }
    for field, path in required.items():
        digest = str(binding.get(field, ""))
        if len(digest) != 64 or not path.is_file() or sha256(path) != digest:
            raise ValueError(f"pipeline frozen input mismatch: {field}")
    candidate = json.loads(required["candidate_decision_sha256"].read_text())
    if (
        candidate.get("status") != "eligible_for_overhead_evaluation"
        or candidate.get("evidence_complete_for_accuracy_latency") is not True
        or candidate.get("automatic_production_promotion") is not False
        or candidate.get("source_sha256", {}).get("model_manifest")
        != binding["model_manifest_sha256"]
        or candidate.get("source_sha256", {}).get("decision_policy")
        != binding["decision_policy_sha256"]
    ):
        raise ValueError("pipeline candidate decision is not terminal eligible")
    contract = json.loads(required["overhead_contract_sha256"].read_text())
    if (
        contract.get("registered_before_blind_outcomes") is not True
        or contract.get("automatic_promotion") is not False
        or [item.get("condition") for item in protocol.get("phases", [])]
        != contract.get("design", {}).get("phase_order")
    ):
        raise ValueError("pipeline protocol differs from preregistered contract")
    return binding


def verify_pipeline_phase(root: Path, phase: dict, binding: dict) -> dict:
    name = str(phase["name"])
    snapshot = root / f"{name}-detector-final.txt"
    if not snapshot.is_file():
        raise ValueError(f"missing detector snapshot for {name}")
    fields = dict(
        line.split("=", 1)
        for line in snapshot.read_text(encoding="utf-8").splitlines()
        if "=" in line
    )
    if fields.get("ActiveState") != "active" or fields.get("NRestarts") != "0":
        raise ValueError(f"detector health failed for {name}")
    expected_run = str(phase.get("treatment_run_id", ""))
    candidates = []
    for decision_path in root.glob(
        "detector-runs/var/lib/sentinel-pulse-detector/runs/*/decisions.jsonl"
    ):
        alert_path = decision_path.with_name("alerts.jsonl")
        if not alert_path.is_file() or alert_path.stat().st_size != 0:
            continue
        with decision_path.open(encoding="utf-8") as handle:
            first = json.loads(handle.readline())
            if first.get("run_id") != expected_run:
                continue
            rows = 1
            alert_decisions = int(first.get("status") == "alert")
            identities = {
                (
                    first.get("model_manifest_sha256"),
                    first.get("decision_policy_sha256"),
                    first.get("run_id"),
                )
            }
            for line in handle:
                record = json.loads(line)
                rows += 1
                alert_decisions += int(record.get("status") == "alert")
                identities.add(
                    (
                        record.get("model_manifest_sha256"),
                        record.get("decision_policy_sha256"),
                        record.get("run_id"),
                    )
                )
            expected_identity = {
                (
                    binding["model_manifest_sha256"],
                    binding["decision_policy_sha256"],
                    expected_run,
                )
            }
            if identities != expected_identity:
                raise ValueError(f"detector identity changed during {name}")
            if alert_decisions:
                raise ValueError(f"normal alert observed during {name}")
            candidates.append((decision_path, alert_path, rows))
    if len(candidates) != 1:
        raise ValueError(f"expected one detector stream for {name}, got {len(candidates)}")
    decision_path, alert_path, rows = candidates[0]
    return {
        "phase": name,
        "run_id": expected_run,
        "decisions": rows,
        "alerts": 0,
        "decision_sha256": sha256(decision_path),
        "alert_sha256": sha256(alert_path),
        "health_snapshot_sha256": sha256(snapshot),
    }


def aggregate(root: Path, protocol_path: Path) -> dict:
    protocol = json.loads(protocol_path.read_text(encoding="utf-8"))
    if protocol.get("schema") != "sentinel-pulse-500ms-overhead-protocol-v1":
        raise ValueError("unsupported overhead protocol")
    phases = protocol.get("phases", [])
    if not phases or len(phases) % 2:
        raise ValueError("overhead protocol requires complete adjacent pairs")
    treatment = protocol.get("treatment", "collector")
    pipeline_binding = (
        verify_pipeline_inputs(root, protocol) if treatment == "pipeline" else None
    )
    pipeline_evidence = []

    records = []
    for expected_index, phase in enumerate(phases, 1):
        if int(phase.get("index", 0)) != expected_index:
            raise ValueError("non-contiguous phase index")
        condition = phase.get("condition")
        if condition not in ("off", "on"):
            raise ValueError("invalid overhead condition")
        phase_name = str(phase.get("name", ""))
        if not re.fullmatch(r"p[0-9]{2}-(off|on)", phase_name):
            raise ValueError("unsafe phase name")
        matches = list(root.glob(f"{phase_name}-*/report.json"))
        if len(matches) != 1:
            raise ValueError(f"expected one phase report for {phase_name}, got {len(matches)}")
        report_path = matches[0]
        if not report_path.resolve().is_relative_to(root.resolve()):
            raise ValueError(f"unsafe phase report: {report_path}")
        report = json.loads(report_path.read_text(encoding="utf-8"))
        if (
            report.get("experiment_id") != protocol.get("campaign_id")
            or report.get("phase") != phase.get("name")
            or report.get("url") != protocol.get("endpoint", {}).get("url")
            or report.get("quality_gate", {}).get("passed") is not True
            or int(report.get("failed_requests_total", -1)) != 0
            or len(report.get("runs", []))
            != int(protocol.get("repetitions_per_phase", 0))
        ):
            raise ValueError(f"phase integrity/quality failed: {phase.get('name')}")
        records.append(
            {
                "index": expected_index,
                "name": phase_name,
                "condition": condition,
                "report": str(report_path.relative_to(root)),
                "report_sha256": sha256(report_path),
                "rps_median": float(report["requests_per_second"]["median"]),
                "latency_p99_ms_median": float(report["latency_p99_ms"]["median"]),
            }
        )
        if treatment == "pipeline" and condition == "on":
            pipeline_evidence.append(
                verify_pipeline_phase(root, phase, pipeline_binding)
            )

    throughput, latency, pairs = [], [], []
    for offset in range(0, len(records), 2):
        pair = records[offset : offset + 2]
        if {item["condition"] for item in pair} != {"off", "on"}:
            raise ValueError(f"phase pair {offset // 2 + 1} is not OFF/ON balanced")
        by_condition = {item["condition"]: item for item in pair}
        off, on = by_condition["off"], by_condition["on"]
        if off["rps_median"] <= 0 or off["latency_p99_ms_median"] <= 0:
            raise ValueError("zero control metric")
        throughput_effect = 100.0 * (1.0 - on["rps_median"] / off["rps_median"])
        latency_effect = 100.0 * (
            on["latency_p99_ms_median"] / off["latency_p99_ms_median"] - 1.0
        )
        throughput.append(throughput_effect)
        latency.append(latency_effect)
        pairs.append(
            {
                "pair": offset // 2 + 1,
                "order": [item["condition"] for item in pair],
                "throughput_loss_percent": throughput_effect,
                "p99_latency_increase_percent": latency_effect,
            }
        )

    inferential = protocol.get("mode") == "full" and len(pairs) >= 4
    return {
        "schema": "sentinel-pulse-500ms-overhead-result-v1",
        "campaign_id": protocol["campaign_id"],
        "mode": protocol.get("mode"),
        "treatment": treatment,
        "valid": True,
        "inferential": inferential,
        "protocol_sha256": sha256(protocol_path),
        "records": records,
        "pipeline_candidate_binding": pipeline_binding,
        "pipeline_treatment_evidence": pipeline_evidence,
        "pairs": pairs,
        "effects": {
            "throughput_loss": bootstrap_median(throughput, 20260817),
            "p99_latency_increase": bootstrap_median(latency, 20260818),
        },
        "limitations": [
            "Treatment runs on one worker and targets its ingress pod directly.",
            "Smoke mode validates machinery only and is not inferential evidence.",
            "Service cgroup accounting does not capture all eBPF CPU charged to workloads.",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--protocol", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = aggregate(args.root, args.protocol)
    args.output.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    main()
