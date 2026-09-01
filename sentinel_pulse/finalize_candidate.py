"""Create a checksum-bound, non-promoting Sentinel Pulse candidate decision."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import math
import os
from pathlib import Path

from .integrity import contained_artifact, sha256_file, verify_sha256
from .decision_policy import load_decision_policy
from .blind_contract import load_contract


def read_json(path: Path) -> dict:
    if not path.is_file():
        raise ValueError(f"missing evidence file: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def verify_model_bundle(model_dir: Path) -> tuple[dict, list[str], list[str]]:
    manifest_path = model_dir / "manifest.json"
    checksum_path = model_dir / "manifest.sha256"
    fields = checksum_path.read_text(encoding="ascii").strip().split()
    if len(fields) != 2 or fields[1] != "manifest.json":
        raise ValueError("invalid detached model manifest checksum")
    verify_sha256(manifest_path, fields[0])
    manifest = read_json(manifest_path)
    if manifest.get("schema") != "sentinel-pulse-model-manifest-v2":
        raise ValueError("unsupported model manifest")
    if manifest.get("capture_validation", {}).get("valid") is not True:
        raise ValueError("model manifest is not bound to a valid capture")
    temporal_gap = float(manifest.get("max_contiguous_gap_seconds", 0.0))
    if not math.isfinite(temporal_gap) or temporal_gap <= 0.0:
        raise ValueError("model manifest has invalid temporal gap contract")
    if set(manifest.get("software", {})) != {
        "python",
        "numpy",
        "scikit_learn",
        "scipy",
        "joblib",
        "threadpoolctl",
        "narwhals",
    }:
        raise ValueError("model manifest has incomplete training software provenance")
    candidates, collect_only = [], []
    for workload, item in sorted(manifest.get("workloads", {}).items()):
        if item.get("status") != "candidate":
            collect_only.append(workload)
            continue
        if item.get("model_class") != "PulseExtraTrees":
            raise ValueError(f"unsupported model class for {workload}")
        artifact = contained_artifact(model_dir, item["artifact"])
        if artifact.stat().st_size != int(item["artifact_bytes"]):
            raise ValueError(f"artifact size mismatch for {artifact.name}")
        verify_sha256(artifact, item["artifact_sha256"])
        candidates.append(workload)
    if not candidates:
        raise ValueError("model manifest has no candidate workload")
    return manifest, candidates, collect_only


def build_decision(
    model_dir: Path,
    normal_report_path: Path,
    attack_report_path: Path,
    minimum_recall: float = 0.975,
    expected_injections: int = 450,
    maximum_inference_p99_ms: float = 50.0,
    maximum_processing_p99_seconds: float = 0.75,
    decision_policy_path: Path | None = None,
    soak_marker_path: Path | None = None,
    attack_contract_path: Path | None = None,
) -> dict:
    manifest, candidates, collect_only = verify_model_bundle(model_dir)
    model_manifest_sha256 = sha256_file(model_dir / "manifest.json")
    normal = read_json(normal_report_path)
    attack = read_json(attack_report_path)
    soak_marker = read_json(soak_marker_path) if soak_marker_path is not None else None
    soak_marker_sha256 = (
        sha256_file(soak_marker_path) if soak_marker_path is not None else None
    )
    decision_policy_sha256 = None
    if decision_policy_path is not None:
        _policy, decision_policy_sha256 = load_decision_policy(decision_policy_path)
    attack_contract = (
        load_contract(attack_contract_path) if attack_contract_path is not None else None
    )
    attack_contract_sha256 = (
        sha256_file(attack_contract_path) if attack_contract_path is not None else None
    )
    if normal.get("schema") != "sentinel-pulse-normal-soak-report-v1":
        raise ValueError("unsupported normal-soak report")
    if attack.get("schema") != "sentinel-pulse-latency-report-v2":
        raise ValueError("unsupported blind-attack report")
    normal_workloads = set(normal.get("workloads", {}))
    missing_normal = sorted(set(candidates) - normal_workloads)
    inference_p99 = attack.get("inference_ms", {}).get("p99")
    processing_p99 = attack.get("post_window_processing_seconds", {}).get("p99")
    gates = {
        "capture_integrity": manifest["capture_validation"]["valid"] is True,
        "all_workloads_have_candidate": not collect_only,
        "all_candidates_in_normal_soak": not missing_normal,
        "independent_normal_soak": normal.get("normal_gate") is True,
        "normal_protocol": (
            int(normal.get("minimum_scored_windows", 0)) >= 86400
            and float(normal.get("minimum_duration_hours_per_workload", 0.0)) >= 24.0
            and float(normal.get("minimum_coverage_ratio_per_workload", 0.0)) >= 0.95
            and int(normal.get("maximum_alerts", -1)) == 0
            and normal.get("duration_gate") is True
            and normal.get("coverage_gate") is True
            and normal.get("marker_time_gate") is True
            and normal.get("soak_marker_gate") is True
        ),
        "normal_soak_marker": bool(
            soak_marker is not None
            and str(soak_marker.get("schema", "")).startswith(
                "sentinel-pulse-semantic-soak-start-"
            )
            and soak_marker.get("blind_evaluation_started") is False
            and soak_marker.get("model_manifest_sha256") == model_manifest_sha256
            and (
                decision_policy_sha256 is None
                or soak_marker.get("decision_policy_sha256")
                == decision_policy_sha256
            )
            and normal.get("soak_marker_sha256") == soak_marker_sha256
            and normal.get("run_id") == soak_marker.get("run_id")
        ),
        "normal_model_identity": (
            normal.get("model_identity_gate") is True
            and normal.get("model_manifest_sha256") == model_manifest_sha256
        ),
        "expected_blind_injections": int(attack.get("expected_injections", -1)) == expected_injections,
        "blind_evidence_integrity": attack.get("blind_evidence_valid") is True,
        "blind_injection_identity": attack.get("injection_identity_gate") is True,
        "blind_run_identity": attack.get("run_identity_gate") is True,
        "blind_kernel_timestamp_identity": attack.get("kernel_timestamp_gate") is True,
        "blind_attack_matrix": attack.get("attack_matrix_gate") is True,
        "blind_attack_contract": (
            (
                attack.get("blind_attack_contract_sha256")
                == manifest.get("blind_attack_contract_sha256")
                and int(manifest.get("expected_blind_injections", -1))
                == expected_injections
            )
            if attack_contract is None
            or attack_contract.get("schema") == "sentinel-pulse-blind-attack-contract-v1"
            else (
                attack.get("blind_attack_contract_sha256") == attack_contract_sha256
                and int(attack_contract.get("expected_injections", -1))
                == expected_injections
                and attack_contract["candidate_binding"]["model_manifest_sha256"]
                == model_manifest_sha256
                and attack_contract["candidate_binding"]["decision_policy_sha256"]
                == decision_policy_sha256
            )
        ),
        "blind_model_identity": (
            attack.get("model_identity_gate") is True
            and attack.get("model_manifest_sha256") == model_manifest_sha256
        ),
        "normal_decision_policy_identity": (
            decision_policy_sha256 is None
            or (
                normal.get("decision_policy_identity_gate") is True
                and normal.get("decision_policy_sha256") == decision_policy_sha256
            )
        ),
        "blind_decision_policy_identity": (
            decision_policy_sha256 is None
            or (
                attack.get("decision_policy_identity_gate") is True
                and attack.get("decision_policy_sha256") == decision_policy_sha256
            )
        ),
        "blind_recall": float(attack.get("recall", 0.0)) >= minimum_recall,
        "kernel_to_alert_p99": attack.get("latency_gate_p99_le_2s") is True,
        "inference_p99": inference_p99 is not None and float(inference_p99) <= maximum_inference_p99_ms,
        "post_window_processing_p99": (
            processing_p99 is not None
            and float(processing_p99) <= maximum_processing_p99_seconds
        ),
    }
    failures = [name for name, passed in gates.items() if not passed]
    eligible = not failures
    return {
        "schema": "sentinel-pulse-candidate-decision-v1",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "status": "eligible_for_overhead_evaluation" if eligible else "research_candidate_failed_gates",
        "automatic_production_promotion": False,
        "production_ready": False,
        "evidence_complete_for_accuracy_latency": eligible,
        "failed_gates": failures,
        "gates": gates,
        "candidate_workloads": candidates,
        "collect_only_workloads": collect_only,
        "missing_normal_soak_workloads": missing_normal,
        "requirements": {
            "minimum_recall": minimum_recall,
            "expected_injections": expected_injections,
            "maximum_kernel_to_alert_p99_seconds": 2.0,
            "maximum_inference_p99_ms": maximum_inference_p99_ms,
            "maximum_post_window_processing_p99_seconds": maximum_processing_p99_seconds,
            "normal_soak_gate": "24 wall-clock hours per workload, zero observed alerts",
            "minimum_normal_second_bucket_coverage": 0.95,
            "decision_policy_sha256": decision_policy_sha256,
            "soak_marker_sha256": soak_marker_sha256,
        },
        "observed": {
            "normal_scored_windows": normal.get("scored_windows"),
            "normal_alerts": normal.get("alerts"),
            "normal_false_alert_rate_wilson_95": normal.get("false_alert_rate_wilson_95"),
            "blind_expected": attack.get("expected_injections"),
            "blind_detected": attack.get("detected_injections"),
            "blind_recall": attack.get("recall"),
            "kernel_to_alert_seconds": attack.get("kernel_to_alert_seconds"),
            "injection_command_to_alert_seconds": attack.get(
                "injection_command_to_alert_seconds"
            ),
            "inference_ms": attack.get("inference_ms"),
            "post_window_processing_seconds": attack.get("post_window_processing_seconds"),
        },
        "source_sha256": {
            "model_manifest": sha256_file(model_dir / "manifest.json"),
            "model_manifest_checksum": sha256_file(model_dir / "manifest.sha256"),
            "decision_policy": (
                sha256_file(decision_policy_path)
                if decision_policy_path is not None
                else None
            ),
            "normal_soak_report": sha256_file(normal_report_path),
            "normal_soak_marker": soak_marker_sha256,
            "blind_attack_report": sha256_file(attack_report_path),
            "blind_attack_contract": attack_contract_sha256,
        },
        "next_gate": (
            "counterbalanced A/B overhead and independent reproduction; manual review remains required"
            if eligible else "freeze this result; create a new candidate instead of tuning on blind outcomes"
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model-dir", type=Path, required=True)
    parser.add_argument("--normal-report", type=Path, required=True)
    parser.add_argument("--attack-report", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--minimum-recall", type=float, default=0.975)
    parser.add_argument("--expected-injections", type=int, default=450)
    parser.add_argument("--maximum-inference-p99-ms", type=float, default=50.0)
    parser.add_argument("--maximum-processing-p99-seconds", type=float, default=0.75)
    parser.add_argument("--decision-policy", type=Path)
    parser.add_argument("--soak-marker", type=Path, required=True)
    parser.add_argument("--attack-contract", type=Path)
    args = parser.parse_args()
    decision = build_decision(
        args.model_dir,
        args.normal_report,
        args.attack_report,
        args.minimum_recall,
        args.expected_injections,
        args.maximum_inference_p99_ms,
        args.maximum_processing_p99_seconds,
        args.decision_policy,
        args.soak_marker,
        args.attack_contract,
    )
    if args.output.exists():
        existing = read_json(args.output)
        if (
            existing.get("source_sha256") != decision["source_sha256"]
            or existing.get("requirements") != decision["requirements"]
        ):
            raise ValueError("existing terminal decision belongs to different evidence or gates")
        raise SystemExit(0 if existing.get("evidence_complete_for_accuracy_latency") else 1)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    temporary = args.output.with_suffix(args.output.suffix + ".tmp")
    temporary.write_text(json.dumps(decision, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, args.output)
    raise SystemExit(0 if decision["evidence_complete_for_accuracy_latency"] else 1)


if __name__ == "__main__":
    main()
