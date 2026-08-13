"""Assemble the terminal V8 syscall paper matrix from immutable derivatives."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import shutil
import tempfile
from typing import Any

from analyze_syscall_evaluation_matrix import analyze_matrix
from evaluation_matrix_validation import validate_evaluation_matrix
from render_syscall_paper_results import render


ML_METHODS = (
    "isolation_forest", "lstm_only", "evt_pot", "full_v7",
    "without_fast_path", "without_behavior_gate",
    "without_extreme_volume_gate", "without_two_window_confirmation",
    "shared_workload_model",
)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def digest_json(document: Any) -> str:
    payload = json.dumps(
        document, sort_keys=True, separators=(",", ":")
    ).encode()
    return hashlib.sha256(payload).hexdigest()


def read_json(path: Path) -> dict[str, Any]:
    document = json.loads(path.read_text())
    if not isinstance(document, dict):
        raise ValueError(f"JSON object required: {path}")
    return document


def verify_checksums(root: Path) -> None:
    checksum = root / "SHA256SUMS"
    if not checksum.is_file():
        raise ValueError("existing matrix has no checksum manifest")
    for line in checksum.read_text().splitlines():
        digest, relative = line.split(maxsplit=1)
        path = (root / relative.strip()).resolve()
        if not path.is_relative_to(root.resolve()) or not path.is_file():
            raise ValueError("matrix checksum path is invalid")
        if sha256(path) != digest:
            raise ValueError(f"matrix checksum mismatch: {relative.strip()}")


def normalized_latency(document: dict[str, Any]) -> dict[str, Any]:
    count = int(document.get("count", document.get("sample_count", 0)))
    return {
        "sample_count": count,
        "minimum": document.get("minimum", document.get("min")),
        "median": document.get("median"),
        "p95": document.get("p95"),
        "p99": document.get("p99"),
        "maximum": document.get("maximum", document.get("max")),
    }


def normalized_outcomes(
    items: list[dict[str, Any]], *, horizon_seconds: float,
) -> list[dict[str, Any]]:
    outcomes = []
    for item in items:
        latency = item.get(
            "first_confirmation_latency_seconds",
            item.get("first_alert_latency_seconds", item.get("latency_seconds")),
        )
        start, end = float(item["start"]), float(item["end"])
        attribution_end = float(item.get(
            "attribution_end", end + horizon_seconds,
        ))
        if attribution_end < end or attribution_end <= start:
            raise ValueError("invalid attack attribution/censor boundary")
        outcomes.append({
            "injection_id": str(item["injection_id"]),
            "pod_key": str(item["pod_key"]),
            "scenario": str(item["scenario"]),
            "seed": int(item["seed"]),
            "rate": int(item["rate"]),
            "detected": bool(item["detected"]),
            "latency_seconds": float(latency) if latency is not None else None,
            "censor_seconds": attribution_end - start,
            "horizon_right_censored": bool(
                item.get("horizon_right_censored_by_next_injection", False)
            ),
        })
    outcomes.sort(key=lambda row: row["injection_id"])
    if len(outcomes) != len({row["injection_id"] for row in outcomes}):
        raise ValueError("duplicate injection ID in method outcomes")
    return outcomes


def normalized_normal_phases(
    items: list[dict[str, Any]], common: dict[str, Any], *,
    expected_false_alerts: int,
) -> list[dict[str, Any]]:
    indexed = {str(item["phase"]): item for item in items}
    expected = common["normal_phase_contract"]
    if set(indexed) != set(expected):
        raise ValueError("normal phase outcome set mismatch")
    outcomes = []
    for phase, identity in expected.items():
        source = indexed[phase]
        observed_run = source.get("run_id")
        if observed_run is not None and observed_run != identity["run_id"]:
            raise ValueError(f"normal phase run mismatch: {phase}")
        alerts = int(source.get(
            "false_alerts", source.get("alert_count", source.get("alerts", -1))
        ))
        if alerts < 0:
            raise ValueError(f"normal phase alert count is missing: {phase}")
        outcomes.append({
            "phase": phase,
            "run_id": identity["run_id"],
            "traffic_regime": identity["traffic_regime"],
            "windows": (
                int(source["windows"]) if source.get("windows") is not None else None
            ),
            "false_alerts": alerts,
            "exposure_seconds": identity["exposure_seconds"],
        })
    if sum(item["false_alerts"] for item in outcomes) != expected_false_alerts:
        raise ValueError("normal phase alerts do not equal aggregate false alerts")
    return outcomes


def classification_metrics(detected: int, trials: int, false_alerts: int) -> dict:
    if trials < 1 or not 0 <= detected <= trials or false_alerts < 0:
        raise ValueError("invalid classification counts")
    precision = detected / (detected + false_alerts) if detected + false_alerts else 0.0
    recall = detected / trials
    f1 = (
        2.0 * precision * recall / (precision + recall)
        if precision + recall else 0.0
    )
    return {
        "precision": precision, "recall_point": recall, "f1": f1,
        "definition": (
            "TP=detected blind trials; FN=missed blind trials; "
            "FP=alerts during independent normal windows"
        ),
    }


def common_result_fields(common: dict[str, Any], experiment_id: str,
                         code_digest: str) -> dict[str, Any]:
    return {
        "schema": common["contract"]["result_schema"],
        "experiment_id": experiment_id,
        "track": "syscall",
        "release_id": common["contract"]["release_id"],
        "feature_capture_schema": common["contract"]["feature_capture_schema"],
        "injection_schema": common["contract"]["injection_schema"],
        "completed": True,
        "blind_set_used_for_training": False,
        "paired_replay": True,
        "trial_seeds": common["contract"]["trial_seeds"],
        "dataset_sha256": common["dataset_sha256"],
        "dataset_manifest_sha256": common["dataset_manifest_sha256"],
        "capture_sha256": common["capture_sha256"],
        "capture_manifest_sha256": common["capture_manifest_sha256"],
        "normal_capture_sha256": common["normal_capture_sha256"],
        "normal_capture_manifest_sha256": common[
            "normal_capture_manifest_sha256"
        ],
        "vocab_sha256": common["vocab_sha256"],
        "split_sha256": common["split_sha256"],
        "blind_attack_contract_sha256": common["blind_attack_contract_sha256"],
        "attack_observability_audit_sha256": common[
            "attack_observability_audit_sha256"
        ],
        "evaluation_protocol_sha256": common["evaluation_protocol_sha256"],
        "environment_sha256": common["environment_sha256"],
        "code_sha256": code_digest,
    }


def build_ml_result(
    method: str, normal: dict[str, Any], attack: dict[str, Any],
    common: dict[str, Any], *, fast_path: dict[str, Any] | None = None,
) -> dict[str, Any]:
    experiment_id = f"syscall__{method}"
    if normal.get("experiment_id") != experiment_id:
        raise ValueError(f"{method}: normal experiment identity mismatch")
    if attack.get("experiment_id") != experiment_id:
        raise ValueError(f"{method}: attack experiment identity mismatch")
    if normal.get("status") != "complete" or attack.get("status") != "complete":
        raise ValueError(f"{method}: replay is incomplete")
    if int(attack.get("completed_trials", 0)) != 200:
        raise ValueError(f"{method}: attack replay does not contain 200 trials")
    if attack.get("labels_used_for_training_or_tuning") is not False:
        raise ValueError(f"{method}: blind label exclusion is missing")
    normal_policy = dict(normal.get("evaluation_policy", {}))
    attack_policy = dict(attack.get("evaluation_policy", {}))
    attack_policy.pop("fast_path_replayed", None)
    if normal_policy != attack_policy:
        raise ValueError(f"{method}: normal/attack policy mismatch")
    if normal.get("candidate_sha256") != attack.get("candidate_sha256"):
        raise ValueError(f"{method}: normal/attack candidate mismatch")
    if (
        normal.get("initial_calibration_sha256")
        != attack.get("initial_calibration_sha256")
    ):
        raise ValueError(f"{method}: normal/attack calibration mismatch")
    if attack.get("attack_capture_sha256") != common["capture_sha256"]:
        raise ValueError(f"{method}: attack capture mismatch")
    if attack.get("evaluation_protocol_sha256") != common["evaluation_protocol_sha256"]:
        raise ValueError(f"{method}: evaluation protocol mismatch")

    phases = list(normal.get("phases", []))
    run_ids = {
        phase["phase"].rsplit("-", 1)[-1] for phase in phases
    }
    false_alerts = int(normal.get("alerts", -1))
    if false_alerts < 0 or false_alerts != int(normal.get("detections", -2)):
        raise ValueError(f"{method}: normal alert accounting mismatch")
    trials = int(attack["completed_trials"])
    detected = int(attack["detected_trials"])
    normal_phase_outcomes = normalized_normal_phases(
        phases, common, expected_false_alerts=false_alerts,
    )
    exposure = sum(
        item["exposure_seconds"] for item in normal_phase_outcomes
    ) / 3600.0
    horizon = float(attack["post_attack_horizon_seconds"])
    outcomes = normalized_outcomes(
        list(attack.get("trials", [])), horizon_seconds=horizon,
    )
    if len(outcomes) != trials:
        raise ValueError(f"{method}: attack outcomes are incomplete")
    result = {
        **common_result_fields(
            common, experiment_id,
            digest_json({
                "normal_evaluator_sha256": sha256(
                    Path(__file__).with_name("evaluate_aims_normal_split.py")
                ),
                "attack_evaluator_sha256": sha256(
                    Path(__file__).with_name("evaluate_aims_attack_replay.py")
                ),
                "policy": normal_policy,
            }),
        ),
        "normal": {
            "independent_runs": len(run_ids), "phases": len(phases),
            "windows": int(normal.get("windows", 0)),
            "false_alerts": false_alerts,
            "exposure_hours": exposure,
            "false_alerts_per_hour": false_alerts / exposure if exposure else None,
            "phase_outcomes": normal_phase_outcomes,
        },
        "attack": {
            "trials": trials, "detected": detected,
            "recall": attack["recall"],
            **classification_metrics(detected, trials, false_alerts),
            "by_scenario": attack.get("by_scenario", {}),
            "by_workload": attack.get("by_workload", {}),
            "post_attack_horizon_seconds": horizon,
            "outcomes": outcomes,
        },
        "latency_seconds": normalized_latency(attack.get("latency_seconds", {})),
        "inference_ms": attack.get("trial_median_inference_ms", {}),
        "statistics": {
            "confidence_level": 0.95,
            "method": "Wilson score interval for recall; paired descriptive metrics",
        },
        "policy": normal_policy,
        "fast_path": fast_path or {
            "enabled": False, "replayed": False,
            "reason": "method does not include the early-warning lane",
        },
        "source_reports": {
            "normal_sha256": digest_json(normal),
            "attack_sha256": digest_json(attack),
        },
    }
    return result


def build_rule_result(
    method: str, normal: dict[str, Any], attack: dict[str, Any],
    latency: dict[str, Any], common: dict[str, Any], code_digest: str,
) -> dict[str, Any]:
    trials, detected = int(attack["trials"]), int(attack["detected"])
    false_alerts = int(normal["false_alerts"])
    exposure_hours = float(normal["exposure_hours"])
    observed_rate = normal.get(
        "false_alerts_per_hour", normal.get("alerts_per_hour")
    )
    expected_rate = false_alerts / exposure_hours if exposure_hours else None
    if observed_rate is not None and expected_rate is not None and not math.isclose(
        float(observed_rate), expected_rate, rel_tol=1e-9, abs_tol=1e-12,
    ):
        raise ValueError(f"{method}: normal alert-rate accounting mismatch")
    normal["false_alerts_per_hour"] = expected_rate
    normal.pop("alerts_per_hour", None)
    normal["phase_outcomes"] = normalized_normal_phases(
        list(normal.get("phase_outcomes", [])), common,
        expected_false_alerts=false_alerts,
    )
    horizon = float(attack["post_attack_horizon_seconds"])
    outcomes = normalized_outcomes(
        list(attack.get("outcomes", [])), horizon_seconds=horizon,
    )
    if len(outcomes) != trials:
        raise ValueError(f"{method}: attack outcomes are incomplete")
    return {
        **common_result_fields(common, f"syscall__{method}", code_digest),
        "normal": normal,
        "attack": {
            **attack, "outcomes": outcomes,
            **classification_metrics(detected, trials, false_alerts),
        },
        "latency_seconds": normalized_latency(latency),
        "statistics": {
            "confidence_level": 0.95,
            "method": "Wilson score interval for recall; paired descriptive metrics",
        },
        "fast_path": {"enabled": False, "replayed": False},
    }


def live_fast_path(
    report_path: Path, normal_report_path: Path, exclusion_report_path: Path,
) -> dict[str, Any]:
    aggregate = read_json(report_path)
    if normal_report_path.is_file() and exclusion_report_path.exists():
        raise ValueError("fast-path normal track is both accepted and excluded")
    if normal_report_path.is_file():
        normal = read_json(normal_report_path)
        if (
            normal.get("schema") != "sentinel-fast-path-normal-evidence/v1"
            or normal.get("valid") is not True
            or normal.get("phase_count") != 20
            or normal.get("independent_runs") != 5
            or normal.get("evidence_class")
            != "retrospective_operational_normal_evidence"
        ):
            raise ValueError("live fast-path normal evidence is invalid")
        normal_summary = {
            "status": "accepted",
            "evidence_class": normal["evidence_class"],
            "claim_limit": normal["claim_limit"],
            "independent_runs": normal["independent_runs"],
            "phases": normal["phase_count"],
            "exposure_hours": normal["normal_duration_seconds"] / 3600.0,
            "early_warning_count": normal["early_warning_count"],
            "early_warnings_per_hour": normal["early_warnings_per_hour"],
            "report_sha256": sha256(normal_report_path),
        }
    else:
        exclusion = read_json(exclusion_report_path)
        if not (
            exclusion.get("schema")
            == "sentinel-fast-path-normal-exclusion/v1"
            and exclusion.get("valid") is False
            and exclusion.get("status") == "excluded"
            and exclusion.get("claim_available") is False
            and exclusion.get("automatic_promotion") is False
        ):
            raise ValueError("live fast-path exclusion evidence is invalid")
        normal_summary = {
            "status": "excluded",
            "evidence_class": exclusion.get("evidence_class"),
            "claim_limit": exclusion.get("claim_limit"),
            "reason": exclusion.get("reason"),
            "independent_runs": None,
            "phases": None,
            "exposure_hours": None,
            "early_warning_count": None,
            "early_warnings_per_hour": None,
            "report_sha256": sha256(exclusion_report_path),
        }
    rows = []
    for trial in aggregate.get("trials", []):
        child_path = Path(str(trial.get("report_path", "")))
        child = read_json(child_path)
        for scenario, item in child.get("scenarios", {}).items():
            rows.append({"scenario": scenario, **item})
    if len(rows) != 200:
        raise ValueError(f"live fast-path report has {len(rows)}/200 scenarios")
    expected = [item for item in rows if item.get("fast_path_expected") is True]
    matched = [item for item in expected if item.get("fast_path_expected_matched") is True]
    latencies = sorted(
        float(item["fast_path_latency_seconds"])
        for item in rows if item.get("fast_path_latency_seconds") is not None
    )
    def percentile(fraction: float) -> float | None:
        if not latencies:
            return None
        position = (len(latencies) - 1) * fraction
        lower, upper = int(position), min(len(latencies) - 1, int(position) + 1)
        return latencies[lower] + (latencies[upper] - latencies[lower]) * (position - lower)
    return {
        "enabled": True, "replayed": False, "source": "live blind harness",
        "scenario_trials": len(rows), "expected_trials": len(expected),
        "expected_matched": len(matched),
        "expected_recall": len(matched) / len(expected) if expected else None,
        "warning_trials": sum(int(item.get("fast_path_warning_count", 0)) > 0 for item in rows),
        "latency_seconds": {
            "sample_count": len(latencies),
            "minimum": latencies[0] if latencies else None,
            "median": percentile(0.50), "p95": percentile(0.95),
            "p99": percentile(0.99), "maximum": latencies[-1] if latencies else None,
        },
        "report_sha256": sha256(report_path),
        "normal_operational_evidence": normal_summary,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument("--derived-root", type=Path, required=True)
    parser.add_argument("--attack-root", type=Path, required=True)
    parser.add_argument("--falco-root", type=Path, required=True)
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--protocol", type=Path, required=True)
    parser.add_argument("--attack-contract", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    args = parser.parse_args()
    evidence = args.evidence_root.resolve()
    derived = args.derived_root.resolve()
    attack_root = args.attack_root.resolve()
    falco_root = args.falco_root.resolve()
    output = args.output_root.resolve()
    contract_path, protocol_path = args.contract.resolve(), args.protocol.resolve()
    attack_contract_path = args.attack_contract.resolve()
    contract, protocol = read_json(contract_path), read_json(protocol_path)
    expected = set(contract["tracks"]["syscall"]["baselines"])
    expected.update(contract["tracks"]["syscall"]["ablations"])
    if set(protocol.get("methods", {})) != expected:
        raise ValueError("evaluation protocol/matrix method mismatch")

    attack_capture = attack_root / "frozen-attack-feature-capture.jsonl"
    attack_capture_manifest = attack_root / "frozen-attack-feature-capture.manifest.json"
    normal_capture = evidence / "frozen-normal-feature-capture.jsonl"
    normal_capture_manifest = evidence / "frozen-normal-feature-capture.manifest.json"
    dataset = attack_root / "frozen-attack-replay.jsonl"
    dataset_manifest = attack_root / "frozen-attack-replay.manifest.json"
    attack_report = attack_root / "report.json"
    observability_audit = attack_root / "attack-observability-audit.json"
    required = [
        attack_capture, attack_capture_manifest, dataset, dataset_manifest,
        attack_report, observability_audit,
        evidence / "vocab.pkl", evidence / "v8_capture_split_contract.json",
        normal_capture, normal_capture_manifest,
        evidence / "nodes-before.txt", evidence / "pods-before.txt",
        evidence / "tetragon-policy-live.yaml",
        falco_root / "collection-contract.json",
        falco_root / "falco-daemonset.yaml",
        falco_root / "falco-configmap.yaml",
    ]
    for path in required:
        if not path.is_file():
            raise FileNotFoundError(path)

    observability = read_json(observability_audit)
    if not (
        observability.get("schema") == "sentinel-attack-observability-audit/v1"
        and observability.get("status") == "complete"
        and observability.get("valid") is True
        and observability.get("primary_outcomes_redefined") is False
        and int(observability.get("completed_trials", -1)) == 200
        and observability.get("source_report_sha256") == sha256(attack_report)
    ):
        raise ValueError("attack observability audit is incomplete or invalid")

    environment = {
        "schema": "sentinel-syscall-environment/v1",
        "release_id": contract["release_id"],
        "sources": {
            path.name: sha256(path) for path in (
                evidence / "nodes-before.txt", evidence / "pods-before.txt",
                evidence / "tetragon-policy-live.yaml",
                falco_root / "collection-contract.json",
                falco_root / "falco-daemonset.yaml",
                falco_root / "falco-configmap.yaml",
            )
        },
    }
    common = {
        "contract": contract,
        "dataset_sha256": sha256(dataset),
        "dataset_manifest_sha256": sha256(dataset_manifest),
        "capture_sha256": sha256(attack_capture),
        "capture_manifest_sha256": sha256(attack_capture_manifest),
        "normal_capture_sha256": sha256(normal_capture),
        "normal_capture_manifest_sha256": sha256(normal_capture_manifest),
        "vocab_sha256": sha256(evidence / "vocab.pkl"),
        "split_sha256": sha256(evidence / "v8_capture_split_contract.json"),
        "blind_attack_contract_sha256": sha256(attack_contract_path),
        "attack_observability_audit_sha256": sha256(observability_audit),
        "evaluation_protocol_sha256": sha256(protocol_path),
        "environment_sha256": digest_json(environment),
    }
    normal_manifest = read_json(normal_capture_manifest)
    normal_windows = int(normal_manifest["validation"]["feature_windows"])
    split = read_json(evidence / "v8_capture_split_contract.json")
    normal_phase_contract = {}
    for run in split["normal"]["runs"]:
        if run.get("role") != "independent_evaluation":
            continue
        run_id = str(run["run_id"])
        run_number = int(run_id.rsplit("-", 1)[1])
        for regime in split["normal"]["regimes"]:
            phase = f"aims-{regime}-run-{run_number:02d}"
            manifest = read_json(evidence / phase / "collection_manifest.json")
            normal_phase_contract[phase] = {
                "run_id": run_id,
                "traffic_regime": regime,
                "exposure_seconds": float(manifest["actual_duration_seconds"]),
            }
    if len(normal_phase_contract) != 20:
        raise ValueError("normal phase contract does not contain 20 holdout phases")
    common["normal_phase_contract"] = normal_phase_contract
    independent_runs = sum(
        item.get("role") == "independent_evaluation"
        for item in split["normal"]["runs"]
    )
    independent_phases = independent_runs * len(split["normal"]["regimes"])

    if output.exists():
        verify_checksums(output)
        prior = validate_evaluation_matrix(output, contract, {"syscall"})
        if prior["valid"]:
            print(output)
            return 0
        raise ValueError(f"existing matrix is invalid: {prior['errors']}")
    output.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{output.name}.", dir=output.parent))
    try:
        environment_path = staging / "environment.json"
        environment_path.write_text(
            json.dumps(environment, sort_keys=True, separators=(",", ":"))
        )
        if sha256(environment_path) != common["environment_sha256"]:
            raise ValueError("serialized environment digest mismatch")
        shutil.copy2(
            observability_audit, staging / "attack_observability_audit.json"
        )
        fast = live_fast_path(
            attack_root / "report.json",
            derived / "fast-path-live-normal" / "fast-path-normal-evidence.report.json",
            derived / "fast-path-live-normal.exclusion.json",
        )
        ablation_root = derived / "normal-ablation-replay"
        for method in ML_METHODS:
            normal_path = ablation_root / f"syscall__{method}.json"
            attack_path = ablation_root / f"syscall__{method}.attack.json"
            normal, attack = read_json(normal_path), read_json(attack_path)
            fast_path = None
            if method == "full_v7":
                fast_path = fast
            elif method == "without_fast_path":
                fast_path = {
                    "enabled": False, "replayed": False,
                    "paired_full_v7_fast_path_sha256": fast["report_sha256"],
                }
            result = build_ml_result(
                method, normal, attack, common, fast_path=fast_path,
            )
            directory = staging / f"syscall__{method}"
            directory.mkdir()
            (directory / "result.json").write_text(
                json.dumps(result, indent=2, sort_keys=True) + "\n"
            )

        tetragon_path = derived / "tetragon-rule-only-replay" / "tetragon-rule-replay.report.json"
        tetragon = read_json(tetragon_path)
        if tetragon.get("evaluation_protocol_sha256") != common["evaluation_protocol_sha256"]:
            raise ValueError("Tetragon protocol digest mismatch")
        tetragon_result = build_rule_result(
            "tetragon_rule_only", tetragon["normal"], tetragon["attack"],
            tetragon["latency_seconds"], common,
            sha256(Path(__file__).with_name("evaluate_tetragon_rule_replay.py")),
        )
        directory = staging / "syscall__tetragon_rule_only"
        directory.mkdir()
        (directory / "result.json").write_text(
            json.dumps(tetragon_result, indent=2, sort_keys=True) + "\n"
        )

        falco_normal_path = derived / "falco-rule-only-normal" / "falco-normal-evidence.report.json"
        falco_attack_path = attack_root / "falco-rule-only-attack" / "falco-attack-evidence.report.json"
        falco_normal, falco_attack = read_json(falco_normal_path), read_json(falco_attack_path)
        falco_normal_summary = {
            "independent_runs": independent_runs, "phases": independent_phases,
            "windows": normal_windows,
            "false_alerts": int(falco_normal["normal_alert_count"]),
            "exposure_hours": float(falco_normal["normal_duration_seconds"]) / 3600.0,
            "false_alerts_per_hour": falco_normal["normal_alerts_per_hour"],
            "phase_outcomes": falco_normal["phases"],
        }
        falco_attack_summary = {
            "trials": int(falco_attack["trial_count"]),
            "detected": int(falco_attack["detected_trials"]),
            "recall": falco_attack["recall"],
            "post_attack_horizon_seconds": float(
                falco_attack["post_attack_horizon_seconds"]
            ),
            "outcomes": falco_attack["trials"],
        }
        falco_result = build_rule_result(
            "falco_rule_only", falco_normal_summary, falco_attack_summary,
            falco_attack["latency_seconds"], common,
            digest_json({
                "collector": sha256(Path(__file__).with_name("falco_evidence_collector.py")),
                "normal": sha256(Path(__file__).with_name("falco_evidence_finalizer.py")),
                "attack": sha256(Path(__file__).with_name("falco_attack_evidence_finalizer.py")),
            }),
        )
        directory = staging / "syscall__falco_rule_only"
        directory.mkdir()
        (directory / "result.json").write_text(
            json.dumps(falco_result, indent=2, sort_keys=True) + "\n"
        )

        paired_statistics = analyze_matrix(
            staging,
            {f"syscall__{method}" for method in expected},
        )
        (staging / "paired_statistics.json").write_text(
            json.dumps(paired_statistics, indent=2, sort_keys=True) + "\n"
        )
        render(
            staging, staging / "syscall_results.md", staging / "syscall_results.csv",
        )
        validation = validate_evaluation_matrix(staging, contract, {"syscall"})
        if not validation["valid"]:
            raise ValueError(f"assembled matrix is invalid: {validation['errors']}")
        validation["created_at"] = datetime.now(timezone.utc).isoformat()
        (staging / "evaluation_matrix_manifest.json").write_text(
            json.dumps(validation, indent=2, sort_keys=True) + "\n"
        )
        checksum_lines = []
        for path in sorted(item for item in staging.rglob("*") if item.is_file()):
            checksum_lines.append(f"{sha256(path)}  {path.relative_to(staging)}\n")
        (staging / "SHA256SUMS").write_text("".join(checksum_lines))
        os.replace(staging, output)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
