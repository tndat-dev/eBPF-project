"""Assemble the terminal V8 syscall paper matrix from immutable derivatives."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
from typing import Any

from evaluation_matrix_validation import validate_evaluation_matrix


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


def phase_exposure_hours(normal: dict[str, Any]) -> float:
    seconds = 0.0
    for phase in normal.get("phases", []):
        manifest = Path(phase["source"]["manifest"])
        source = read_json(manifest)
        seconds += float(source["actual_duration_seconds"])
    return seconds / 3600.0


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
    exposure = phase_exposure_hours(normal)
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
        },
        "attack": {
            "trials": trials, "detected": detected,
            "recall": attack["recall"],
            **classification_metrics(detected, trials, false_alerts),
            "by_scenario": attack.get("by_scenario", {}),
            "by_workload": attack.get("by_workload", {}),
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
    return {
        **common_result_fields(common, f"syscall__{method}", code_digest),
        "normal": normal,
        "attack": {
            **attack, **classification_metrics(detected, trials, false_alerts),
        },
        "latency_seconds": normalized_latency(latency),
        "statistics": {
            "confidence_level": 0.95,
            "method": "Wilson score interval for recall; paired descriptive metrics",
        },
        "fast_path": {"enabled": False, "replayed": False},
    }


def live_fast_path(report_path: Path) -> dict[str, Any]:
    aggregate = read_json(report_path)
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
    required = [
        attack_capture, attack_capture_manifest, dataset, dataset_manifest,
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
        "evaluation_protocol_sha256": sha256(protocol_path),
        "environment_sha256": digest_json(environment),
    }
    normal_manifest = read_json(normal_capture_manifest)
    normal_windows = int(normal_manifest["validation"]["feature_windows"])
    split = read_json(evidence / "v8_capture_split_contract.json")
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
        fast = live_fast_path(attack_root / "report.json")
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
        }
        falco_attack_summary = {
            "trials": int(falco_attack["trial_count"]),
            "detected": int(falco_attack["detected_trials"]),
            "recall": falco_attack["recall"],
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
