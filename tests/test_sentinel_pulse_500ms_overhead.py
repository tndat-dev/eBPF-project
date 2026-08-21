import json
from pathlib import Path

import pytest

from sentinel_pulse.aggregate_500ms_overhead import aggregate


def write_phase(root: Path, campaign: str, name: str, condition: str, rps: float, p99: float):
    directory = root / f"{name}-20260817T000000Z"
    directory.mkdir()
    report = {
        "experiment_id": campaign,
        "phase": name,
        "url": "http://10.0.2.1/api/products/",
        "quality_gate": {"passed": True},
        "failed_requests_total": 0,
        "runs": [{"run": 1}],
        "requests_per_second": {"median": rps},
        "latency_p99_ms": {"median": p99},
        "condition": condition,
    }
    (directory / "report.json").write_text(json.dumps(report))


def protocol(root: Path, phases: list[dict], mode: str = "smoke") -> Path:
    path = root / "protocol.json"
    path.write_text(json.dumps({
        "schema": "sentinel-pulse-500ms-overhead-protocol-v1",
        "campaign_id": "campaign-a",
        "mode": mode,
        "endpoint": {"url": "http://10.0.2.1/api/products/"},
        "repetitions_per_phase": 1,
        "phases": phases,
    }))
    return path


def write_pipeline_inputs(root: Path, phases: list[dict]) -> dict:
    import hashlib

    frozen = root / "frozen-inputs"
    frozen.mkdir()
    model = frozen / "model-manifest.json"
    policy = frozen / "decision-policy.json"
    contract = frozen / "pipeline-overhead-contract.json"
    model.write_text('{"model":"frozen"}')
    policy.write_text('{"policy":"frozen"}')
    contract.write_text(json.dumps({
        "registered_before_blind_outcomes": True,
        "automatic_promotion": False,
        "design": {"phase_order": [item["condition"] for item in phases]},
    }))
    digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
    candidate = frozen / "CANDIDATE_DECISION.json"
    candidate.write_text(json.dumps({
        "status": "eligible_for_overhead_evaluation",
        "evidence_complete_for_accuracy_latency": True,
        "automatic_production_promotion": False,
        "source_sha256": {
            "model_manifest": digest(model),
            "decision_policy": digest(policy),
        },
    }))
    return {
        "candidate_decision_sha256": digest(candidate),
        "model_manifest_sha256": digest(model),
        "decision_policy_sha256": digest(policy),
        "overhead_contract_sha256": digest(contract),
    }


def write_pipeline_detector(root: Path, phase: dict, binding: dict, *, alert=False):
    (root / f'{phase["name"]}-detector-final.txt').write_text(
        "ActiveState=active\nNRestarts=0\n"
    )
    run = root / "detector-runs/var/lib/sentinel-pulse-detector/runs" / phase["name"]
    run.mkdir(parents=True, exist_ok=True)
    record = {
        "schema": "sentinel-pulse-decision-v1",
        "status": "alert" if alert else "normal",
        "run_id": phase["treatment_run_id"],
        "model_manifest_sha256": binding["model_manifest_sha256"],
        "decision_policy_sha256": binding["decision_policy_sha256"],
    }
    (run / "decisions.jsonl").write_text(json.dumps(record) + "\n")
    (run / "alerts.jsonl").write_text(json.dumps(record) + "\n" if alert else "")


def test_aggregate_accepts_balanced_smoke_pair(tmp_path):
    phases = []
    for index, (condition, rps, p99) in enumerate(
        (("off", 100.0, 10.0), ("on", 95.0, 11.0)), 1
    ):
        name = f"p{index:02d}-{condition}"
        phases.append({
            "index": index,
            "name": name,
            "condition": condition,
        })
        write_phase(tmp_path, "campaign-a", name, condition, rps, p99)
    report = aggregate(tmp_path, protocol(tmp_path, phases))
    assert report["valid"] is True
    assert report["inferential"] is False
    assert report["effects"]["throughput_loss"]["median_percent"] == pytest.approx(5.0)
    assert report["effects"]["p99_latency_increase"]["median_percent"] == pytest.approx(10.0)


def test_aggregate_rejects_unbalanced_pair(tmp_path):
    phases = []
    for index in (1, 2):
        name = f"p{index:02d}-off"
        phases.append({
            "index": index,
            "name": name,
            "condition": "off",
        })
        write_phase(tmp_path, "campaign-a", name, "off", 100.0, 10.0)
    with pytest.raises(ValueError, match="not OFF/ON balanced"):
        aggregate(tmp_path, protocol(tmp_path, phases))


def test_pipeline_aggregate_binds_terminal_candidate_and_zero_alert_stream(tmp_path):
    phases = []
    for index, (condition, rps, p99) in enumerate(
        (("off", 100.0, 10.0), ("on", 98.0, 10.2)), 1
    ):
        name = f"p{index:02d}-{condition}"
        phase = {
            "index": index,
            "name": name,
            "condition": condition,
            "treatment_run_id": f"campaign-a-{name}" if condition == "on" else None,
        }
        phases.append(phase)
        write_phase(tmp_path, "campaign-a", name, condition, rps, p99)
    binding = write_pipeline_inputs(tmp_path, phases)
    write_pipeline_detector(tmp_path, phases[1], binding)
    path = protocol(tmp_path, phases, mode="full")
    payload = json.loads(path.read_text())
    payload["treatment"] = "pipeline"
    payload["candidate_binding"] = binding
    path.write_text(json.dumps(payload))
    report = aggregate(tmp_path, path)
    assert report["valid"] is True
    assert report["pipeline_candidate_binding"] == binding
    assert report["pipeline_treatment_evidence"][0]["decisions"] == 1
    assert report["pipeline_treatment_evidence"][0]["alerts"] == 0


def test_pipeline_aggregate_rejects_normal_alert(tmp_path):
    phases = []
    for index, condition in enumerate(("off", "on"), 1):
        name = f"p{index:02d}-{condition}"
        phase = {
            "index": index, "name": name, "condition": condition,
            "treatment_run_id": f"campaign-a-{name}" if condition == "on" else None,
        }
        phases.append(phase)
        write_phase(tmp_path, "campaign-a", name, condition, 100.0, 10.0)
    binding = write_pipeline_inputs(tmp_path, phases)
    write_pipeline_detector(tmp_path, phases[1], binding, alert=True)
    path = protocol(tmp_path, phases, mode="full")
    payload = json.loads(path.read_text())
    payload.update(treatment="pipeline", candidate_binding=binding)
    path.write_text(json.dumps(payload))
    with pytest.raises(ValueError, match="detector stream"):
        aggregate(tmp_path, path)
