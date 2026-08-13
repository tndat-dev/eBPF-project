import hashlib
import json
from pathlib import Path
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ml-service"))

from finalize_v8_stable_release import build_decision


def write_checksums(root: Path):
    lines = []
    for path in sorted(p for p in root.rglob("*") if p.is_file() and p.name != "SHA256SUMS"):
        lines.append(
            f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.relative_to(root)}\n"
        )
    (root / "SHA256SUMS").write_text("".join(lines))


def evidence(tmp_path: Path, recall: float = 0.975):
    release_id = "v8-paired-replay-20260811"
    contract = tmp_path / "contract.json"
    contract.write_text(json.dumps({
        "eligible_targets": ["production/api"],
        "excluded_targets": {"production/payment": "sandbox"},
        "normal_protocol": {"promotion_false_positive_alerts": 0},
        "attack_protocol": {"promotion_recall": 1.0},
        "promotion": {"automatic": False},
    }))
    matrix = tmp_path / "matrix"
    (matrix / "syscall__full_v7").mkdir(parents=True)
    (matrix / "evaluation_matrix_manifest.json").write_text(json.dumps({
        "valid": True, "completed_experiments": 11,
    }))
    (matrix / "paired_statistics.json").write_text(json.dumps({
        "methods": 11, "pairwise_comparisons": 55,
    }))
    (matrix / "syscall__full_v7" / "result.json").write_text(json.dumps({
        "experiment_id": "syscall__full_v7", "release_id": release_id,
        "development_gate": {"accepted": True},
        "normal": {"independent_runs": 5, "phases": 20, "windows": 122639,
                   "exposure_hours": 24.005, "false_alerts": 0},
        "attack": {"trials": 200, "detected": int(recall * 200),
                   "recall": {"estimate": recall}},
        "latency_seconds": {"median": 18.25},
        "inference_ms": {"median": 12.7},
    }))
    write_checksums(matrix)
    (tmp_path / "NORMAL_ABLATION_REPLAY_COMPLETE").write_text("")

    overhead = tmp_path / "overhead"
    overhead.mkdir()
    (overhead / f"counterbalanced-{release_id}.json").write_text(json.dumps({
        "schema": "sentinel-aims-overhead-counterbalanced/v1",
        "campaign_prefix": release_id, "evidence_release": "v8",
        "experiments": [{}] * 6,
        "effects": {"full_pipeline_vs_no_tracing": {"throughput_loss": {"median_percent": 1}}},
    }))
    write_checksums(overhead)
    (overhead / "V8_OVERHEAD_COMPLETE").write_text("")
    return contract, matrix, overhead


def test_finalizer_preserves_failed_preregistered_recall_gate(tmp_path):
    decision = build_decision(*evidence(tmp_path, recall=0.975))
    assert decision["evidence_complete"] is True
    assert decision["status"] == "research_stable_dry_run_only"
    assert decision["manual_production_promotion_eligible"] is False
    assert decision["failed_preregistered_gates"] == ["blind_attack"]
    assert decision["automatic_promotion"] is False


def test_finalizer_marks_perfect_candidate_manual_only(tmp_path):
    decision = build_decision(*evidence(tmp_path, recall=1.0))
    assert decision["status"] == "eligible_for_manual_promotion"
    assert decision["manual_production_promotion_eligible"] is True
    assert decision["failed_preregistered_gates"] == []
    assert decision["automatic_promotion"] is False


def test_finalizer_rejects_tampered_terminal_artifact(tmp_path):
    contract, matrix, overhead = evidence(tmp_path)
    (matrix / "paired_statistics.json").write_text("{}")
    with pytest.raises(ValueError, match="checksum mismatch"):
        build_decision(contract, matrix, overhead)


def test_release_finalizer_unit_is_terminal_gated():
    service = (ROOT / "sentinel/systemd/aims-v8-release-finalize.service").read_text()
    path = (ROOT / "sentinel/systemd/aims-v8-release-finalize.path").read_text()
    assert "ConditionPathExists=" in service
    assert "V8_OVERHEAD_COMPLETE" in service and "V8_OVERHEAD_COMPLETE" in path
    assert "finalize_v8_stable_release.py" in service
    assert "promote_candidate.py" not in service
