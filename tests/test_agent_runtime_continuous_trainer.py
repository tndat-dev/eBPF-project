from __future__ import annotations
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from agent_runtime.eval.gat_continuous_trainer import holdout_gate, run

def test_trainer_waits_without_enough_clean_snapshots(tmp_path):
    dataset = tmp_path / "empty.jsonl"
    dataset.write_text("")
    result = run(dataset, tmp_path / "candidates", tmp_path / "state.json", min_snapshots=10, epochs=1)
    assert result["status"] == "waiting_for_clean_data"


def test_trainer_waits_for_dataset_file(tmp_path):
    result = run(tmp_path / "missing.jsonl", tmp_path / "candidates", tmp_path / "state.json", min_snapshots=10, epochs=1)
    assert result["status"] == "waiting_for_dataset"


def test_trainer_rejects_unreviewed_or_attack_records(tmp_path):
    dataset = tmp_path / "mixed.jsonl"
    dataset.write_text('{"review_status": "attack", "window_seconds": 60, "events": [], "generated_at": 1}\n')
    result = run(dataset, tmp_path / "candidates", tmp_path / "state.json", min_snapshots=1, epochs=1)
    assert result["status"] == "waiting_for_reviewed_clean_data"
    assert result["rejected"] == 1


def test_trainer_requires_diverse_approved_snapshots(tmp_path):
    dataset = tmp_path / "single-agent.jsonl"
    dataset.write_text(
        '{"review_status":"approved_normal","generated_at":1,"window_seconds":60,'
        '"events":[{"agent_id":"one","namespace":"lab","pod":"only"}]}\n'
    )
    result = run(dataset, tmp_path / "candidates", tmp_path / "state.json", min_snapshots=1, epochs=1)
    assert result["status"] == "waiting_for_diverse_data"
    assert result["unique_agents"] == 1


def test_holdout_gate_rejects_any_normal_alert_by_default():
    result = holdout_gate([0.1, 0.5, 0.9], threshold=0.5, max_alert_rate=0.0)
    assert result["holdout_alerts"] == 2
    assert result["holdout_passed"] is False
