from __future__ import annotations

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agent_runtime.eval.replay_validation import run_validation


def test_replay_validation_has_no_normal_alerts_and_detects_every_agent_scenario():
    report = run_validation(window_seconds=10)
    assert report["normal_alerts"] == 0
    assert report["normal_pending"] == 0
    assert report["attack_detected"] == report["attack_total"] == 5
    for result in report["attacks"].values():
        assert result["pending_first"] is True
        assert result["inference_ms"] < 100
