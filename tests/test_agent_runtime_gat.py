from __future__ import annotations

from pathlib import Path
import json
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agent_runtime.detector.gat_model import GATGraphScorer, available
from agent_runtime.detector.gat_store import load, save
from agent_runtime.eval.replay_validation import NORMAL, scenario_payload
from agent_runtime.mcp.graph import SlidingMCPGraph, parse_jsonrpc_payload


pytestmark = pytest.mark.skipif(not available(), reason="optional torch-geometric is not installed")


def _snapshot(payload: str, count: int, ts: float):
    graph = SlidingMCPGraph(window_seconds=60)
    for index in range(count):
        graph.add_events(parse_jsonrpc_payload(payload, namespace="gat", pod="agent", ts=ts + index * 0.2))
    return graph.snapshot(now=ts + 60)


def test_gat_trains_on_clean_graphs_and_scores_attack_higher():
    normal = [_snapshot(NORMAL, count, 100.0 + count) for count in (180, 240, 300, 360)]
    scorer = GATGraphScorer.fit(normal, epochs=80)
    clean_score, _ = scorer.score(normal[2])
    attack_score, explanation = scorer.score(_snapshot(scenario_payload("agent-production-delete"), 2, 300.0))
    assert attack_score > clean_score
    assert attack_score >= scorer.threshold
    assert any(node.startswith("tool:") for node in explanation)


def test_gat_release_digest_round_trip(tmp_path):
    normal = [_snapshot(NORMAL, count, 100.0 + count) for count in (180, 240, 300)]
    scorer = GATGraphScorer.fit(normal, epochs=20)
    path = tmp_path / "gat.pt"
    save(path, scorer, training_snapshots=len(normal), provenance={"dataset_sha256": "abc", "review_required": True})
    restored = load(path)
    assert restored.threshold == pytest.approx(scorer.threshold)
    manifest = json.loads(path.with_suffix(".pt.manifest.json").read_text())
    assert manifest["provenance"]["dataset_sha256"] == "abc"
