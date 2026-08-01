from __future__ import annotations
import json
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from agent_runtime.eval.snapshot_collector import collect
from agent_runtime.eval.train_gat import load_snapshots

def test_collector_persists_sanitized_graph_not_plaintext():
    payload = b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search_docs","arguments":{"uri":"kb://private-runbook"}}}'
    line = json.dumps({"ts_ns": 1_000_000_000, "pid": 10, "direction": "write", "payload_hex": payload.hex()})
    rows = list(collect([line], namespace="lab", pod="agent", agent_id="docs"))
    text = json.dumps(rows)
    assert len(rows) == 1
    assert "private-runbook" not in text
    assert "search_docs" in text
    assert rows[0]["review_status"] == "pending_review"


def test_training_loader_refuses_unreviewed_records(tmp_path):
    dataset = tmp_path / "unreviewed.jsonl"
    dataset.write_text('{"events": [], "generated_at": 1, "window_seconds": 60}\n')
    try:
        load_snapshots(dataset)
    except ValueError as error:
        assert "not explicitly reviewed" in str(error)
    else:
        raise AssertionError("unreviewed dataset must be rejected")
