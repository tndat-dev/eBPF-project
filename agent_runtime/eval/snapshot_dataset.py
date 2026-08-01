"""Validated access to sanitized graph-snapshot JSONL datasets."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from agent_runtime.mcp.graph import MCPEvent, SlidingMCPGraph

APPROVED_NORMAL = "approved_normal"


def load_records(path: str | Path) -> list[dict]:
    """Load JSONL records and report the source line on malformed input."""
    records: list[dict] = []
    for line_number, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError as error:
            raise ValueError(f"invalid JSON at snapshot line {line_number}") from error
    return records


def rejected_review_count(records: list[dict]) -> int:
    return sum(record.get("review_status") != APPROVED_NORMAL for record in records)


def build_snapshots(records: list[dict], *, require_approved: bool = True):
    result = []
    for line_number, value in enumerate(records, start=1):
        if require_approved and value.get("review_status") != APPROVED_NORMAL:
            raise ValueError(f"snapshot line {line_number} is not explicitly reviewed as {APPROVED_NORMAL}")
        graph = SlidingMCPGraph(window_seconds=float(value["window_seconds"]))
        graph.add_events(MCPEvent(**event) for event in value["events"])
        result.append(graph.snapshot(now=float(value["generated_at"])))
    return result


def dataset_digest(path: str | Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()
