"""Versioned, validated storage for reviewed per-agent MCP baselines."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from agent_runtime.detector.online_detector import MCPBaseline


BASELINE_FORMAT = "agent-runtime-sentinel/mcp-baseline/v1"


def save_baseline(path: str | Path, baseline: MCPBaseline, *, agent_id: str) -> None:
    """Persist a reviewed baseline; the digest detects accidental edits."""

    data = {
        "format": BASELINE_FORMAT,
        "agent_id": agent_id,
        "feature_names": list(baseline.feature_names),
        "median": list(baseline.median),
        "mad": list(baseline.mad),
        "minimum_scale": baseline.minimum_scale,
    }
    data["sha256"] = _digest(data)
    Path(path).write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def load_baseline(path: str | Path, *, expected_agent_id: str | None = None) -> MCPBaseline:
    """Load only a complete, digest-valid baseline for the requested agent."""

    data = json.loads(Path(path).read_text(encoding="utf-8"))
    digest = data.pop("sha256", None)
    if data.get("format") != BASELINE_FORMAT or not isinstance(digest, str) or digest != _digest(data):
        raise ValueError("baseline format or digest is invalid")
    if expected_agent_id is not None and data.get("agent_id") != expected_agent_id:
        raise ValueError("baseline belongs to another agent")
    names = tuple(data.get("feature_names", ()))
    median = tuple(float(value) for value in data.get("median", ()))
    mad = tuple(float(value) for value in data.get("mad", ()))
    if not names or len(names) != len(median) or len(names) != len(mad) or any(value <= 0 for value in mad):
        raise ValueError("baseline dimensions are invalid")
    return MCPBaseline(names, median, mad, float(data.get("minimum_scale", 0.05)))


def _digest(data: dict[str, object]) -> str:
    canonical = json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
