"""Feature extraction bridge from MCP behavior graph to anomaly models."""

from __future__ import annotations

from typing import Iterable

from agent_runtime.mcp.graph import GraphSnapshot


DEFAULT_FEATURE_NAMES = (
    "events_total",
    "event_rate_per_second",
    "unique_agents",
    "unique_tools",
    "unique_resources",
    "high_risk_events",
    "high_risk_ratio",
    "max_tool_calls",
    "max_resource_touches",
    "tool_entropy",
    "raw_kib",
)


def graph_feature_vector(
    snapshot: GraphSnapshot,
    feature_names: Iterable[str] = DEFAULT_FEATURE_NAMES,
) -> list[float]:
    """Return a deterministic dense vector for a graph snapshot.

    This is the compatibility layer between the new V2 behavior graph and the
    current V1-style detector harness.  A future PyTorch Geometric GAT can use
    the richer node/edge objects directly; this vector keeps CI and baseline
    validation runnable before the GAT dependency is installed.
    """

    return [float(snapshot.features.get(name, 0.0)) for name in feature_names]
