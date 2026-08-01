"""MCP JSON-RPC parser and sliding-window behavior graph.

Layer 1 eBPF must stay tiny: copy decrypted TLS buffers from SSL_read /
SSL_write into a ring buffer.  This module implements the userspace Layer 2
logic that is safe to make semantic: parse JSON-RPC 2.0, extract tool/resource
signals, and maintain a bounded behavior graph.
"""

from __future__ import annotations

from collections import Counter, deque
from dataclasses import dataclass
import hashlib
import json
import math
import time
from typing import Any, Deque, Iterable, Mapping


RESOURCE_KEYS = {
    "bucket",
    "database",
    "deployment",
    "endpoint",
    "file",
    "filename",
    "host",
    "namespace",
    "path",
    "pod",
    "resource",
    "secret",
    "service",
    "table",
    "uri",
    "url",
}

HIGH_RISK_TOOL_PATTERNS = (
    "apply",
    "bash",
    "chmod",
    "chown",
    "delete",
    "drop",
    "exec",
    "kubectl",
    "patch",
    "privileged",
    "rm",
    "secret",
    "shell",
    "ssh",
    "token",
)

HIGH_RISK_RESOURCE_PATTERNS = (
    "clusterrole",
    "credential",
    "kube-system",
    "secret",
    "serviceaccount",
    "token",
)


@dataclass(frozen=True)
class MCPEvent:
    """A semantic MCP action extracted from a JSON-RPC payload."""

    ts: float
    namespace: str
    pod: str
    agent_id: str
    jsonrpc_method: str
    tool_name: str
    request_id: str | None
    resources: tuple[str, ...]
    raw_size: int
    high_risk: bool


@dataclass(frozen=True)
class GraphNode:
    node_id: str
    kind: str
    label: str


@dataclass(frozen=True)
class GraphEdge:
    source: str
    target: str
    kind: str
    count: int


@dataclass(frozen=True)
class GraphSnapshot:
    generated_at: float
    window_seconds: float
    events: tuple[MCPEvent, ...]
    nodes: tuple[GraphNode, ...]
    edges: tuple[GraphEdge, ...]
    features: Mapping[str, float]


def parse_jsonrpc_payload(
    payload: bytes | str,
    *,
    namespace: str,
    pod: str,
    agent_id: str | None = None,
    ts: float | None = None,
) -> list[MCPEvent]:
    """Parse one MCP JSON-RPC payload into semantic events.

    Invalid JSON, responses without a method, and non-object batch entries are
    ignored.  Parameter values are never preserved verbatim except for hashed
    resource identifiers, keeping this safe for security telemetry.
    """

    raw = payload.decode("utf-8", errors="ignore") if isinstance(payload, bytes) else payload
    raw_size = len(raw.encode("utf-8", errors="ignore"))
    try:
        decoded = json.loads(raw)
    except json.JSONDecodeError:
        return []

    entries: Iterable[Any]
    if isinstance(decoded, list):
        entries = decoded
    else:
        entries = (decoded,)

    now = time.time() if ts is None else ts
    derived_agent = agent_id or f"{namespace}/{pod}"
    events: list[MCPEvent] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        method = entry.get("method")
        if not isinstance(method, str) or not method:
            continue

        params = entry.get("params")
        tool_name = _extract_tool_name(method, params)
        resources = tuple(sorted(set(_iter_resource_hashes(params))))
        request_id = entry.get("id")
        request_id_str = None if request_id is None else str(request_id)
        # The graph retains resource hashes only.  Classify from semantic
        # parameters before hashing so secret/production references are not
        # lost in the privacy-preserving storage representation.
        high_risk = _is_high_risk(tool_name, params)
        events.append(
            MCPEvent(
                ts=now,
                namespace=namespace,
                pod=pod,
                agent_id=derived_agent,
                jsonrpc_method=method,
                tool_name=tool_name,
                request_id=request_id_str,
                resources=resources,
                raw_size=raw_size,
                high_risk=high_risk,
            )
        )
    return events


class SlidingMCPGraph:
    """Bounded in-memory graph for recent MCP behavior."""

    def __init__(self, window_seconds: float = 300.0, max_events: int = 50_000) -> None:
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        if max_events <= 0:
            raise ValueError("max_events must be positive")
        self.window_seconds = float(window_seconds)
        self.max_events = int(max_events)
        self._events: Deque[MCPEvent] = deque()
        self._edge_counts: Counter[tuple[str, str, str]] = Counter()
        self._tool_counts: Counter[str] = Counter()
        self._resource_counts: Counter[str] = Counter()
        self._agent_counts: Counter[str] = Counter()
        self._pod_counts: Counter[tuple[str, str]] = Counter()
        self._raw_bytes = 0
        self._high_risk_events = 0

    def add_event(self, event: MCPEvent) -> None:
        self._events.append(event)
        self._index_event(event, 1)
        self.expire(now=event.ts)
        self._trim_to_capacity()

    def add_events(self, events: Iterable[MCPEvent]) -> None:
        last_ts: float | None = None
        for event in events:
            self._events.append(event)
            self._index_event(event, 1)
            last_ts = event.ts
        self.expire(now=last_ts or time.time())
        self._trim_to_capacity()

    def expire(self, *, now: float | None = None) -> None:
        cutoff = (time.time() if now is None else now) - self.window_seconds
        while self._events and self._events[0].ts < cutoff:
            self._index_event(self._events.popleft(), -1)

    def _trim_to_capacity(self) -> None:
        """Keep memory bounded if event rate exceeds the time-window budget."""

        while len(self._events) > self.max_events:
            self._index_event(self._events.popleft(), -1)

    def _index_event(self, event: MCPEvent, delta: int) -> None:
        """Maintain bounded-window graph aggregates incrementally."""

        agent_id = f"agent:{event.agent_id}"
        pod_id = f"pod:{event.namespace}/{event.pod}"
        tool_id = f"tool:{event.tool_name}"
        self._adjust(self._agent_counts, event.agent_id, delta)
        self._adjust(self._pod_counts, (event.namespace, event.pod), delta)
        self._adjust(self._tool_counts, event.tool_name, delta)
        self._adjust(self._edge_counts, (pod_id, agent_id, "hosts"), delta)
        self._adjust(self._edge_counts, (agent_id, tool_id, "calls"), delta)
        for resource_hash in event.resources:
            resource_id = f"resource:{resource_hash}"
            self._adjust(self._resource_counts, resource_hash, delta)
            self._adjust(self._edge_counts, (tool_id, resource_id, "touches"), delta)
        self._raw_bytes += delta * event.raw_size
        self._high_risk_events += delta * int(event.high_risk)

    @staticmethod
    def _adjust(counter: Counter[Any], key: Any, delta: int) -> None:
        next_value = counter.get(key, 0) + delta
        if next_value > 0:
            counter[key] = next_value
        else:
            counter.pop(key, None)

    def snapshot(self, *, now: float | None = None) -> GraphSnapshot:
        current = time.time() if now is None else now
        self.expire(now=current)
        events = tuple(self._events)

        nodes: dict[str, GraphNode] = {}
        for agent in self._agent_counts:
            node_id = f"agent:{agent}"
            nodes[node_id] = GraphNode(node_id, "agent", agent)
        for namespace, pod in self._pod_counts:
            node_id = f"pod:{namespace}/{pod}"
            nodes[node_id] = GraphNode(node_id, "pod", f"{namespace}/{pod}")
        for tool_name in self._tool_counts:
            node_id = f"tool:{tool_name}"
            nodes[node_id] = GraphNode(node_id, "tool", tool_name)
        for resource_hash in self._resource_counts:
            node_id = f"resource:{resource_hash}"
            nodes[node_id] = GraphNode(node_id, "resource", resource_hash)

        graph_edges = tuple(
            GraphEdge(source=src, target=dst, kind=kind, count=count)
            for (src, dst, kind), count in sorted(self._edge_counts.items())
        )
        features = _build_features(
            events,
            self._agent_counts,
            self._tool_counts,
            self._resource_counts,
            self._raw_bytes,
            self._high_risk_events,
            current,
            self.window_seconds,
        )
        return GraphSnapshot(
            generated_at=current,
            window_seconds=self.window_seconds,
            events=events,
            nodes=tuple(sorted(nodes.values(), key=lambda n: n.node_id)),
            edges=graph_edges,
            features=features,
        )


def _extract_tool_name(method: str, params: Any) -> str:
    if method in {"tools/call", "tool/call"} and isinstance(params, dict):
        name = params.get("name") or params.get("tool") or params.get("tool_name")
        if isinstance(name, str) and name:
            return name
    return method


def _iter_resource_hashes(value: Any) -> Iterable[str]:
    if isinstance(value, dict):
        for key, nested in value.items():
            lowered = str(key).lower()
            if lowered in RESOURCE_KEYS:
                yield from _hash_resource_values(nested)
            yield from _iter_resource_hashes(nested)
    elif isinstance(value, list):
        for item in value:
            yield from _iter_resource_hashes(item)


def _hash_resource_values(value: Any) -> Iterable[str]:
    if isinstance(value, (str, int, float, bool)):
        yield _stable_hash(str(value))
    elif isinstance(value, list):
        for item in value:
            yield from _hash_resource_values(item)
    elif isinstance(value, dict):
        for item in value.values():
            yield from _hash_resource_values(item)


def _stable_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="ignore")).hexdigest()[:16]


def _is_high_risk(tool_name: str, params: Any) -> bool:
    lowered_tool = tool_name.lower()
    if any(pattern in lowered_tool for pattern in HIGH_RISK_TOOL_PATTERNS):
        return True
    return _contains_high_risk_resource(params)


def _contains_high_risk_resource(value: Any) -> bool:
    """Check resource values without retaining them in graph telemetry."""

    if isinstance(value, dict):
        for key, nested in value.items():
            if str(key).lower() in RESOURCE_KEYS and _contains_risk_pattern(nested):
                return True
            if _contains_high_risk_resource(nested):
                return True
    elif isinstance(value, list):
        return any(_contains_high_risk_resource(item) for item in value)
    return False


def _contains_risk_pattern(value: Any) -> bool:
    if isinstance(value, (str, int, float, bool)):
        lowered = str(value).lower()
        return any(pattern in lowered for pattern in HIGH_RISK_RESOURCE_PATTERNS)
    if isinstance(value, dict):
        return any(_contains_risk_pattern(item) for item in value.values())
    if isinstance(value, list):
        return any(_contains_risk_pattern(item) for item in value)
    return False


def _build_features(
    events: tuple[MCPEvent, ...],
    agent_counts: Counter[str],
    tool_counts: Counter[str],
    resource_counts: Counter[str],
    raw_bytes: int,
    high_risk_events: int,
    now: float,
    window_seconds: float,
) -> dict[str, float]:
    if events:
        first_ts = min(event.ts for event in events)
        observed_span = max(1.0, now - first_ts)
    else:
        observed_span = window_seconds

    return {
        "events_total": float(len(events)),
        "event_rate_per_second": float(len(events)) / observed_span,
        "unique_agents": float(len(agent_counts)),
        "unique_tools": float(len(tool_counts)),
        "unique_resources": float(len(resource_counts)),
        "high_risk_events": float(high_risk_events),
        "high_risk_ratio": float(high_risk_events) / max(1.0, float(len(events))),
        "max_tool_calls": float(max(tool_counts.values(), default=0)),
        "max_resource_touches": float(max(resource_counts.values(), default=0)),
        "tool_entropy": _entropy(tool_counts),
        "raw_kib": float(raw_bytes) / 1024.0,
    }


def _entropy(counter: Counter[str]) -> float:
    total = sum(counter.values())
    if total <= 0:
        return 0.0
    entropy = 0.0
    for count in counter.values():
        p = count / total
        entropy -= p * math.log2(p)
    return float(entropy)
