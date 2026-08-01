"""Optional PyTorch-Geometric GAT autoencoder for MCP behavior graphs.

The online robust detector remains the safe default until this model is trained
on reviewed normal captures.  This module deliberately imports PyG lazily so
the lightweight collector and parser do not require a GPU/ML environment.
"""

from __future__ import annotations

from dataclasses import dataclass
import math
from typing import Iterable

from agent_runtime.detector.evt_pot import quantile
from agent_runtime.mcp.graph import GraphSnapshot


try:  # Optional on developer machines; required only for GAT train/inference.
    import torch
    from torch import nn
    from torch_geometric.data import Data
    from torch_geometric.nn import GATConv
except ImportError:  # pragma: no cover - exercised by import-only local CI.
    torch = None
    nn = None
    Data = None
    GATConv = None


NODE_KINDS = ("agent", "pod", "tool", "resource")


def available() -> bool:
    return torch is not None and GATConv is not None


def graph_to_data(snapshot: GraphSnapshot):
    """Encode topology, node type and global behavior statistics for GAT."""

    _require_gat()
    nodes = list(snapshot.nodes)
    if not nodes:
        # GAT needs at least one node. Empty windows should be handled by the
        # stream gate instead of being sent to this ML model.
        raise ValueError("cannot create GAT data for an empty graph")
    index = {node.node_id: position for position, node in enumerate(nodes)}
    in_degree = [0.0] * len(nodes)
    out_degree = [0.0] * len(nodes)
    sources: list[int] = []
    targets: list[int] = []
    for edge in snapshot.edges:
        source, target = index[edge.source], index[edge.target]
        # Bidirectional message passing captures tool/resource context.
        sources.extend((source, target))
        targets.extend((target, source))
        out_degree[source] += edge.count
        in_degree[target] += edge.count
        out_degree[target] += edge.count
        in_degree[source] += edge.count
    if not sources:
        sources, targets = [0], [0]

    global_features = (
        float(snapshot.features.get("event_rate_per_second", 0.0)),
        float(snapshot.features.get("unique_tools", 0.0)),
        float(snapshot.features.get("unique_resources", 0.0)),
        float(snapshot.features.get("high_risk_ratio", 0.0)),
        float(snapshot.features.get("tool_entropy", 0.0)),
    )
    rows = []
    for position, node in enumerate(nodes):
        kind = [1.0 if node.kind == candidate else 0.0 for candidate in NODE_KINDS]
        rows.append(kind + [math.log1p(in_degree[position]), math.log1p(out_degree[position])] + list(global_features))
    return Data(
        x=torch.tensor(rows, dtype=torch.float32),
        edge_index=torch.tensor([sources, targets], dtype=torch.long),
    )


class GraphAttentionAutoencoder(nn.Module if nn is not None else object):
    """Small GAT that reconstructs graph node features from neighbor context."""

    def __init__(self, input_dim: int, hidden_dim: int = 16, latent_dim: int = 8, heads: int = 2) -> None:
        _require_gat()
        super().__init__()
        self.input_dim, self.hidden_dim, self.latent_dim, self.heads = input_dim, hidden_dim, latent_dim, heads
        self.conv1 = GATConv(input_dim, hidden_dim, heads=heads, concat=True, dropout=0.0)
        self.conv2 = GATConv(hidden_dim * heads, latent_dim, heads=1, concat=False, dropout=0.0)
        self.decoder = nn.Sequential(nn.Linear(latent_dim, hidden_dim), nn.ReLU(), nn.Linear(hidden_dim, input_dim))

    def forward(self, data):
        hidden = torch.relu(self.conv1(data.x, data.edge_index))
        latent = torch.relu(self.conv2(hidden, data.edge_index))
        return self.decoder(latent), latent


@dataclass
class GATGraphScorer:
    """Train-on-clean GAT reconstruction scorer with a conservative tail limit."""

    model: GraphAttentionAutoencoder
    threshold: float

    @classmethod
    def fit(
        cls,
        snapshots: Iterable[GraphSnapshot],
        *,
        epochs: int = 120,
        learning_rate: float = 0.01,
        threshold_quantile: float = 0.99,
        margin: float = 0.02,
        seed: int = 7,
    ) -> "GATGraphScorer":
        _require_gat()
        data = [graph_to_data(snapshot) for snapshot in snapshots if snapshot.nodes]
        if len(data) < 3:
            raise ValueError("at least three non-empty clean graph snapshots are required")
        torch.manual_seed(seed)
        model = GraphAttentionAutoencoder(data[0].x.size(1))
        optimizer = torch.optim.Adam(model.parameters(), lr=learning_rate)
        model.train()
        for _ in range(epochs):
            for item in data:
                optimizer.zero_grad()
                reconstructed, _ = model(item)
                loss = torch.mean((reconstructed - item.x) ** 2)
                loss.backward()
                optimizer.step()
        model.eval()
        with torch.no_grad():
            scores = [float(torch.mean((model(item)[0] - item.x) ** 2).item()) for item in data]
        return cls(model=model, threshold=max(1e-6, quantile(scores, threshold_quantile) + margin))

    def score(self, snapshot: GraphSnapshot) -> tuple[float, dict[str, float]]:
        _require_gat()
        item = graph_to_data(snapshot)
        started = torch.cuda.Event(enable_timing=True) if torch.cuda.is_available() else None
        # CPU timing is deliberately left to the caller; CUDA event is not
        # needed for the score and would synchronize a realtime hot path.
        del started
        self.model.eval()
        with torch.no_grad():
            reconstructed, _ = self.model(item)
            per_node = torch.mean((reconstructed - item.x) ** 2, dim=1)
        score = float(torch.mean(per_node).item())
        explanation = {snapshot.nodes[index].node_id: float(value) for index, value in enumerate(per_node.tolist())}
        return score, explanation

    def is_anomalous(self, snapshot: GraphSnapshot) -> bool:
        return self.score(snapshot)[0] >= self.threshold


def _require_gat() -> None:
    if not available():
        raise RuntimeError("GAT requires torch and torch-geometric; install the optional agent-runtime ML dependencies")
