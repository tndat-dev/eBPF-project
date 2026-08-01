"""Safe persistence for reviewed GAT model releases."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
from typing import Mapping, Any
from agent_runtime.detector.gat_model import GATGraphScorer, GraphAttentionAutoencoder, _require_gat, torch


def save(path: str | Path, scorer: GATGraphScorer, *, training_snapshots: int,
         provenance: Mapping[str, Any] | None = None) -> None:
    _require_gat()
    path = Path(path)
    model = scorer.model
    torch.save({"input_dim": model.input_dim, "hidden_dim": model.hidden_dim, "latent_dim": model.latent_dim,
                "heads": model.heads, "threshold": scorer.threshold, "state_dict": model.state_dict()}, path)
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    manifest = {"format": "agent-runtime-sentinel/gat/v1", "sha256": digest,
                "training_snapshots": training_snapshots, "provenance": dict(provenance or {})}
    path.with_suffix(path.suffix + ".manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def load(path: str | Path) -> GATGraphScorer:
    _require_gat()
    path = Path(path)
    manifest = json.loads(path.with_suffix(path.suffix + ".manifest.json").read_text())
    if manifest.get("format") != "agent-runtime-sentinel/gat/v1" or manifest.get("sha256") != hashlib.sha256(path.read_bytes()).hexdigest():
        raise ValueError("GAT model manifest or digest is invalid")
    payload = torch.load(path, map_location="cpu", weights_only=True)
    model = GraphAttentionAutoencoder(payload["input_dim"], payload["hidden_dim"], payload["latent_dim"], payload["heads"])
    model.load_state_dict(payload["state_dict"])
    return GATGraphScorer(model, float(payload["threshold"]))
