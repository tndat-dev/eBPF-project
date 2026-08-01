"""Train and persist a GAT release from reviewed, sanitized graph snapshots."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
from agent_runtime.detector.gat_model import GATGraphScorer
from agent_runtime.detector.gat_store import save
from agent_runtime.eval.snapshot_dataset import build_snapshots, dataset_digest, load_records


def load_snapshots(path: str | Path, *, require_approved: bool = True):
    return build_snapshots(load_records(path), require_approved=require_approved)


def main() -> int:
    parser = argparse.ArgumentParser(description="Train GAT only from reviewed sanitized graph snapshots")
    parser.add_argument("--input", required=True, help="JSONL snapshots containing no raw MCP payload")
    parser.add_argument("--output", required=True)
    parser.add_argument("--epochs", type=int, default=120)
    args = parser.parse_args()
    snapshots = load_snapshots(args.input)
    scorer = GATGraphScorer.fit(snapshots, epochs=args.epochs)
    save(args.output, scorer, training_snapshots=len(snapshots), provenance={
        "dataset_sha256": dataset_digest(args.input),
        "review_required": True,
        "epochs": args.epochs,
    })
    print(json.dumps({"training_snapshots": len(snapshots), "threshold": scorer.threshold, "output": args.output}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
