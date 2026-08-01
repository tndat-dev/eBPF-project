"""Safe background GAT candidate trainer; never promotes a model."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
from agent_runtime.detector.gat_store import save
from agent_runtime.detector.gat_model import GATGraphScorer
from agent_runtime.eval.snapshot_dataset import build_snapshots, dataset_digest, load_records, rejected_review_count


def diversity(records: list[dict]) -> dict:
    agents = set()
    workloads = set()
    timestamps = []
    for record in records:
        timestamps.append(float(record["generated_at"]))
        for event in record.get("events", []):
            agents.add(event["agent_id"])
            workloads.add((event["namespace"], event["pod"]))
    return {"unique_agents": len(agents), "unique_workloads": len(workloads),
            "span_seconds": max(timestamps) - min(timestamps) if timestamps else 0.0}


def holdout_gate(scores: list[float], threshold: float, max_alert_rate: float) -> dict:
    alerts = sum(score >= threshold for score in scores)
    rate = alerts / len(scores) if scores else 1.0
    return {"holdout_alerts": alerts, "holdout_alert_rate": rate,
            "holdout_max_score": max(scores) if scores else None,
            "holdout_passed": rate <= max_alert_rate}


def run(input_path: Path, candidate_dir: Path, state_path: Path, *, min_snapshots: int, epochs: int,
        min_agents: int = 3, min_workloads: int = 3, min_span_seconds: float = 86_400,
        max_holdout_alert_rate: float = 0.0) -> dict:
    if not 0.0 <= max_holdout_alert_rate <= 1.0:
        raise ValueError("max_holdout_alert_rate must be between 0 and 1")
    if not input_path.exists():
        return {"status": "waiting_for_dataset", "snapshots": 0, "required": min_snapshots}
    # The collector emits sanitized, reviewed normal snapshots.  Guard that
    # invariant here too: a timer must never turn attack/unreviewed data into
    # baseline training merely because it appeared in the input file.
    raw_records = load_records(input_path)
    rejected = rejected_review_count(raw_records)
    if rejected:
        return {"status": "waiting_for_reviewed_clean_data", "snapshots": len(raw_records),
                "rejected": rejected, "required": min_snapshots}
    if len(raw_records) < min_snapshots:
        return {"status": "waiting_for_clean_data", "snapshots": len(raw_records), "required": min_snapshots}
    observed = diversity(raw_records)
    if (observed["unique_agents"] < min_agents or observed["unique_workloads"] < min_workloads
            or observed["span_seconds"] < min_span_seconds):
        return {"status": "waiting_for_diverse_data", "snapshots": len(raw_records),
                **observed, "required_agents": min_agents, "required_workloads": min_workloads,
                "required_span_seconds": min_span_seconds}
    graph_snapshots = build_snapshots(raw_records, require_approved=True)
    source_digest = dataset_digest(input_path)
    previous = json.loads(state_path.read_text()) if state_path.exists() else {}
    if previous.get("source_sha256") == source_digest:
        return {"status": "unchanged", "snapshots": len(graph_snapshots)}
    split = max(3, int(len(graph_snapshots) * 0.8))
    if len(graph_snapshots) - split < 3:
        return {"status": "waiting_for_holdout", "snapshots": len(graph_snapshots), "required": min_snapshots}
    scorer = GATGraphScorer.fit(graph_snapshots[:split], epochs=epochs)
    holdout = [scorer.score(snapshot)[0] for snapshot in graph_snapshots[split:]]
    candidate_dir.mkdir(parents=True, exist_ok=True)
    state_path.parent.mkdir(parents=True, exist_ok=True)
    holdout_result = holdout_gate(holdout, scorer.threshold, max_holdout_alert_rate)
    if not holdout_result["holdout_passed"]:
        state = {"status": "candidate_rejected_holdout", "source_sha256": source_digest,
                 "snapshots": len(graph_snapshots), "train_snapshots": split,
                 "holdout_snapshots": len(holdout), "threshold": scorer.threshold,
                 "max_holdout_alert_rate": max_holdout_alert_rate, **holdout_result}
        state_path.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n")
        return state
    output = candidate_dir / f"gat-{source_digest[:12]}.pt"
    save(output, scorer, training_snapshots=split, provenance={
        "dataset_sha256": source_digest,
        "epochs": epochs,
        "min_snapshots": min_snapshots,
        "min_agents": min_agents,
        "min_workloads": min_workloads,
        "min_span_seconds": min_span_seconds,
        "max_holdout_alert_rate": max_holdout_alert_rate,
        **observed,
        **holdout_result,
    })
    state = {"status": "candidate_ready", "source_sha256": source_digest, "snapshots": len(graph_snapshots),
             "train_snapshots": split, "holdout_snapshots": len(holdout), "threshold": scorer.threshold,
             "max_holdout_alert_rate": max_holdout_alert_rate, **holdout_result,
             "candidate": str(output)}
    state_path.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n")
    return state


def main() -> int:
    parser = argparse.ArgumentParser(description="Background safe GAT candidate trainer")
    parser.add_argument("--input", required=True)
    parser.add_argument("--candidate-dir", required=True)
    parser.add_argument("--state", required=True)
    parser.add_argument("--min-snapshots", type=int, default=200)
    parser.add_argument("--epochs", type=int, default=120)
    parser.add_argument("--min-agents", type=int, default=3)
    parser.add_argument("--min-workloads", type=int, default=3)
    parser.add_argument("--min-span-seconds", type=float, default=86_400)
    parser.add_argument("--max-holdout-alert-rate", type=float, default=0.0)
    args = parser.parse_args()
    result = run(Path(args.input), Path(args.candidate_dir), Path(args.state), min_snapshots=args.min_snapshots,
                 epochs=args.epochs, min_agents=args.min_agents, min_workloads=args.min_workloads,
                 min_span_seconds=args.min_span_seconds, max_holdout_alert_rate=args.max_holdout_alert_rate)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
