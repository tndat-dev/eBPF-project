"""Aggregate checksum-verified per-node live normal canary evidence."""

from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import json
from pathlib import Path

import numpy as np

from .integrity import sha256_file


def distribution(values: list[float]) -> dict:
    if not values:
        return {
            "count": 0, "mean": None, "p50": None,
            "p95": None, "p99": None, "max": None,
        }
    data = np.asarray(values, dtype=np.float64)
    return {
        "count": len(values),
        "mean": float(np.mean(data)),
        "p50": float(np.quantile(data, 0.50)),
        "p95": float(np.quantile(data, 0.95)),
        "p99": float(np.quantile(data, 0.99)),
        "max": float(np.max(data)),
    }


def verify_checksums(root: Path) -> int:
    checksum_path = root / "CANARY_SHA256SUMS"
    if not checksum_path.is_file() or not (root / "CANARY_COMPLETE").is_file():
        raise ValueError(f"node canary is not terminal: {root}")
    verified = 0
    for line in checksum_path.read_text(encoding="ascii").splitlines():
        digest, separator, name = line.partition("  ")
        if not separator or "/" in name or name in {"", ".", ".."}:
            raise ValueError(f"unsafe canary checksum entry: {line}")
        if sha256_file(root / name) != digest:
            raise ValueError(f"canary checksum mismatch: {root / name}")
        verified += 1
    if verified == 0:
        raise ValueError("empty canary checksum manifest")
    return verified


def aggregate(
    node_roots: dict[str, Path], expected_model: str, expected_policy: str
) -> dict:
    if len(node_roots) < 1:
        raise ValueError("at least one node root is required")
    statuses: Counter[str] = Counter()
    inference_ms: list[float] = []
    post_window_seconds: list[float] = []
    start_to_decision_seconds: list[float] = []
    workloads = set()
    nodes = {}
    total_alerts = 0
    observed_durations = []
    for node, root in sorted(node_roots.items()):
        verified = verify_checksums(root)
        canary = json.loads((root / "CANARY.json").read_text(encoding="utf-8"))
        if (
            canary.get("valid") is not True
            or canary.get("accuracy_claim_allowed") is not False
            or canary.get("automatic_promotion") is not False
            or canary.get("model_manifest_sha256") != expected_model
            or canary.get("decision_policy_sha256") != expected_policy
            or int(canary.get("detector_restarts", -1)) != 0
        ):
            raise ValueError(f"node canary failed its evidence contract: {node}")
        observed_rows = 0
        scored_rows = 0
        observed_scored_node_names = set()
        with (root / "decisions.jsonl").open(encoding="utf-8") as source:
            for line in source:
                record = json.loads(line)
                observed_rows += 1
                if record.get("model_manifest_sha256") != expected_model:
                    raise ValueError(f"decision model identity mismatch: {node}")
                if record.get("decision_policy_sha256") != expected_policy:
                    raise ValueError(f"decision policy identity mismatch: {node}")
                statuses[str(record.get("status"))] += 1
                workloads.add(str(record.get("workload_key")))
                if "inference_ms" in record:
                    scored_rows += 1
                    observed_scored_node_names.add(str(record.get("node_name")))
                    inference_ms.append(float(record["inference_ms"]))
                    post_window_seconds.append(
                        float(record["post_window_processing_seconds"])
                    )
                    start_to_decision_seconds.append(
                        float(record["alerted_at"]) - float(record["window_start"])
                    )
        alerts = sum(
            1 for line in (root / "alerts.jsonl").open() if line.strip()
        )
        if observed_rows != int(canary["decisions"]):
            raise ValueError(f"node decision count mismatch: {node}")
        if scored_rows == 0 or observed_scored_node_names != {node}:
            raise ValueError(f"scored decision node identity mismatch: {node}")
        if alerts != int(canary["alerts"]):
            raise ValueError(f"node alert count mismatch: {node}")
        total_alerts += alerts
        observed_durations.append(float(canary["collector_duration_seconds"]))
        nodes[node] = {
            "canary_sha256": sha256_file(root / "CANARY.json"),
            "verified_checksum_entries": verified,
            "collector_duration_seconds": canary["collector_duration_seconds"],
            "collector_rows": canary["collector_rows"],
            "collector_workloads": canary["collector_workloads"],
            "decisions": observed_rows,
            "scored_decisions": scored_rows,
            "scored_decision_node_identity": node,
            "alerts": alerts,
            "detector_restarts": canary["detector_restarts"],
        }
    minimum_duration = min(observed_durations)
    duration_label = f"{minimum_duration / 3600.0:.2f}-hour"
    return {
        "schema": "sentinel-pulse-live-normal-canary-aggregate-v2",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "evidence_class": "nonformal_live_normal_canary",
        "accuracy_claim_allowed": False,
        "automatic_promotion": False,
        "model_manifest_sha256": expected_model,
        "decision_policy_sha256": expected_policy,
        "node_identity_binding": (
            "verified from node_name in every scored decision; legacy warming "
            "records in this canary do not embed provenance"
        ),
        "nodes": nodes,
        "node_count": len(nodes),
        "decisions": sum(item["decisions"] for item in nodes.values()),
        "alerts": total_alerts,
        "minimum_observed_duration_seconds": minimum_duration,
        "status_counts": dict(sorted(statuses.items())),
        "workloads": sorted(workloads),
        "inference_ms": distribution(inference_ms),
        "post_window_processing_seconds": distribution(post_window_seconds),
        "window_start_to_decision_seconds": distribution(start_to_decision_seconds),
        "valid": total_alerts == 0 and all(
            item["detector_restarts"] == 0 for item in nodes.values()
        ),
        "claim_boundary": (
            f"{duration_label} non-formal live normal observation only; no blind "
            "attack, independence assumption, false-positive-rate or recall claim"
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--node-root", action="append", required=True)
    parser.add_argument("--expected-model", required=True)
    parser.add_argument("--expected-policy", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    roots = {}
    for item in args.node_root:
        node, separator, path = item.partition("=")
        if not separator or not node or node in roots:
            raise ValueError(f"invalid or duplicate node root: {item}")
        roots[node] = Path(path)
    if args.output.exists():
        raise ValueError(f"refusing to overwrite aggregate: {args.output}")
    report = aggregate(roots, args.expected_model, args.expected_policy)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    if not report["valid"]:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
