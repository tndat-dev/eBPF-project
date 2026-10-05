"""Read-only latency audit of frozen diagnostic evidence; no accuracy claim."""
from __future__ import annotations

import argparse
from collections import Counter
import json
import math
from pathlib import Path

from sentinel_pulse.integrity import sha256_file


def quantiles(values: list[float]) -> dict:
    if not values:
        return {"n": 0}
    values = sorted(values)
    return {"n": len(values), **{
        f"p{int(q * 100)}": values[math.ceil(q * len(values)) - 1]
        for q in (.5, .95, .99)}, "max": values[-1]}


def audit(root: Path, startup_seconds: float = 120) -> dict:
    first_window = None
    rows = []
    with (root / "features.jsonl").open() as stream:
        for line in stream:
            row = json.loads(line)
            if row.get("schema") == "sentinel-pulse-feature-v1":
                first_window = row["window_start"]
                break
    if first_window is None:
        raise ValueError("missing feature window")
    with (root / "decisions.jsonl").open() as stream:
        for line in stream:
            row = json.loads(line)
            if row["status"] in {"normal", "suppressed", "alert"}:
                rows.append(row)
    def summarize(selected):
        return {"scored_rows": len(selected),
                "workloads": len({r["workload_key"] for r in selected}),
                "inference_ms": quantiles([r["inference_ms"] for r in selected]),
                "window_end_to_post_model_seconds": quantiles([
                    r["post_window_processing_seconds"] for r in selected]),
                "window_start_to_post_model_seconds": quantiles([
                    r["alerted_at"] - r["window_start"] for r in selected]),
                "window_end_to_post_model_over_1s": sum(
                    r["post_window_processing_seconds"] > 1 for r in selected),
                "window_start_to_post_model_over_2s": sum(
                    r["alerted_at"] - r["window_start"] > 2 for r in selected)}
    return {"schema": "sentinel-pulse-recovery-smoke-latency-audit-v1",
            "run_id": root.name,
            "source_sha256": {name: sha256_file(root / name) for name in
                              ("features.jsonl", "decisions.jsonl", "alerts.jsonl")},
            "method": "nearest-rank ceil(q*n); diagnostic partition, not acceptance retuning",
            "startup_partition_seconds": startup_seconds,
            "partition_origin_window_start": first_window,
            "all": summarize(rows),
            "startup": summarize([r for r in rows if r["window_start"] < first_window + startup_seconds]),
            "after_startup": summarize([r for r in rows if r["window_start"] >= first_window + startup_seconds]),
            "status_counts": dict(Counter(r["status"] for r in rows)),
            "timestamp_scope": "alerted_at was sampled immediately after model.predict, before policy and output; not actual alert delivery",
            "all_windows_retained_in_terminal_verdict": True,
            "kernel_to_alert_claim_allowed": False, "accuracy_claim_allowed": False,
            "operational_soak_pass": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(audit(args.run_dir), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
