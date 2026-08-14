"""Train per-workload Pulse candidates from immutable one-second JSONL."""

from __future__ import annotations

import argparse
from collections import defaultdict
import json
import platform
from pathlib import Path

import numpy as np

from .model import MAX_CONTIGUOUS_GAP_SECONDS, PulseExtraTrees
from .encoding import decode_vector, schema_digest
from .integrity import sha256_file
from .validate_capture import validate


def load_dataset_manifest(dataset: Path) -> tuple[Path, dict]:
    manifest_path = dataset.with_suffix(dataset.suffix + ".manifest.json")
    if not manifest_path.is_file():
        raise ValueError(f"dataset provenance manifest is missing: {manifest_path}")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("schema") != "sentinel-pulse-dataset-manifest-v1":
        raise ValueError("unsupported dataset provenance manifest")
    if manifest.get("normal_only") is not True:
        raise ValueError("training dataset is not contractually normal-only")
    if manifest.get("dataset_sha256") != sha256_file(dataset):
        raise ValueError("training dataset hash differs from provenance manifest")
    if (
        not manifest.get("contract_sha256")
        or not manifest.get("source_sha256")
        or not manifest.get("source_manifest_sha256")
    ):
        raise ValueError("dataset provenance is incomplete")
    return manifest_path, manifest


def load_sequences(
    path: Path,
    maximum_gap_seconds: float = MAX_CONTIGUOUS_GAP_SECONDS,
) -> tuple[dict[str, list[np.ndarray]], list[str]]:
    if maximum_gap_seconds <= 0:
        raise ValueError("maximum sequence gap must be positive")
    rows = defaultdict(lambda: defaultdict(list))
    columns = None
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            record = json.loads(line)
            if record.get("schema") == "sentinel-pulse-feature-schema-v1":
                if columns is None:
                    columns = record["columns"]
                elif record["columns"] != columns:
                    raise ValueError(f"line {line_number}: feature schema drift")
                continue
            if record.get("schema") != "sentinel-pulse-feature-v1":
                raise ValueError(f"line {line_number}: unsupported schema")
            if "columns" in record:
                if columns is None:
                    columns = record["columns"]
                elif record["columns"] != columns:
                    raise ValueError(f"line {line_number}: feature schema drift")
            if columns is None:
                raise ValueError(f"line {line_number}: feature row precedes schema")
            if record.get("feature_schema_sha256") not in (None, schema_digest(columns)):
                raise ValueError(f"line {line_number}: feature schema hash mismatch")
            vector = decode_vector(record)
            source_identity = "|".join(
                (
                    str(record.get("node_name", "unknown-node")),
                    str(record.get("pod_uid", "unknown-pod")),
                    str(record.get("container_name", "unknown-container")),
                    str(record["cgroup_id"]),
                )
            )
            rows[record["workload_key"]][source_identity].append(
                (float(record["window_end"]), record.get("traffic_regime"), vector)
            )
    sequences = {}
    for workload, cgroups in rows.items():
        sequences[workload] = []
        for records in cgroups.values():
            records.sort(key=lambda value: value[0])
            current_sequence = []
            previous_end = None
            previous_regime = None
            for window_end, regime, vector in records:
                gap_boundary = (
                    previous_end is not None
                    and window_end - previous_end > maximum_gap_seconds
                )
                regime_boundary = (
                    previous_regime is not None
                    and regime is not None
                    and regime != previous_regime
                )
                if current_sequence and (gap_boundary or regime_boundary):
                    sequences[workload].append(
                        np.stack(current_sequence).astype(np.float32, copy=False)
                    )
                    current_sequence = []
                current_sequence.append(vector)
                previous_end = window_end
                previous_regime = regime
            if current_sequence:
                sequences[workload].append(
                    np.stack(current_sequence).astype(np.float32, copy=False)
                )
    return sequences, columns or []


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--history", type=int, default=3)
    parser.add_argument("--alpha", type=float, default=1e-4)
    args = parser.parse_args()
    dataset_manifest_path, dataset_manifest = load_dataset_manifest(args.dataset)
    capture_validation = validate(args.dataset, minimum_rows_per_workload=100)
    if not capture_validation["valid"]:
        first_errors = "; ".join(capture_validation["errors"][:5])
        raise ValueError(f"capture integrity validation failed: {first_errors}")
    sequences, columns = load_sequences(args.dataset)
    import sklearn
    args.output.mkdir(parents=True, exist_ok=False)
    reports = {}
    for workload, workload_sequences in sorted(sequences.items()):
        model = PulseExtraTrees(history=args.history, alpha=args.alpha)
        try:
            report = model.fit_sequences(workload_sequences)
        except ValueError as error:
            reports[workload] = {"status": "collect-only", "reason": str(error)}
            continue
        artifact_name = workload.replace("/", "__").replace(":", "__") + ".pkl"
        artifact_path = args.output / artifact_name
        model.save(artifact_path)
        reports[workload] = {
            "status": "candidate",
            "artifact": artifact_name,
            "artifact_sha256": sha256_file(artifact_path),
            "artifact_bytes": artifact_path.stat().st_size,
            "model_class": "PulseExtraTrees",
            "history_windows": model.history,
            "alpha": model.alpha,
            "feature_dim": model.feature_dim,
            **report,
        }
    manifest = {
        "schema": "sentinel-pulse-model-manifest-v2",
        "dataset": str(args.dataset),
        "dataset_sha256": sha256_file(args.dataset),
        "dataset_manifest": str(dataset_manifest_path),
        "dataset_manifest_sha256": sha256_file(dataset_manifest_path),
        "capture_contract_sha256": dataset_manifest["contract_sha256"],
        "campaign_id": dataset_manifest["campaign_id"],
        "capture_validation": {
            "schema": capture_validation["schema"],
            "valid": capture_validation["valid"],
            "rows": capture_validation["rows"],
            "workloads": capture_validation["workloads"],
            "collector_max_drops": capture_validation["collector_max_drops"],
            "interval_seconds": capture_validation["interval_seconds"],
            "ingest_lag_seconds": capture_validation["ingest_lag_seconds"],
            "snapshot_read_seconds": capture_validation["snapshot_read_seconds"],
            "capture_sha256": capture_validation["capture_sha256"],
        },
        "feature_columns": columns,
        "feature_schema_sha256": schema_digest(columns),
        "history_windows": args.history,
        "window_seconds": 1,
        "max_contiguous_gap_seconds": MAX_CONTIGUOUS_GAP_SECONDS,
        "alpha": args.alpha,
        "software": {
            "python": platform.python_version(),
            "numpy": np.__version__,
            "scikit_learn": sklearn.__version__,
        },
        "workloads": reports,
    }
    manifest_path = args.output / "manifest.json"
    with manifest_path.open("w", encoding="utf-8") as handle:
        json.dump(manifest, handle, indent=2, sort_keys=True)
        handle.write("\n")
    (args.output / "manifest.sha256").write_text(
        f"{sha256_file(manifest_path)}  manifest.json\n", encoding="ascii"
    )


if __name__ == "__main__":
    main()
