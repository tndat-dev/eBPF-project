"""Score live Pulse features with immutable per-workload artifacts."""

from __future__ import annotations

import argparse
from collections import deque
import json
import platform
from pathlib import Path
import time

import numpy as np

from .model import PulseExtraTrees
from .encoding import decode_vector, schema_digest
from .integrity import contained_artifact, verify_sha256
from .latency import InjectionTracker


class PulseRuntime:
    def __init__(self, model_dir: Path):
        checksum_path = model_dir / "manifest.sha256"
        manifest_path = model_dir / "manifest.json"
        try:
            checksum_fields = checksum_path.read_text(encoding="ascii").strip().split()
        except FileNotFoundError as error:
            raise ValueError("model directory has no detached manifest checksum") from error
        if len(checksum_fields) != 2 or checksum_fields[1] != "manifest.json":
            raise ValueError("invalid detached manifest checksum")
        verify_sha256(manifest_path, checksum_fields[0])
        with manifest_path.open(encoding="utf-8") as handle:
            self.manifest = json.load(handle)
        if self.manifest.get("schema") != "sentinel-pulse-model-manifest-v2":
            raise ValueError("unsupported Pulse model manifest")
        expected_software = self.manifest.get("software")
        if expected_software is not None:
            import sklearn
            observed_software = {
                "python": platform.python_version(),
                "numpy": np.__version__,
                "scikit_learn": sklearn.__version__,
            }
            if observed_software != expected_software:
                raise ValueError(
                    f"inference software differs from training environment: "
                    f"expected={expected_software}, observed={observed_software}"
                )
        self.history_size = int(self.manifest["history_windows"])
        self.feature_schema_sha256 = self.manifest.get(
            "feature_schema_sha256", schema_digest(self.manifest["feature_columns"])
        )
        self.models = {}
        for workload, item in self.manifest["workloads"].items():
            if item.get("status") == "candidate":
                artifact = contained_artifact(model_dir, item["artifact"])
                if artifact.stat().st_size != int(item["artifact_bytes"]):
                    raise ValueError(f"artifact size mismatch for {artifact.name}")
                verify_sha256(artifact, item["artifact_sha256"])
                model = PulseExtraTrees.load(artifact)
                expected = {
                    "history": int(item["history_windows"]),
                    "alpha": float(item["alpha"]),
                    "feature_dim": int(item["feature_dim"]),
                }
                observed = {
                    "history": model.history,
                    "alpha": model.alpha,
                    "feature_dim": model.feature_dim,
                }
                if observed != expected or model.history != self.history_size:
                    raise ValueError(f"model metadata mismatch for {artifact.name}")
                self.models[workload] = model
        self.histories = {}

    def score(self, record: dict) -> dict:
        observed_schema = record.get("feature_schema_sha256")
        if observed_schema is None and "columns" in record:
            observed_schema = schema_digest(record["columns"])
        if observed_schema != self.feature_schema_sha256:
            raise ValueError("live feature schema does not match model manifest")
        workload = record["workload_key"]
        cgroup_id = str(record["cgroup_id"])
        source_identity = (
            workload,
            str(record.get("node_name", "unknown-node")),
            str(record.get("pod_uid", "unknown-pod")),
            str(record.get("container_name", "unknown-container")),
            cgroup_id,
        )
        model = self.models.get(workload)
        if model is None:
            return {"status": "collect-only", "workload_key": workload, "cgroup_id": cgroup_id}
        row = decode_vector(record)
        history = self.histories.setdefault(
            source_identity, deque(maxlen=self.history_size)
        )
        if len(history) < self.history_size:
            history.append(row)
            return {"status": "warming", "workload_key": workload, "cgroup_id": cgroup_id}
        decision = model.predict(list(history), row)
        history.append(row)
        alerted_at = time.time()
        return {
            "schema": "sentinel-pulse-decision-v1",
            "status": "alert" if decision.anomalous else "normal",
            "workload_key": workload,
            "cgroup_id": cgroup_id,
            "pod_name": record.get("pod_name"),
            "window_start": record["window_start"],
            "window_end": record["window_end"],
            "alerted_at": alerted_at,
            "post_window_processing_seconds": max(0.0, alerted_at - float(record["window_end"])),
            "score": decision.score,
            "conformal_p": decision.conformal_p,
            "inference_ms": decision.inference_ms,
        }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model-dir", type=Path, required=True)
    parser.add_argument("--features", type=Path, required=True)
    parser.add_argument("--decisions", type=Path, required=True)
    parser.add_argument("--alerts", type=Path, required=True)
    parser.add_argument("--from-start", action="store_true")
    parser.add_argument("--injections", type=Path)
    args = parser.parse_args()
    runtime = PulseRuntime(args.model_dir)
    injection_tracker = InjectionTracker(args.injections) if args.injections else None
    args.decisions.parent.mkdir(parents=True, exist_ok=True)
    args.alerts.parent.mkdir(parents=True, exist_ok=True)
    with args.features.open(encoding="utf-8") as source, \
            args.decisions.open("a", encoding="utf-8") as decisions, \
            args.alerts.open("a", encoding="utf-8") as alerts:
        if not args.from_start:
            source.seek(0, 2)
        while True:
            line = source.readline()
            if not line:
                time.sleep(0.05)
                continue
            record = json.loads(line)
            if record.get("schema") == "sentinel-pulse-feature-schema-v1":
                continue
            result = runtime.score(record)
            if result.get("status") == "alert" and injection_tracker is not None:
                marker = injection_tracker.match(result)
                if marker is not None:
                    result["injection_id"] = marker["injection_id"]
                    result["injected_at"] = marker["injected_at"]
                    result["true_detection_latency_seconds"] = max(
                        0.0, float(result["alerted_at"]) - float(marker["injected_at"])
                    )
            decisions.write(json.dumps(result, separators=(",", ":")) + "\n")
            decisions.flush()
            if result.get("status") == "alert":
                alerts.write(json.dumps(result, separators=(",", ":")) + "\n")
                alerts.flush()
