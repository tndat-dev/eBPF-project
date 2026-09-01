"""Score live Pulse features with immutable per-workload artifacts."""

from __future__ import annotations

import argparse
from collections import deque
import json
import os
import platform
from pathlib import Path
import time

import numpy as np

from .model import PulseExtraTrees
from .decision_policy import corroboration_details, load_decision_policy
from .encoding import decode_vector, schema_digest
from .integrity import contained_artifact, verify_sha256
from .latency import InjectionTracker


class RotatingJsonlFollower:
    """Follow an append-only JSONL path across atomic rotation/truncation."""

    def __init__(self, path: Path, from_start: bool = False, poll_seconds: float = 0.05):
        if poll_seconds < 0:
            raise ValueError("tail poll interval cannot be negative")
        self.path = path
        self.from_start = from_start
        self.poll_seconds = poll_seconds
        self.source = None
        self.identity = None
        self._initial_open = True

    def _open(self) -> bool:
        try:
            source = self.path.open(encoding="utf-8")
        except FileNotFoundError:
            return False
        if self._initial_open and not self.from_start:
            source.seek(0, os.SEEK_END)
        descriptor = os.fstat(source.fileno())
        self.source = source
        self.identity = (descriptor.st_dev, descriptor.st_ino)
        self._initial_open = False
        return True

    def _path_replaced_or_truncated(self) -> bool:
        if self.source is None:
            return False
        try:
            current = self.path.stat()
        except FileNotFoundError:
            return False
        except PermissionError:
            # A finite collector can restore root ownership while shutting
            # down after this process has already opened the stream. At EOF,
            # keep the valid descriptor and wait for an explicit detector stop
            # instead of entering a systemd restart storm on a path stat.
            return False
        return (
            (current.st_dev, current.st_ino) != self.identity
            or current.st_size < self.source.tell()
        )

    def readline(self) -> str:
        while True:
            if self.source is None:
                if not self._open():
                    time.sleep(self.poll_seconds)
                    continue
            line_start = self.source.tell()
            line = self.source.readline()
            if line.endswith("\n"):
                return line
            if line:
                # A reader can observe an append-only file between the writer's
                # data write and terminating newline.  Rewind and wait instead
                # of handing a torn JSON object to the decoder.  If rotation
                # replaced the file while a fragment was pending, discard only
                # that unterminated fragment and reopen the new inode.
                if self._path_replaced_or_truncated():
                    self.source.close()
                    self.source = None
                    self.identity = None
                    continue
                self.source.seek(line_start)
            if self._path_replaced_or_truncated():
                self.source.close()
                self.source = None
                self.identity = None
                continue
            time.sleep(self.poll_seconds)

    def close(self) -> None:
        if self.source is not None:
            self.source.close()
            self.source = None
            self.identity = None


class PulseRuntime:
    def __init__(self, model_dir: Path, decision_policy: Path | None = None):
        checksum_path = model_dir / "manifest.sha256"
        manifest_path = model_dir / "manifest.json"
        try:
            checksum_fields = checksum_path.read_text(encoding="ascii").strip().split()
        except FileNotFoundError as error:
            raise ValueError("model directory has no detached manifest checksum") from error
        if len(checksum_fields) != 2 or checksum_fields[1] != "manifest.json":
            raise ValueError("invalid detached manifest checksum")
        verify_sha256(manifest_path, checksum_fields[0])
        self.model_manifest_sha256 = checksum_fields[0]
        with manifest_path.open(encoding="utf-8") as handle:
            self.manifest = json.load(handle)
        if self.manifest.get("schema") != "sentinel-pulse-model-manifest-v2":
            raise ValueError("unsupported Pulse model manifest")
        expected_software = self.manifest.get("software")
        if expected_software is not None:
            import joblib
            import narwhals
            import scipy
            import sklearn
            import threadpoolctl
            observed_software = {
                "python": platform.python_version(),
                "numpy": np.__version__,
                "scikit_learn": sklearn.__version__,
                "scipy": scipy.__version__,
                "joblib": joblib.__version__,
                "threadpoolctl": threadpoolctl.__version__,
                "narwhals": narwhals.__version__,
            }
            if observed_software != expected_software:
                raise ValueError(
                    f"inference software differs from training environment: "
                    f"expected={expected_software}, observed={observed_software}"
                )
        self.history_size = int(self.manifest["history_windows"])
        self.max_contiguous_gap_seconds = float(
            self.manifest.get("max_contiguous_gap_seconds", 0.0)
        )
        if (
            not np.isfinite(self.max_contiguous_gap_seconds)
            or self.max_contiguous_gap_seconds <= 0.0
        ):
            raise ValueError("invalid temporal gap contract in model manifest")
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
        self.history_metadata = {}
        self.temporal_evidence = {}
        self.confirmation_evidence = {}
        self.decision_policy = None
        self.decision_policy_sha256 = None
        if decision_policy is not None:
            self.decision_policy, self.decision_policy_sha256 = load_decision_policy(
                decision_policy
            )

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
            return {
                "schema": "sentinel-pulse-decision-v1",
                "status": "collect-only",
                "model_manifest_sha256": self.model_manifest_sha256,
                "decision_policy_sha256": self.decision_policy_sha256,
                "workload_key": workload,
                "cgroup_id": cgroup_id,
                "pod_name": record.get("pod_name"),
                "pod_uid": record.get("pod_uid"),
                "node_name": record.get("node_name"),
                "container_name": record.get("container_name"),
                "window_start": record.get("window_start"),
                "window_end": record.get("window_end"),
            }
        row = decode_vector(record)
        history = self.histories.setdefault(
            source_identity, deque(maxlen=self.history_size)
        )
        window_end = float(record["window_end"])
        regime = record.get("traffic_regime")
        reset_reason = None
        previous = self.history_metadata.get(source_identity)
        if previous is not None:
            previous_end, previous_regime = previous
            if window_end <= previous_end:
                raise ValueError(
                    f"non-monotonic live feature window for {workload}: "
                    f"previous={previous_end}, current={window_end}"
                )
            if window_end - previous_end > self.max_contiguous_gap_seconds:
                history.clear()
                self.temporal_evidence.pop(source_identity, None)
                self.confirmation_evidence.pop(source_identity, None)
                reset_reason = "temporal_gap"
            elif (
                previous_regime is not None
                and regime is not None
                and regime != previous_regime
            ):
                history.clear()
                self.temporal_evidence.pop(source_identity, None)
                self.confirmation_evidence.pop(source_identity, None)
                reset_reason = "traffic_regime_change"
        self.history_metadata[source_identity] = (window_end, regime)
        if len(history) < self.history_size:
            history.append(row)
            return {
                "schema": "sentinel-pulse-decision-v1",
                "status": "warming",
                "warming_reason": reset_reason or "history_fill",
                "model_manifest_sha256": self.model_manifest_sha256,
                "decision_policy_sha256": self.decision_policy_sha256,
                "workload_key": workload,
                "cgroup_id": cgroup_id,
                "pod_name": record.get("pod_name"),
                "pod_uid": record.get("pod_uid"),
                "node_name": record.get("node_name"),
                "container_name": record.get("container_name"),
                "window_start": record.get("window_start"),
                "window_end": record.get("window_end"),
            }
        decision = model.predict(list(history), row)
        history.append(row)
        alerted_at = time.time()
        corroborated = True
        security_mass = None
        security_fields = None
        if self.decision_policy is not None:
            semantic = corroboration_details(
                self.decision_policy, record.get("exact_counts"), workload
            )
            semantic_corroborated = semantic["confirmed"]
            security_mass = semantic["mass"]
            security_fields = semantic["observed_fields"]
            semantic_signal_groups = semantic["signal_groups"]
            score_gate = self.decision_policy.get("score_corroboration", {})
            minimum_score_excess = float(
                score_gate.get("minimum_excess_over_calibration_max", 0.0)
            )
            calibration_max = float(model.calibration_scores[-1])
            score_excess = decision.score - calibration_max
            score_corroborated = score_excess >= minimum_score_excess
            same_window_corroborated = semantic_corroborated and score_corroborated
        else:
            semantic_corroborated = True
            score_corroborated = True
            calibration_max = None
            score_excess = None
            minimum_score_excess = None
            semantic_signal_groups = {}
            same_window_corroborated = True

        temporal = (
            self.decision_policy.get("bounded_event_time_corroboration")
            if self.decision_policy is not None
            else None
        )
        triggered_groups = sorted(
            name for name, details in semantic_signal_groups.items()
            if details.get("triggered") is True
        )
        confirmation = (
            self.decision_policy.get("temporal_confirmation")
            if self.decision_policy is not None
            else None
        )
        instant_candidate = bool(decision.anomalous and same_window_corroborated)
        confirmation_corroborated = instant_candidate
        confirmation_count = 1 if instant_candidate else 0
        confirmation_groups = triggered_groups
        confirmation_bypassed = False
        if confirmation is not None:
            bypass_groups = set(confirmation["immediate_bypass_signal_groups"])
            required_windows = int(confirmation["required_consecutive_windows"])
            maximum_confirmation_gap = float(confirmation["maximum_gap_seconds"])
            confirmation_corroborated = False
            if instant_candidate and set(triggered_groups) & bypass_groups:
                confirmation_bypassed = True
                confirmation_corroborated = True
                self.confirmation_evidence.pop(source_identity, None)
            elif instant_candidate and triggered_groups:
                previous_confirmation = self.confirmation_evidence.get(source_identity)
                if (
                    previous_confirmation is not None
                    and 0.0 < window_end - float(previous_confirmation["window_end"])
                    <= maximum_confirmation_gap
                    and set(triggered_groups) & set(previous_confirmation["groups"])
                ):
                    confirmation_count = int(previous_confirmation["count"]) + 1
                else:
                    confirmation_count = 1
                self.confirmation_evidence[source_identity] = {
                    "window_end": window_end,
                    "groups": triggered_groups,
                    "count": confirmation_count,
                }
                confirmation_corroborated = confirmation_count >= required_windows
                if (
                    confirmation_corroborated
                    and confirmation.get("consume_on_alert") is True
                ):
                    self.confirmation_evidence.pop(source_identity, None)
            else:
                confirmation_count = 0
                self.confirmation_evidence.pop(source_identity, None)
        temporal_corroborated = False
        model_evidence_window_end = None
        semantic_evidence_window_end = None
        evidence_span_seconds = None
        model_evidence_score = None
        model_evidence_conformal_p = None
        semantic_evidence_security_activity_mass = None
        semantic_evidence_security_activity_fields = None
        semantic_evidence_signal_groups = None
        semantic_evidence_triggered_groups = None
        eligible_temporal_semantic_groups = None
        if temporal is not None:
            maximum_age = float(temporal["maximum_evidence_age_seconds"])
            configured_eligible = temporal.get("eligible_semantic_signal_groups")
            eligible_temporal_semantic_groups = (
                sorted(configured_eligible)
                if configured_eligible is not None
                else sorted(semantic_signal_groups)
            )
            temporal_semantic_corroborated = bool(
                semantic_corroborated
                and (
                    configured_eligible is None
                    or set(triggered_groups) & set(configured_eligible)
                )
            )
            evidence = self.temporal_evidence.setdefault(source_identity, {})
            for name in ("model", "semantic"):
                item = evidence.get(name)
                if item is not None and window_end - float(item["window_end"]) > maximum_age:
                    evidence.pop(name, None)
            if decision.anomalous and score_corroborated:
                evidence["model"] = {
                    "window_end": window_end,
                    "score": decision.score,
                    "conformal_p": decision.conformal_p,
                }
            if temporal_semantic_corroborated:
                evidence["semantic"] = {
                    "window_end": window_end,
                    "security_activity_mass": security_mass,
                    "security_activity_fields": security_fields,
                    "semantic_signal_groups": semantic_signal_groups,
                    "triggered_groups": triggered_groups,
                }
            model_evidence = evidence.get("model")
            semantic_evidence = evidence.get("semantic")
            if model_evidence is not None:
                model_evidence_window_end = float(model_evidence["window_end"])
                model_evidence_score = float(model_evidence["score"])
                model_evidence_conformal_p = float(model_evidence["conformal_p"])
            if semantic_evidence is not None:
                semantic_evidence_window_end = float(semantic_evidence["window_end"])
                semantic_evidence_security_activity_mass = int(
                    semantic_evidence["security_activity_mass"]
                )
                semantic_evidence_security_activity_fields = dict(
                    semantic_evidence["security_activity_fields"]
                )
                semantic_evidence_signal_groups = dict(
                    semantic_evidence["semantic_signal_groups"]
                )
                semantic_evidence_triggered_groups = list(
                    semantic_evidence["triggered_groups"]
                )
            if model_evidence is not None and semantic_evidence is not None:
                evidence_span_seconds = abs(
                    model_evidence_window_end - semantic_evidence_window_end
                )
                temporal_corroborated = evidence_span_seconds <= maximum_age
            alerted = bool(confirmation_corroborated or temporal_corroborated)
            if alerted and temporal.get("consume_on_alert") is True:
                self.temporal_evidence.pop(source_identity, None)
        else:
            maximum_age = None
            alerted = confirmation_corroborated
        status = (
            "alert"
            if alerted
            else "suppressed"
            if decision.anomalous
            else "normal"
        )
        return {
            "schema": "sentinel-pulse-decision-v1",
            "status": status,
            "model_manifest_sha256": self.model_manifest_sha256,
            "decision_policy_sha256": self.decision_policy_sha256,
            "workload_key": workload,
            "cgroup_id": cgroup_id,
            "pod_name": record.get("pod_name"),
            "pod_uid": record.get("pod_uid"),
            "node_name": record.get("node_name"),
            "container_name": record.get("container_name"),
            "window_start": record["window_start"],
            "window_end": window_end,
            "alerted_at": alerted_at,
            "post_window_processing_seconds": max(0.0, alerted_at - float(record["window_end"])),
            "score": decision.score,
            "conformal_p": decision.conformal_p,
            "raw_model_anomalous": decision.anomalous,
            "same_window_corroborated": same_window_corroborated,
            "temporal_confirmation_corroborated": confirmation_corroborated,
            "temporal_confirmation_count": confirmation_count,
            "temporal_confirmation_groups": confirmation_groups,
            "temporal_confirmation_bypassed": confirmation_bypassed,
            "temporal_confirmation_required_consecutive_windows": (
                int(confirmation["required_consecutive_windows"])
                if confirmation is not None else 1
            ),
            "corroboration_mode": (
                "bounded_model_semantic_join" if temporal is not None else "same_window"
            ),
            "bounded_event_time_corroborated": temporal_corroborated,
            "maximum_evidence_age_seconds": maximum_age,
            "model_evidence_window_end": model_evidence_window_end,
            "semantic_evidence_window_end": semantic_evidence_window_end,
            "evidence_span_seconds": evidence_span_seconds,
            "model_evidence_score": model_evidence_score,
            "model_evidence_conformal_p": model_evidence_conformal_p,
            "semantic_evidence_security_activity_mass": (
                semantic_evidence_security_activity_mass
            ),
            "semantic_evidence_security_activity_fields": (
                semantic_evidence_security_activity_fields
            ),
            "semantic_evidence_signal_groups": semantic_evidence_signal_groups,
            "semantic_evidence_triggered_groups": semantic_evidence_triggered_groups,
            "eligible_temporal_semantic_groups": eligible_temporal_semantic_groups,
            "semantic_corroborated": semantic_corroborated,
            "score_corroborated": score_corroborated,
            "calibration_score_max": calibration_max,
            "score_excess_over_calibration_max": score_excess,
            "minimum_score_excess": minimum_score_excess,
            "security_activity_mass": security_mass,
            "security_activity_fields": security_fields,
            "semantic_signal_groups": semantic_signal_groups,
            "inference_ms": decision.inference_ms,
        }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model-dir", type=Path, required=True)
    parser.add_argument("--decision-policy", type=Path)
    parser.add_argument("--run-id", default="manual")
    parser.add_argument("--features", type=Path, required=True)
    parser.add_argument("--decisions", type=Path, required=True)
    parser.add_argument("--alerts", type=Path, required=True)
    parser.add_argument("--from-start", action="store_true")
    parser.add_argument("--injections", type=Path)
    args = parser.parse_args()
    runtime = PulseRuntime(args.model_dir, args.decision_policy)
    injection_tracker = InjectionTracker(args.injections) if args.injections else None
    args.decisions.parent.mkdir(parents=True, exist_ok=True)
    args.alerts.parent.mkdir(parents=True, exist_ok=True)
    source = RotatingJsonlFollower(args.features, from_start=args.from_start)
    try:
        with args.decisions.open("a", encoding="utf-8") as decisions, \
            args.alerts.open("a", encoding="utf-8") as alerts:
            while True:
                line = source.readline()
                record = json.loads(line)
                if record.get("schema") == "sentinel-pulse-feature-schema-v1":
                    continue
                result = runtime.score(record)
                result["run_id"] = args.run_id
                if result.get("status") == "alert" and injection_tracker is not None:
                    marker = injection_tracker.match(result)
                    if marker is not None:
                        result["injection_id"] = marker["injection_id"]
                        result["injected_at"] = marker["injected_at"]
                        result["injection_command_to_alert_seconds"] = max(
                            0.0, float(result["alerted_at"]) - float(marker["injected_at"])
                        )
                decisions.write(json.dumps(result, separators=(",", ":")) + "\n")
                decisions.flush()
                if result.get("status") == "alert":
                    alerts.write(json.dumps(result, separators=(",", ":")) + "\n")
                    alerts.flush()
    finally:
        source.close()


if __name__ == "__main__":
    main()
