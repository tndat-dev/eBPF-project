"""Integrity-checked scorer for the frozen idle-aware *model-only* candidate.

This is an offline/shadow evaluation adapter. It intentionally has no alert
policy, output sink, collector integration, or promotion path. A positive score
must never be interpreted as a production alert.
"""
from __future__ import annotations

import json
import math
import __main__
from pathlib import Path
import pickle

import numpy as np

from ..integrity import contained_artifact, sha256_file, verify_sha256


SCHEMA = "sentinel-pulse-model-only-candidate-v1"
FEATURE_CONTRACT = "pulse-entered-plus-seccomp-skip-idle-v2"
FEATURE_DIM = 249


class IdleCandidateScorer:
    """Load a caller-pinned candidate and return raw model scores only."""

    def __init__(self, candidate_dir: Path, expected_manifest_sha256: str):
        self.candidate_dir = candidate_dir.resolve(strict=True)
        manifest_path = self.candidate_dir / "CANDIDATE_MANIFEST.json"
        verify_sha256(manifest_path, expected_manifest_sha256)
        self.manifest_sha256 = expected_manifest_sha256
        self.manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest = self.manifest

        if manifest.get("schema") != SCHEMA:
            raise ValueError("unsupported model-only candidate schema")
        if manifest.get("feature_contract") != FEATURE_CONTRACT:
            raise ValueError("candidate feature contract is not idle-aware v2")
        if manifest.get("feature_dimensions") != FEATURE_DIM:
            raise ValueError("candidate feature dimension mismatch")
        if type(manifest.get("history_windows")) is not int or manifest["history_windows"] < 1:
            raise ValueError("candidate history length is invalid")
        if manifest.get("status") != "offline_frozen_candidate_for_independent_evaluation":
            raise ValueError("candidate is not frozen for independent evaluation")
        if manifest.get("decision_policy") is not None:
            raise ValueError("model-only scorer must not accept an alert policy")
        if manifest.get("serving_compatible") is not False:
            raise ValueError("candidate must remain explicitly non-serving")
        if manifest.get("automatic_promotion") is not False:
            raise ValueError("automatic promotion must remain disabled")
        fit_protocol = manifest.get("fit_protocol")
        if (
            not isinstance(fit_protocol, dict)
            or fit_protocol.get("attack_data_used") is not False
            or fit_protocol.get("normal_training_admission") is not False
        ):
            raise ValueError("candidate fit provenance is incomplete or unsafe")

        workloads = manifest.get("workloads")
        if not isinstance(workloads, dict) or not workloads:
            raise ValueError("candidate contains no workload artifacts")
        self.models = {}
        for workload, entry in workloads.items():
            if not isinstance(workload, str) or not workload or not isinstance(entry, dict):
                raise ValueError("candidate workload entry is malformed")
            if entry.get("feature_dim") != FEATURE_DIM:
                raise ValueError(f"candidate feature dimension mismatch for {workload}")
            if not math.isclose(float(entry.get("tree_alpha", -1)), .001, rel_tol=0, abs_tol=1e-12):
                raise ValueError(f"candidate tree calibration metadata mismatch for {workload}")
            artifact = contained_artifact(self.candidate_dir, entry.get("artifact", ""))
            verify_sha256(artifact, entry.get("artifact_sha256", ""))
            # Pickle is executable: only load files reached through the
            # caller-pinned manifest and matching its artifact digest.
            # The frozen trainer was invoked as ``python -m`` and serialized
            # PulseExtendedReferenceTree as ``__main__.PulseExtendedReferenceTree``.
            from .extended_reference_experiment import PulseExtendedReferenceTree
            __main__.PulseExtendedReferenceTree = PulseExtendedReferenceTree
            with artifact.open("rb") as stream:
                model = pickle.load(stream)
            base = getattr(model, "base", None)
            if (
                getattr(base, "feature_dim", None) != FEATURE_DIM
                or getattr(base, "history", None) != manifest["history_windows"]
                or not math.isclose(float(getattr(base, "alpha", -1)), .001, rel_tol=0, abs_tol=1e-12)
                or getattr(base, "estimator", None) is None
                or getattr(base, "calibration_scores", None) is None
                or getattr(model, "support_calibration", None) is None
            ):
                raise ValueError(f"candidate artifact metadata mismatch for {workload}")
            if not math.isclose(
                float(getattr(model, "alpha", -1)),
                float(entry.get("support_alpha_per_window_combined", -2)),
                rel_tol=1e-10,
                abs_tol=1e-12,
            ):
                raise ValueError(f"candidate support calibration mismatch for {workload}")
            self.models[workload] = model

    def score_context(self, workload_key: str, context) -> dict:
        """Score exactly ``history_windows + current`` vectors; never emit alerts."""
        model = self.models.get(workload_key)
        if model is None:
            return {
                "status": "candidate-model-unavailable",
                "workload_key": workload_key,
                "candidate_manifest_sha256": self.manifest_sha256,
                "alert": False,
            }

        values = np.asarray(context, dtype=np.float32)
        expected = (self.manifest["history_windows"] + 1) * FEATURE_DIM
        if values.shape == (expected,):
            values = values.reshape(1, expected)
        if values.shape != (1, expected) or not np.isfinite(values).all():
            raise ValueError(f"context must be one finite vector of {expected} values")

        result = model.predict_contexts(values)
        names = ("tree_score", "tree_p", "support_score", "support_p", "joint_p")
        scores = {name: float(np.asarray(result[name]).reshape(-1)[0]) for name in names}
        if any(not math.isfinite(value) for value in scores.values()):
            raise ValueError("candidate produced a non-finite score")
        anomalous = bool(np.asarray(result["anomalous"]).reshape(-1)[0])
        return {
            "status": "candidate-raw-score-only",
            "workload_key": workload_key,
            "candidate_manifest_sha256": self.manifest_sha256,
            **scores,
            "raw_model_anomaly": anomalous,
            "alert": False,
            "policy_applied": False,
            "serving_compatible": False,
        }


def candidate_manifest_sha256(candidate_dir: Path) -> str:
    """Return a digest for registration; callers must freeze/pin this value."""
    return sha256_file(candidate_dir / "CANDIDATE_MANIFEST.json")
