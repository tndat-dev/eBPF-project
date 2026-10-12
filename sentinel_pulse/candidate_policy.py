"""Frozen, model-only alert preview policy for the idle-aware candidate."""
from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path


SCHEMA = "sentinel-pulse-candidate-preview-policy-v1"


class CandidatePreviewPolicy:
    """Evaluate an alert preview without emitting an operational alert."""

    def __init__(self, policy: dict, policy_sha256: str, scorer):
        if policy.get("schema") != SCHEMA:
            raise ValueError("unsupported candidate preview policy schema")
        if policy.get("candidate_manifest_sha256") != scorer.manifest_sha256:
            raise ValueError("policy is not bound to this candidate manifest")
        if policy.get("frozen_before_independent_evaluation") is not True:
            raise ValueError("policy was not frozen before evaluation")
        if policy.get("blind_outcome_used") is not False:
            raise ValueError("policy cannot depend on blind outcomes")
        if policy.get("automatic_promotion") is not False:
            raise ValueError("automatic promotion must remain disabled")
        rule = policy.get("rule")
        if rule != {
            "score": "joint_p",
            "comparison": "less_than_or_equal",
            "threshold_source": "per_workload_model_calibrated_alpha",
            "semantic_gate": False,
            "temporal_confirmation": False,
        }:
            raise ValueError("candidate preview rule differs from the registered rule")
        budget = policy.get("nominal_error_budget")
        if isinstance(budget, dict) and budget.get("is_guarantee") is True:
            raise ValueError("candidate policy cannot claim an FPR guarantee")
        if (
            not isinstance(budget, dict)
            or budget.get("horizon_windows") != 30
            or not math.isclose(float(budget.get("interval_target", -1)), .05,
                                rel_tol=0, abs_tol=1e-12)
            or budget.get("is_guarantee") is not False
        ):
            raise ValueError("candidate preview error-budget declaration is invalid")

        for workload, model in scorer.models.items():
            alpha = float(getattr(model, "alpha", float("nan")))
            entry = scorer.manifest["workloads"][workload]
            declared = float(entry.get("support_alpha_per_window_combined", float("nan")))
            if not math.isfinite(alpha) or not 0 < alpha < 1:
                raise ValueError(f"invalid calibrated alpha for {workload}")
            if not math.isclose(alpha, declared, rel_tol=1e-10, abs_tol=1e-12):
                raise ValueError(f"model alpha differs from manifest for {workload}")
        self.scorer = scorer
        self.policy = policy
        self.sha256 = policy_sha256

    @classmethod
    def load(cls, path: Path, scorer):
        raw = path.read_bytes()
        try:
            policy = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("candidate preview policy is not valid JSON") from exc
        digest = hashlib.sha256(raw).hexdigest()
        return cls(policy, digest, scorer)

    def evaluate(self, score: dict) -> dict:
        workload = score.get("workload_key")
        model = self.scorer.models.get(workload)
        if model is None or score.get("status") != "candidate-raw-score-only":
            return {
                "policy_sha256": self.sha256,
                "policy_evaluated": False,
                "candidate_alert_preview": None,
                "preview_reason": "model_unavailable_or_unscored",
            }
        joint_p = float(score["joint_p"])
        alpha = float(model.alpha)
        raw_anomaly = bool(score["raw_model_anomaly"])
        preview = joint_p <= alpha
        if raw_anomaly != preview:
            raise ValueError("candidate model anomaly disagrees with registered p-value rule")
        return {
            "policy_sha256": self.sha256,
            "policy_evaluated": True,
            "candidate_policy_alpha": alpha,
            "candidate_alert_preview": preview,
            "preview_reason": "joint_p_at_or_below_model_alpha" if preview else "below_threshold_not_met",
            # A preview is explicitly never an alert or enforcement action.
            "alert": False,
            "policy_applied": False,
            "serving_compatible": False,
        }
