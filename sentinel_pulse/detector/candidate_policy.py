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

    def evaluate(self, score: dict, context: dict | None = None) -> dict:
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


SCHEMA_V2 = "sentinel-pulse-candidate-preview-policy-v2"


class ConfirmedPreviewPolicy(CandidatePreviewPolicy):
    """Preview after k-of-n consecutive windows pass ``alpha * alpha_scale``.

    Uses the same ``ConfirmationState`` as the offline confirmation study so
    live and replayed decisions follow one definition. Still shadow-only.

    Optional rule keys (Pulse 5.11a, only used if a stable policy adopts them; absent = unchanged behaviour):
    - ``"combination": "cauchy"``: k-of-n on the Cauchy combination of tree_p and support_p instead of joint_p;
    - ``"temporal_rule": {"kind": "cusum", "drift", "threshold", "max_gap_seconds"[, "on_alarm"]}`` in place of
      ``temporal_confirmation`` and ``alpha_scale``: CUSUM on -ln joint_p per container.
    """

    def __init__(self, policy: dict, policy_sha256: str, scorer):
        from .confirmation import ConfirmationPolicy, ConfirmationState, CusumPolicy, CusumState
        if policy.get("schema") != SCHEMA_V2:
            raise ValueError("unsupported candidate preview policy schema")
        rule = dict(policy.get("rule") or {})
        confirmation = rule.pop("temporal_confirmation", None)
        scale = rule.pop("alpha_scale", None)
        temporal = rule.pop("temporal_rule", None)
        self.combination = rule.pop("combination", "bonferroni_min")
        base = {
            "score": "joint_p",
            "comparison": "less_than_or_equal",
            "threshold_source": "per_workload_model_calibrated_alpha",
            "semantic_gate": False,
        }
        if temporal is not None:
            if (rule != base or confirmation is not None or scale is not None or self.combination != "bonferroni_min"
                    or not isinstance(temporal, dict) or temporal.get("kind") != "cusum"
                    or not {"kind", "drift", "threshold", "max_gap_seconds"} <= set(temporal)
                    or not set(temporal) <= {"kind", "drift", "threshold", "max_gap_seconds", "on_alarm"}):
                raise ValueError("candidate preview v2 rule differs from the registered form")
            self.confirmation = CusumPolicy(drift=float(temporal["drift"]), threshold=float(temporal["threshold"]),
                                            max_gap_seconds=float(temporal["max_gap_seconds"]),
                                            on_alarm=str(temporal.get("on_alarm", "keep")))
            self.state = CusumState(self.confirmation)
        else:
            if (rule != base or not isinstance(confirmation, dict) or not isinstance(scale, (int, float))
                    or self.combination not in ("bonferroni_min", "cauchy")):
                raise ValueError("candidate preview v2 rule differs from the registered form")
            self.confirmation = ConfirmationPolicy(k=int(confirmation["k"]), n=int(confirmation["n"]),
                                                   alpha_scale=float(scale),
                                                   max_gap_seconds=float(confirmation["max_gap_seconds"]))
            self.state = ConfirmationState(self.confirmation)
        super().__init__(dict(policy, schema=SCHEMA, rule={
            "score": "joint_p", "comparison": "less_than_or_equal",
            "threshold_source": "per_workload_model_calibrated_alpha",
            "semantic_gate": False, "temporal_confirmation": False}), policy_sha256, scorer)
        self.policy = policy

    def evaluate(self, score: dict, context: dict | None = None) -> dict:
        result = super().evaluate(score)
        if not result["policy_evaluated"]:
            return result
        if not context or context.get("window_start") is None or context.get("window_end") is None:
            raise ValueError("temporal confirmation needs the window identity and bounds")
        alpha = result["candidate_policy_alpha"]
        from .confirmation import CusumPolicy, cauchy_p
        if isinstance(self.confirmation, CusumPolicy):
            row = dict(context, joint_p=float(score["joint_p"]), candidate_policy_alpha=alpha)
            preview = self.state.update(row)
            result.update(candidate_alert_preview=preview, confirmation_policy=self.confirmation.name,
                          preview_reason="cusum_at_or_above_threshold" if preview else "cusum_below_threshold")
            return result
        p = (cauchy_p(score["tree_p"], score["support_p"]) if self.combination == "cauchy"
             else float(score["joint_p"]))
        row = dict(context, joint_p=p, candidate_policy_alpha=alpha)
        preview = self.state.update(row)
        passed = p <= alpha * self.confirmation.alpha_scale
        result.update(candidate_alert_preview=preview, window_passed=passed,
                      confirmation_policy=self.confirmation.name,
                      preview_reason="confirmed_k_of_n" if preview else
                      ("awaiting_confirmation" if passed else "below_threshold_not_met"))
        if self.combination == "cauchy":
            result.update(combined_p=p, combination="cauchy")
        return result


def load_preview_policy(path: Path, scorer):
    """Load a v1 (single window) or v2 (confirmed) preview policy by schema."""
    raw = path.read_bytes()
    try:
        policy = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("candidate preview policy is not valid JSON") from exc
    digest = hashlib.sha256(raw).hexdigest()
    cls = ConfirmedPreviewPolicy if policy.get("schema") == SCHEMA_V2 else CandidatePreviewPolicy
    return cls(policy, digest, scorer)
