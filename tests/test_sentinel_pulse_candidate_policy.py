import copy
import hashlib
import json

import pytest

from sentinel_pulse.candidate_policy import CandidatePreviewPolicy


class _Model:
    alpha = 0.0016666666666666668


class _Scorer:
    manifest_sha256 = "a" * 64
    manifest = {
        "workloads": {
            "production/test:app": {
                "support_alpha_per_window_combined": _Model.alpha,
            }
        }
    }
    models = {"production/test:app": _Model()}


def _policy():
    return {
        "schema": "sentinel-pulse-candidate-preview-policy-v1",
        "candidate_manifest_sha256": _Scorer.manifest_sha256,
        "frozen_before_independent_evaluation": True,
        "blind_outcome_used": False,
        "automatic_promotion": False,
        "rule": {
            "score": "joint_p",
            "comparison": "less_than_or_equal",
            "threshold_source": "per_workload_model_calibrated_alpha",
            "semantic_gate": False,
            "temporal_confirmation": False,
        },
        "nominal_error_budget": {
            "horizon_windows": 30,
            "interval_target": 0.05,
            "is_guarantee": False,
        },
    }


def test_preview_policy_is_checksum_bound_and_only_reports_candidate_preview(tmp_path):
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(_policy()))
    scorer = _Scorer()
    policy = CandidatePreviewPolicy.load(path, scorer)

    result = policy.evaluate({
        "status": "candidate-raw-score-only",
        "workload_key": "production/test:app",
        "joint_p": 0.001,
        "raw_model_anomaly": True,
    })

    assert result["candidate_alert_preview"] is True
    assert result["policy_evaluated"] is True
    assert result["policy_sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
    assert result["alert"] is False
    assert result["policy_applied"] is False
    assert result["serving_compatible"] is False


def test_preview_policy_requires_threshold_consistency(tmp_path):
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(_policy()))
    policy = CandidatePreviewPolicy.load(path, _Scorer())
    with pytest.raises(ValueError, match="disagrees"):
        policy.evaluate({
            "status": "candidate-raw-score-only",
            "workload_key": "production/test:app",
            "joint_p": 0.01,
            "raw_model_anomaly": True,
        })


@pytest.mark.parametrize("mutation, message", [
    (lambda p: p.update(candidate_manifest_sha256="b" * 64), "not bound"),
    (lambda p: p.update(blind_outcome_used=True), "blind outcomes"),
    (lambda p: p["rule"].update(semantic_gate=True), "registered rule"),
    (lambda p: p["nominal_error_budget"].update(is_guarantee=True), "cannot claim an FPR guarantee"),
])
def test_preview_policy_rejects_unregistered_claims(tmp_path, mutation, message):
    payload = copy.deepcopy(_policy())
    mutation(payload)
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(payload))
    with pytest.raises(ValueError, match=message):
        CandidatePreviewPolicy.load(path, _Scorer())
