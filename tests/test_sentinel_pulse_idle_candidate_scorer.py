import hashlib
import json
import __main__
import pickle

import numpy as np
import pytest

from sentinel_pulse.detector.idle_candidate import IdleCandidateScorer
from sentinel_pulse.detector.extended_reference_experiment import PulseExtendedReferenceTree
from sentinel_pulse.detector.support_model import PulseSupportEnsemble


class _Estimator:
    def predict_proba(self, values):
        return np.tile(np.asarray([[0.9, 0.1]]), (len(values), 1))


class _Base:
    feature_dim = 249
    history = 3
    alpha = 0.001
    calibration_scores = np.asarray([0.05, 0.10, 0.15])
    estimator = _Estimator()


def _candidate(tmp_path, monkeypatch=None):
    root = tmp_path / "candidate"
    root.mkdir()
    base = _Base()
    if monkeypatch is not None:
        # Match artifacts produced by the historical ``python -m`` trainer.
        base = PulseExtendedReferenceTree(history=3, alpha=.001)
        base.feature_dim = 249
        base.calibration_scores = np.asarray([0.05, 0.10, 0.15])
        base.estimator = _Estimator()
        monkeypatch.setattr(PulseExtendedReferenceTree, "__module__", "__main__")
        monkeypatch.setattr(__main__, "PulseExtendedReferenceTree", PulseExtendedReferenceTree, raising=False)
    model = PulseSupportEnsemble(base)
    model.low = np.zeros(249)
    model.high = np.ones(249)
    model.scale = np.ones(249)
    model.support_calibration = np.asarray([0.0, 1.0, 2.0])
    model.alpha = 2 * 0.0016666666666666668
    artifact = root / "model.pkl"
    artifact.write_bytes(pickle.dumps(model))
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    manifest = {
        "schema": "sentinel-pulse-model-only-candidate-v1",
        "candidate_name": "test-only",
        "status": "offline_frozen_candidate_for_independent_evaluation",
        "feature_contract": "pulse-entered-plus-seccomp-skip-idle-v2",
        "feature_dimensions": 249,
        "history_windows": 3,
        "decision_policy": None,
        "serving_compatible": False,
        "automatic_promotion": False,
        "fit_protocol": {"attack_data_used": False, "normal_training_admission": False},
        "workloads": {
            "production/test:app": {
                "artifact": "model.pkl",
                "artifact_sha256": digest,
                "feature_dim": 249,
                "tree_alpha": 0.001,
                "support_alpha_per_window_combined": model.alpha,
            }
        },
    }
    path = root / "CANDIDATE_MANIFEST.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    return root, hashlib.sha256(path.read_bytes()).hexdigest()


def test_pinned_candidate_scores_without_emitting_alert(tmp_path, monkeypatch):
    root, digest = _candidate(tmp_path, monkeypatch)
    scorer = IdleCandidateScorer(root, digest)

    result = scorer.score_context("production/test:app", np.zeros(996, dtype=np.float32))

    assert result["status"] == "candidate-raw-score-only"
    assert result["policy_applied"] is False
    assert result["serving_compatible"] is False
    assert result["alert"] is False


def test_manifest_must_be_caller_pinned(tmp_path):
    root, _ = _candidate(tmp_path)
    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        IdleCandidateScorer(root, "0" * 64)


def test_candidate_rejects_invalid_context_shape(tmp_path):
    root, digest = _candidate(tmp_path)
    scorer = IdleCandidateScorer(root, digest)
    with pytest.raises(ValueError, match="context must be one finite vector"):
        scorer.score_context("production/test:app", np.zeros(995, dtype=np.float32))


def test_unknown_workload_is_not_mislabeled_normal(tmp_path):
    root, digest = _candidate(tmp_path)
    scorer = IdleCandidateScorer(root, digest)

    result = scorer.score_context("production/missing:app", np.zeros(996))

    assert result["status"] == "candidate-model-unavailable"
    assert result["alert"] is False
    assert "normal" not in result["status"]


def test_manifest_cannot_claim_serving_compatibility(tmp_path):
    root, _ = _candidate(tmp_path)
    path = root / "CANDIDATE_MANIFEST.json"
    manifest = json.loads(path.read_text())
    manifest["serving_compatible"] = True
    path.write_text(json.dumps(manifest))
    digest = hashlib.sha256(path.read_bytes()).hexdigest()

    with pytest.raises(ValueError, match="explicitly non-serving"):
        IdleCandidateScorer(root, digest)
