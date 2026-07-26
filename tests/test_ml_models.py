import sys
import pickle
from pathlib import Path

import pytest

np = pytest.importorskip("numpy")
pytest.importorskip("torch")
pytest.importorskip("sklearn")

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "ml-service"))

from ml_models import ModelManager, PodModelBundle
from build_phase_dataset import allocate_validation, expand_vocabulary
from artifact_integrity import model_release_hashes
import promote_candidate


def test_decoder_behavior_is_checkpoint_versioned():
    assert PodModelBundle("production/new", 4).autoencoder.teacher_forcing is False
    assert PodModelBundle(
        "production/legacy", 4, model_version=1
    ).autoencoder.teacher_forcing is True
    assert PodModelBundle.MODEL_VERSION == 7
    assert PodModelBundle(
        "production/legacy", 4, model_version=5
    ).feature_clip is None


def test_v7_clips_scaled_feature_outliers():
    model = PodModelBundle("production/clipping", 4, model_version=7)
    train = np.zeros((16, 4), dtype=np.float32)
    holdout = np.full((4, 4), 100.0, dtype=np.float32)
    model.train(np.vstack([train, holdout]), epochs=1, val_ratio=0.2)
    transformed = model.scaler.transform(holdout[:1])
    assert transformed.max() > model.feature_clip
    # Prediction must remain finite despite the extreme raw standardized value.
    assert all(np.isfinite(model.predict(holdout[0])))


def test_v7_persists_workload_behavior_limits(tmp_path):
    model = PodModelBundle("production/behavior", 4, model_version=7)
    data = np.zeros((20, 4), dtype=np.float32)
    model.train(data, epochs=1, val_ratio=0.2)
    model.behavior_limits = {"connect": .25, "clone": .40}
    model.save(str(tmp_path))
    restored = PodModelBundle.load("production/behavior", str(tmp_path))
    assert restored.behavior_limits == model.behavior_limits


def test_phase_holdout_allocation_matches_trainer_rounding():
    counts = [10, 9, 8, 7]
    allocated = allocate_validation(counts, .20)
    assert sum(allocated) == round(sum(counts) * .20)
    assert all(1 <= value < count for value, count in zip(allocated, counts))


def test_policy_vocabulary_expansion_preserves_existing_indexes():
    base = {
        "read": 0, "write": 1,
        "read|read": 2, "read|write": 3,
        "write|read": 4, "write|write": 5,
    }
    expanded = expand_vocabulary(base, ("read", "write", "ptrace"))
    assert all(expanded[key] == index for key, index in base.items())
    assert set(key for key in expanded if "|" not in key) == {
        "read", "write", "ptrace",
    }
    assert len(expanded) == 12  # n unigrams + n^2 directed bigrams
    assert "ptrace|ptrace" in expanded


def test_empty_model_release_fails_closed(tmp_path):
    vocab = tmp_path / "vocab.pkl"
    with vocab.open("wb") as handle:
        pickle.dump({"read": 0}, handle)
    manager = ModelManager(str(tmp_path / "models"), str(vocab))
    with pytest.raises(RuntimeError, match="No model bundles"):
        manager.load_all()


def test_training_preprocessors_do_not_see_temporal_holdout():
    # The newest four windows deliberately have a radically different mean.
    # A leakage-prone scaler fitted on all 20 rows would not remain near zero.
    train = np.zeros((16, 4), dtype=np.float32)
    holdout = np.full((4, 4), 100.0, dtype=np.float32)
    model = PodModelBundle("production/leakage-test", 4)
    model.train(np.vstack([train, holdout]), epochs=1, val_ratio=0.2)

    assert np.allclose(model.scaler.mean_, 0.0)
    assert np.all(model.scaler.scale_ >= model.FEATURE_SCALE_FLOOR)
    assert len(model.baseline_scores) == 16
    assert len(model.validation_scores) == 4
    assert max(model.baseline_scores) < 0.3
    assert min(model.validation_scores) > 0.8


def test_atomic_promotion_includes_release_vocabulary(tmp_path, monkeypatch):
    import hashlib
    import json

    targets = ("default/postgres", "production/nginx", "production/redis")
    candidate = tmp_path / "candidate"
    candidate.mkdir()
    vocab = candidate / "vocab.pkl"
    vocab.write_bytes(b"immutable-vocabulary")
    vocab_hash = hashlib.sha256(vocab.read_bytes()).hexdigest()
    dataset_manifest = candidate / "dataset_manifest.json"
    dataset_manifest.write_text(json.dumps({
        "phase_order": ["normal", "wrk", "high", "recovery"],
        "vocabulary": {"output_sha256": vocab_hash},
        "source_manifests": [
            {"sensor_health": {"backpressure_events": 0}}
        ],
        "targets": {target: {"shape": [100, 1]} for target in targets},
    }))
    dataset_hash = hashlib.sha256(dataset_manifest.read_bytes()).hexdigest()
    training = {
        "accepted_offline": True,
        "vocab_sha256": vocab_hash,
        "bundled_vocab_sha256": vocab_hash,
        "dataset_manifest_sha256": dataset_hash,
        "bundled_dataset_manifest_sha256": dataset_hash,
        "models": {
            target: {"model_version": 7, "shape": [100, 1]}
            for target in targets
        },
    }
    (candidate / "training_report.json").write_text(json.dumps(training))
    for target in targets:
        stem = target.replace("/", "__")
        (candidate / f"{stem}_bundle.pkl").write_bytes(b"bundle")
        (candidate / f"{stem}_lstm.pt").write_bytes(b"weights")

    calibration = tmp_path / "calibration.json"
    calibration.write_text("{}")
    calibration_hash = hashlib.sha256(calibration.read_bytes()).hexdigest()
    runtime_hashes = promote_candidate.runtime_code_hashes()
    release_hashes = model_release_hashes(candidate)
    normal = tmp_path / "normal.json"
    normal.write_text(json.dumps({
        "passed": True,
        "candidate": str(candidate.resolve()),
        "vocab_sha256": vocab_hash,
        "calibration": str(calibration.resolve()),
        "calibration_sha256": calibration_hash,
        "runtime_code_sha256": runtime_hashes,
        "model_release_sha256": release_hashes,
        "regimes": {
            name: {"passed": True} for name in (
                "normal-1x", "wrk-c50", "high-mixed", "recovery-1x"
            )
        },
    }))
    attack = tmp_path / "attack.json"
    attack.write_text(json.dumps({
        "all_passed": True,
        "detected": 15,
        "total": 15,
        "model_dir": str(candidate.resolve()),
        "vocab_sha256": vocab_hash,
        "normal_calibration_sha256": calibration_hash,
        "runtime_code_sha256": runtime_hashes,
        "model_release_sha256": release_hashes,
        "runtime_binary_sha256": "safe-runtime-binary",
        "workloads": {
            target: {
                "exit_code": 0,
                "report": {"all_passed": True, "detected": 5, "total": 5},
            }
            for target in targets
        },
    }))
    production = tmp_path / "models"
    production.mkdir()
    (production / "old").write_text("old")

    class Bundle:
        model_version = 7
        input_dim = 1

    class Manager:
        vocab_size = 1

        def __init__(self, *_args):
            pass

        def load_all(self):
            pass

        def list_models(self):
            return list(targets)

        def get_model(self, _key):
            return Bundle()

    monkeypatch.setattr(promote_candidate, "ModelManager", Manager)
    monkeypatch.setattr(sys, "argv", [
        "promote_candidate.py", "--candidate", str(candidate),
        "--production", str(production),
        "--normal-report", str(normal), "--attack-report", str(attack),
        "--calibration", str(calibration),
        "--expected-version", "7", "--apply",
    ])
    assert promote_candidate.main() == 0
    assert (production / "vocab.pkl").read_bytes() == vocab.read_bytes()
    assert (production / "dataset_manifest.json").read_bytes() == dataset_manifest.read_bytes()
    assert (production / "validated_calibration.json").read_bytes() == b"{}"
    assert calibration.read_bytes() == b"{}"
    assert list(tmp_path.glob("calibration.json.backup-*"))
    release = json.loads((production / "release_manifest.json").read_text())
    assert release["files"]["vocab.pkl"] == vocab_hash
