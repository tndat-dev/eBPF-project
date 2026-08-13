import json
import pickle
import sys
from pathlib import Path

import pytest

np = pytest.importorskip("numpy")
pytest.importorskip("torch")
pytest.importorskip("sklearn")

SERVICE_ROOT = Path(__file__).resolve().parents[1] / "ml-service"
sys.path.insert(0, str(SERVICE_ROOT))

import ml_models
from ml_models import SharedWorkloadModelManager


def test_shared_manager_routes_one_bundle_and_keeps_workload_behavior(
    tmp_path, monkeypatch,
):
    targets = ["production/api", "production/cart"]
    with (tmp_path / "vocab.pkl").open("wb") as handle:
        pickle.dump({"read": 0, "write": 1}, handle)
    (tmp_path / "training_report.json").write_text(json.dumps({
        "model_routing": "shared_workload",
        "shared_model_key": "shared/workload",
        "targets": targets,
    }))
    (tmp_path / "workload_behavior_limits.json").write_text(json.dumps({
        "schema": "sentinel-shared-workload-behavior/v1",
        "workloads": {
            "production/api": {"execve": {"rate_limit": 0.1}},
            "production/cart": {"execve": {"rate_limit": 0.2}},
        },
    }))

    class Bundle:
        input_dim = 2
        baseline_scores = [0.1, 0.2]

        def predict(self, _vector):
            return 0.3, 0.4, 0.5

    bundle = Bundle()
    monkeypatch.setattr(
        ml_models.PodModelBundle, "load",
        classmethod(lambda cls, key, directory: bundle),
    )
    manager = SharedWorkloadModelManager(
        str(tmp_path), str(tmp_path / "vocab.pkl")
    )
    manager.load_all()
    assert manager.list_models() == targets
    assert manager._models[targets[0]] is manager._models[targets[1]] is bundle
    api = manager.score("production/api", np.zeros(2))
    cart = manager.score("production/cart", np.zeros(2))
    assert api["ensemble_score"] == cart["ensemble_score"] == 0.3
    assert api["behavior_limits"] != cart["behavior_limits"]
    assert manager.score("production/missing", np.zeros(2)) is None


def test_shared_manager_rejects_behavior_target_drift(tmp_path):
    with (tmp_path / "vocab.pkl").open("wb") as handle:
        pickle.dump({"read": 0}, handle)
    (tmp_path / "training_report.json").write_text(json.dumps({
        "model_routing": "shared_workload",
        "shared_model_key": "shared/workload",
        "targets": ["production/api"],
    }))
    (tmp_path / "workload_behavior_limits.json").write_text(json.dumps({
        "schema": "sentinel-shared-workload-behavior/v1",
        "workloads": {"production/other": {}},
    }))
    manager = SharedWorkloadModelManager(
        str(tmp_path), str(tmp_path / "vocab.pkl")
    )
    with pytest.raises(RuntimeError, match="behavior contract"):
        manager.load_all()


def test_shared_trainer_declares_single_thread_reproducibility_contract():
    source = (SERVICE_ROOT / "train_shared_workload_candidate.py").read_text()
    assert '--torch-threads", type=int, default=1' in source
    assert "torch.set_num_threads(args.torch_threads)" in source
    assert "torch.set_num_interop_threads(1)" in source
    assert '"torch_num_threads"' in source
