import hashlib
import json
import tempfile
import unittest
from pathlib import Path

import numpy as np

from sentinel_pulse.detect import PulseRuntime
from sentinel_pulse.encoding import schema_digest
from sentinel_pulse.integrity import contained_artifact, sha256_file, verify_sha256
from sentinel_pulse.model import PulseExtraTrees


class _PickleEstimator:
    def predict_proba(self, rows):
        return np.column_stack((np.ones(len(rows)), np.zeros(len(rows))))


class PulseIntegrityTests(unittest.TestCase):
    def test_checksum_and_containment_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifact = root / "model.pkl"
            artifact.write_bytes(b"candidate")
            verify_sha256(artifact, sha256_file(artifact))
            with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                verify_sha256(artifact, "0" * 64)
            with self.assertRaisesRegex(ValueError, "unsafe artifact path"):
                contained_artifact(root, "../model.pkl")

    def test_runtime_verifies_manifest_and_model_before_loading(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            columns = ["a", "b"]
            model = PulseExtraTrees(history=1, alpha=0.1)
            model.estimator = _PickleEstimator()
            model.calibration_scores = np.asarray([0.1, 0.2], dtype=np.float32)
            model.feature_dim = 2
            artifact = root / "production__catalog__app.pkl"
            model.save(artifact)
            item = {
                "status": "candidate",
                "artifact": artifact.name,
                "artifact_sha256": sha256_file(artifact),
                "artifact_bytes": artifact.stat().st_size,
                "model_class": "PulseExtraTrees",
                "history_windows": 1,
                "alpha": 0.1,
                "feature_dim": 2,
            }
            manifest = {
                "schema": "sentinel-pulse-model-manifest-v2",
                "feature_columns": columns,
                "feature_schema_sha256": schema_digest(columns),
                "history_windows": 1,
                "workloads": {"production/catalog:app": item},
            }
            manifest_path = root / "manifest.json"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            (root / "manifest.sha256").write_text(
                f"{sha256_file(manifest_path)}  manifest.json\n", encoding="ascii"
            )
            runtime = PulseRuntime(root)
            self.assertIn("production/catalog:app", runtime.models)

            artifact.write_bytes(artifact.read_bytes() + b"corruption")
            with self.assertRaisesRegex(ValueError, "size mismatch"):
                PulseRuntime(root)


if __name__ == "__main__":
    unittest.main()
