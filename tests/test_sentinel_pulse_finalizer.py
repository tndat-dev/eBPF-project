import json
import tempfile
import unittest
from pathlib import Path

from sentinel_pulse.finalize_candidate import build_decision
from sentinel_pulse.integrity import sha256_file


class PulseFinalizerTests(unittest.TestCase):
    def _fixture(self, root: Path):
        model_dir = root / "models"
        model_dir.mkdir()
        artifact = model_dir / "catalog.pkl"
        artifact.write_bytes(b"immutable-model")
        workload = "production/catalog:app"
        manifest = {
            "schema": "sentinel-pulse-model-manifest-v2",
            "capture_validation": {"valid": True},
            "software": {"python": "test", "numpy": "test", "scikit_learn": "test"},
            "workloads": {
                workload: {
                    "status": "candidate",
                    "artifact": artifact.name,
                    "artifact_sha256": sha256_file(artifact),
                    "artifact_bytes": artifact.stat().st_size,
                    "model_class": "PulseExtraTrees",
                }
            },
        }
        manifest_path = model_dir / "manifest.json"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        (model_dir / "manifest.sha256").write_text(
            f"{sha256_file(manifest_path)}  manifest.json\n", encoding="ascii"
        )
        normal_path = root / "normal.json"
        normal_path.write_text(
            json.dumps(
                {
                    "schema": "sentinel-pulse-normal-soak-report-v1",
                    "normal_gate": True,
                    "scored_windows": 86400,
                    "alerts": 0,
                    "false_alert_rate_wilson_95": [0.0, 0.00005],
                    "workloads": {workload: {"duration_gate": True}},
                }
            ), encoding="utf-8"
        )
        attack_path = root / "attack.json"
        attack_path.write_text(
            json.dumps(
                {
                    "schema": "sentinel-pulse-latency-report-v1",
                    "expected_injections": 200,
                    "detected_injections": 200,
                    "recall": 1.0,
                    "latency_gate_p99_le_2s": True,
                    "injection_identity_gate": True,
                    "true_detection_latency_seconds": {"p99": 1.6},
                    "inference_ms": {"p99": 4.0},
                    "post_window_processing_seconds": {"p99": 0.2},
                }
            ), encoding="utf-8"
        )
        return model_dir, normal_path, attack_path

    def test_terminal_decision_passes_only_all_accuracy_latency_gates(self):
        with tempfile.TemporaryDirectory() as temporary:
            model_dir, normal, attack = self._fixture(Path(temporary))
            decision = build_decision(model_dir, normal, attack)
            self.assertEqual(decision["status"], "eligible_for_overhead_evaluation")
            self.assertFalse(decision["production_ready"])

    def test_collect_only_workload_fails_full_coverage_gate(self):
        with tempfile.TemporaryDirectory() as temporary:
            model_dir, normal, attack = self._fixture(Path(temporary))
            manifest_path = model_dir / "manifest.json"
            manifest = json.loads(manifest_path.read_text())
            manifest["workloads"]["production/kafka:kafka"] = {
                "status": "collect-only", "reason": "insufficient calibration"
            }
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            (model_dir / "manifest.sha256").write_text(
                f"{sha256_file(manifest_path)}  manifest.json\n", encoding="ascii"
            )
            decision = build_decision(model_dir, normal, attack)
            self.assertIn("all_workloads_have_candidate", decision["failed_gates"])


if __name__ == "__main__":
    unittest.main()
