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
            "max_contiguous_gap_seconds": 1.5,
            "blind_attack_contract_sha256": "c" * 64,
            "expected_blind_injections": 450,
            "software": {
                "python": "test",
                "numpy": "test",
                "scikit_learn": "test",
                "scipy": "test",
                "joblib": "test",
                "threadpoolctl": "test",
                "narwhals": "test",
            },
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
        model_manifest_sha256 = sha256_file(manifest_path)
        marker_path = root / "SOAK_START.json"
        marker_path.write_text(
            json.dumps(
                {
                    "schema": "sentinel-pulse-semantic-soak-start-v4",
                    "blind_evaluation_started": False,
                    "model_manifest_sha256": model_manifest_sha256,
                    "decision_policy_sha256": "d" * 64,
                    "run_id": "normal-soak-test",
                }
            ),
            encoding="utf-8",
        )
        normal_path = root / "normal.json"
        normal_path.write_text(
            json.dumps(
                {
                    "schema": "sentinel-pulse-normal-soak-report-v1",
                    "model_manifest_sha256": model_manifest_sha256,
                    "model_identity_gate": True,
                    "normal_gate": True,
                    "soak_marker_sha256": sha256_file(marker_path),
                    "soak_marker_gate": True,
                    "marker_time_gate": True,
                    "run_id": "normal-soak-test",
                    "minimum_scored_windows": 86400,
                    "minimum_duration_hours_per_workload": 24.0,
                    "minimum_coverage_ratio_per_workload": 0.95,
                    "maximum_alerts": 0,
                    "duration_gate": True,
                    "coverage_gate": True,
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
                    "schema": "sentinel-pulse-latency-report-v2",
                    "model_manifest_sha256": model_manifest_sha256,
                    "model_identity_gate": True,
                    "blind_attack_contract_sha256": "c" * 64,
                    "attack_matrix_gate": True,
                    "expected_injections": 450,
                    "detected_injections": 450,
                    "recall": 1.0,
                    "blind_evidence_valid": True,
                    "run_identity_gate": True,
                    "latency_gate_p99_le_2s": True,
                    "injection_identity_gate": True,
                    "kernel_timestamp_gate": True,
                    "kernel_to_alert_seconds": {"p99": 1.6},
                    "injection_command_to_alert_seconds": {"p99": 1.7},
                    "inference_ms": {"p99": 4.0},
                    "post_window_processing_seconds": {"p99": 0.2},
                }
            ), encoding="utf-8"
        )
        return model_dir, normal_path, attack_path, marker_path

    def test_terminal_decision_passes_only_all_accuracy_latency_gates(self):
        with tempfile.TemporaryDirectory() as temporary:
            model_dir, normal, attack, marker = self._fixture(Path(temporary))
            decision = build_decision(model_dir, normal, attack, soak_marker_path=marker)
            self.assertEqual(decision["status"], "eligible_for_overhead_evaluation")
            self.assertFalse(decision["production_ready"])

    def test_collect_only_workload_fails_full_coverage_gate(self):
        with tempfile.TemporaryDirectory() as temporary:
            model_dir, normal, attack, marker = self._fixture(Path(temporary))
            manifest_path = model_dir / "manifest.json"
            manifest = json.loads(manifest_path.read_text())
            manifest["workloads"]["production/kafka:kafka"] = {
                "status": "collect-only", "reason": "insufficient calibration"
            }
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            (model_dir / "manifest.sha256").write_text(
                f"{sha256_file(manifest_path)}  manifest.json\n", encoding="ascii"
            )
            decision = build_decision(model_dir, normal, attack, soak_marker_path=marker)
            self.assertIn("all_workloads_have_candidate", decision["failed_gates"])

    def test_report_from_another_model_fails_identity_gate(self):
        with tempfile.TemporaryDirectory() as temporary:
            model_dir, normal, attack, marker = self._fixture(Path(temporary))
            report = json.loads(attack.read_text())
            report["model_manifest_sha256"] = "0" * 64
            attack.write_text(json.dumps(report), encoding="utf-8")
            decision = build_decision(model_dir, normal, attack, soak_marker_path=marker)
            self.assertIn("blind_model_identity", decision["failed_gates"])

    def test_blind_run_identity_is_a_terminal_gate(self):
        with tempfile.TemporaryDirectory() as temporary:
            model_dir, normal, attack, marker = self._fixture(Path(temporary))
            report = json.loads(attack.read_text())
            report["run_identity_gate"] = False
            report["blind_evidence_valid"] = False
            attack.write_text(json.dumps(report), encoding="utf-8")
            decision = build_decision(model_dir, normal, attack, soak_marker_path=marker)
            self.assertIn("blind_run_identity", decision["failed_gates"])
            self.assertIn("blind_evidence_integrity", decision["failed_gates"])

    def test_weakened_normal_protocol_cannot_pass_finalizer(self):
        with tempfile.TemporaryDirectory() as temporary:
            model_dir, normal, attack, marker = self._fixture(Path(temporary))
            report = json.loads(normal.read_text())
            report["minimum_duration_hours_per_workload"] = 1.0
            normal.write_text(json.dumps(report), encoding="utf-8")
            decision = build_decision(model_dir, normal, attack, soak_marker_path=marker)
            self.assertIn("normal_protocol", decision["failed_gates"])

    def test_finalizer_rejects_normal_report_without_immutable_soak_marker(self):
        with tempfile.TemporaryDirectory() as temporary:
            model_dir, normal, attack, _marker = self._fixture(Path(temporary))
            decision = build_decision(model_dir, normal, attack)
            self.assertIn("normal_soak_marker", decision["failed_gates"])

    def test_checksum_bound_decision_policy_must_match_both_evaluations(self):
        with tempfile.TemporaryDirectory() as temporary:
            model_dir, normal, attack, marker = self._fixture(Path(temporary))
            policy = (
                Path(__file__).resolve().parents[1]
                / "sentinel_pulse" / "protocol" / "decision-policy-semantic-v1.json"
            )
            policy_sha = sha256_file(policy)
            marker_record = json.loads(marker.read_text())
            marker_record["decision_policy_sha256"] = policy_sha
            marker.write_text(json.dumps(marker_record), encoding="utf-8")
            for report_path in (normal, attack):
                report = json.loads(report_path.read_text())
                report["decision_policy_identity_gate"] = True
                report["decision_policy_sha256"] = policy_sha
                if report_path == normal:
                    report["soak_marker_sha256"] = sha256_file(marker)
                report_path.write_text(json.dumps(report), encoding="utf-8")
            decision = build_decision(
                model_dir,
                normal,
                attack,
                decision_policy_path=policy,
                soak_marker_path=marker,
            )
            self.assertTrue(decision["gates"]["normal_decision_policy_identity"])
            self.assertTrue(decision["gates"]["blind_decision_policy_identity"])

            report = json.loads(attack.read_text())
            report["decision_policy_sha256"] = "0" * 64
            attack.write_text(json.dumps(report), encoding="utf-8")
            rejected = build_decision(
                model_dir,
                normal,
                attack,
                decision_policy_path=policy,
                soak_marker_path=marker,
            )
            self.assertIn(
                "blind_decision_policy_identity", rejected["failed_gates"]
            )


if __name__ == "__main__":
    unittest.main()
