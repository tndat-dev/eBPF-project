import json
import tempfile
import unittest
from pathlib import Path

from sentinel_pulse.evaluate_latency import evaluate
from sentinel_pulse.latency import InjectionTracker


class PulseLatencyTests(unittest.TestCase):
    def _contract(self, path: Path) -> None:
        path.write_text(
            json.dumps(
                {
                    "schema": "sentinel-pulse-blind-attack-contract-v1",
                    "release": "test",
                    "frozen_before_candidate_training": True,
                    "matrix": {
                        "scenarios": ["probe"],
                        "workload_controllers": ["catalog"],
                        "trials": [
                            {"seed": index + 1, "rate_per_second": 6}
                            for index in range(3)
                        ],
                    },
                    "expected_injections": 3,
                    "safety_contract": {
                        "external_network": False,
                        "persistent_write": False,
                        "successful_mount": False,
                        "successful_privilege_change": False,
                        "target_namespace": "production",
                    },
                    "selection_policy": {
                        "attack_outcomes_used_for_training_or_tuning": False,
                        "infrastructure_failure_must_have_machine_readable_evidence": True,
                        "misses_are_retained": True,
                        "rerun_detection_misses": False,
                    },
                }
            ),
            encoding="utf-8",
        )

    def test_marker_attribution_is_workload_scoped_and_single_use(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "injections.jsonl"
            marker = {"schema": "sentinel-pulse-injection-v1", "injection_id": "x1", "injected_at": 10.0, "workload_key": "production/catalog:app"}
            path.write_text(json.dumps(marker) + "\n", encoding="utf-8")
            tracker = InjectionTracker(path)
            decision = {"alerted_at": 11.2, "workload_key": "production/catalog:app", "cgroup_id": "4"}
            self.assertEqual(tracker.match(decision)["injection_id"], "x1")
            self.assertIsNone(tracker.match(decision))

    def test_pre_injection_window_is_not_attributed_to_attack(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "injections.jsonl"
            marker = {
                "schema": "sentinel-pulse-injection-v1",
                "injection_id": "x1",
                "injected_at": 10.0,
                "workload_key": "production/catalog:app",
            }
            path.write_text(json.dumps(marker) + "\n", encoding="utf-8")
            tracker = InjectionTracker(path)
            stale = {
                "alerted_at": 10.2,
                "window_end": 9.9,
                "workload_key": "production/catalog:app",
            }
            self.assertIsNone(tracker.match(stale))

    def test_latency_gate_uses_true_injection_latency(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "decisions.jsonl"
            records = [
                {"schema": "sentinel-pulse-decision-v1", "model_manifest_sha256": "a" * 64, "decision_policy_sha256": "b" * 64, "injection_id": f"i{i}", "alerted_at": 10.0 + value, "post_window_processing_seconds": 0.1, "inference_ms": 2.0}
                for i, value in enumerate((0.8, 1.0, 1.2))
            ]
            path.write_text("".join(json.dumps(item) + "\n" for item in records), encoding="utf-8")
            injections = Path(temporary) / "injections.jsonl"
            injections.write_text(
                "".join(
                    json.dumps(
                        {
                            "schema": "sentinel-pulse-injection-v1",
                            "injection_id": f"i{i}",
                            "injected_at": 9.9,
                            "workload_controller": "catalog",
                            "workload_key": "production/catalog:app",
                            "cgroup_id": 7,
                            "node_name": "worker",
                            "pod_name": "catalog-pod",
                            "pod_uid": "pod-uid",
                            "scenario": "probe",
                            "seed": i + 1,
                            "rate_per_second": 6,
                        }
                    ) + "\n"
                    for i in range(3)
                ), encoding="utf-8"
            )
            contract = Path(temporary) / "contract.json"
            self._contract(contract)
            kernel = Path(temporary) / "kernel.jsonl"
            kernel.write_text(
                "".join(
                    json.dumps(
                        {
                            "schema": "sentinel-pulse-kernel-event-v1",
                            "injection_id": f"i{i}",
                            "kernel_event_at": 10.0,
                            "source": "tetragon_process_exec",
                            "exec_id": f"exec-{i}",
                            "node_name": "worker",
                            "pod_name": "catalog-pod",
                            "pod_uid": "pod-uid",
                            "workload_key": "production/catalog:app",
                            "workload_controller": "catalog",
                            "scenario": "probe",
                            "seed": i + 1,
                            "rate_per_second": 6,
                        }
                    ) + "\n"
                    for i in range(3)
                ), encoding="utf-8"
            )
            report = evaluate(
                path,
                expected_injections=3,
                injection_path=injections,
                attack_contract_path=contract,
                kernel_event_path=kernel,
            )
        self.assertTrue(report["latency_gate_p99_le_2s"])
        self.assertEqual(report["recall"], 1.0)
        self.assertTrue(report["injection_identity_gate"])
        self.assertTrue(report["attack_matrix_gate"])
        self.assertTrue(report["blind_evidence_valid"])
        self.assertTrue(report["kernel_timestamp_gate"])
        self.assertEqual(report["kernel_to_alert_seconds"]["p50"], 1.0)

    def test_unknown_detection_id_does_not_inflate_recall(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            decisions = root / "decisions.jsonl"
            decisions.write_text(
                json.dumps(
                    {
                        "schema": "sentinel-pulse-decision-v1",
                        "model_manifest_sha256": "a" * 64,
                        "injection_id": "not-in-contract",
                        "alerted_at": 0.5,
                    }
                ) + "\n", encoding="utf-8"
            )
            injections = root / "injections.jsonl"
            injections.write_text(
                json.dumps(
                    {
                        "schema": "sentinel-pulse-injection-v1",
                        "injection_id": "expected-1",
                        "injected_at": 0.0,
                    }
                ) + "\n", encoding="utf-8"
            )
            report = evaluate(decisions, injection_path=injections)
            self.assertEqual(report["recall"], 0.0)
            self.assertFalse(report["injection_identity_gate"])
            self.assertEqual(report["missing_injection_ids"], ["expected-1"])

    def test_userspace_marker_alone_cannot_open_kernel_latency_gate(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            decisions = root / "decisions.jsonl"
            decisions.write_text(
                json.dumps(
                    {
                        "schema": "sentinel-pulse-decision-v1",
                        "model_manifest_sha256": "a" * 64,
                        "decision_policy_sha256": "b" * 64,
                        "injection_id": "i0",
                        "alerted_at": 11.0,
                    }
                ) + "\n",
                encoding="utf-8",
            )
            injections = root / "injections.jsonl"
            injections.write_text(
                json.dumps(
                    {
                        "schema": "sentinel-pulse-injection-v1",
                        "injection_id": "i0",
                        "injected_at": 10.0,
                    }
                ) + "\n",
                encoding="utf-8",
            )
            report = evaluate(decisions, injection_path=injections)
            self.assertFalse(report["kernel_timestamp_gate"])
            self.assertFalse(report["latency_gate_p99_le_2s"])
            self.assertEqual(report["injection_command_to_alert_seconds"]["p50"], 1.0)


if __name__ == "__main__":
    unittest.main()
