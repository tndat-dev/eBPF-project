import json
import hashlib
import tempfile
import unittest
from pathlib import Path

from sentinel_pulse.evaluate_latency import evaluate, kernel_events
from sentinel_pulse.latency import InjectionTracker


class PulseLatencyTests(unittest.TestCase):
    def test_grpc_execve_kprobe_provenance_is_verified(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "kernel.jsonl"
            raw = {
                "node_name": "worker",
                "time": "1970-01-01T00:00:10.000000000Z",
                "process_kprobe": {
                    "policy_name": "sentinel-pulse-exec-provenance",
                    "function_name": "__x64_sys_execve",
                    "args": [{"string_arg": "/tmp/sentinel-runtime-attack-blind"}],
                    "process": {"exec_id": "exec-1", "pid": 123},
                },
            }
            canonical = json.dumps(raw, sort_keys=True, separators=(",", ":")).encode()
            record = {
                "schema": "sentinel-pulse-kernel-event-v1",
                "injection_id": "i0",
                "kernel_event_at": 10.0,
                "source": "tetragon_execve_kprobe_grpc",
                "identity_scope": "serialized_node_exact_binary",
                "policy_name": "sentinel-pulse-exec-provenance",
                "exec_id": "exec-1",
                "pid": 123,
                "node_name": "worker",
                "pod_name": "catalog-pod",
                "pod_uid": "pod-uid",
                "binary": "/tmp/sentinel-runtime-attack-blind",
                "raw_event_sha256": hashlib.sha256(canonical).hexdigest(),
                "raw_event": raw,
            }
            path.write_text(json.dumps(record) + "\n", encoding="utf-8")
            self.assertEqual(kernel_events(path)["i0"]["exec_id"], "exec-1")
            record["policy_name"] = "wrong-policy"
            path.write_text(json.dumps(record) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "execve provenance mismatch"):
                kernel_events(path)

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
                {"schema": "sentinel-pulse-decision-v1", "model_manifest_sha256": "a" * 64, "decision_policy_sha256": "b" * 64, "run_id": "blind-test", "injection_id": f"i{i}", "alerted_at": 10.0 + value, "post_window_processing_seconds": 0.1, "inference_ms": 2.0, "workload_key": "production/catalog:app", "cgroup_id": "7", "pod_name": "catalog-pod", "pod_uid": "pod-uid", "node_name": "worker", "container_name": "app"}
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
            def kernel_record(index):
                raw = {
                    "process_exec": {
                        "process": {
                            "exec_id": f"exec-{index}",
                            "binary": "/tmp/sentinel-runtime-attack-blind",
                            "pod": {
                                "namespace": "production",
                                "name": "catalog-pod",
                                "uid": "pod-uid",
                            },
                        }
                    },
                    "node_name": "worker",
                    "time": "1970-01-01T00:00:10.000000000Z",
                }
                canonical = json.dumps(
                    raw, sort_keys=True, separators=(",", ":")
                ).encode()
                return {
                    "schema": "sentinel-pulse-kernel-event-v1",
                    "injection_id": f"i{index}",
                    "kernel_event_at": 10.0,
                    "source": "tetragon_process_exec",
                    "exec_id": f"exec-{index}",
                    "node_name": "worker",
                    "pod_name": "catalog-pod",
                    "pod_uid": "pod-uid",
                    "workload_key": "production/catalog:app",
                    "workload_controller": "catalog",
                    "scenario": "probe",
                    "seed": index + 1,
                    "rate_per_second": 6,
                    "binary": "/tmp/sentinel-runtime-attack-blind",
                    "raw_event_sha256": hashlib.sha256(canonical).hexdigest(),
                    "raw_event": raw,
                }
            kernel.write_text(
                "".join(
                    json.dumps(kernel_record(i)) + "\n"
                    for i in range(3)
                ), encoding="utf-8"
            )
            report = evaluate(
                path,
                expected_injections=3,
                injection_path=injections,
                attack_contract_path=contract,
                kernel_event_path=kernel,
                expected_run_id="blind-test",
            )
            mismatched = list(records)
            mismatched[0] = {**mismatched[0], "pod_uid": "wrong-pod-uid"}
            path.write_text(
                "".join(json.dumps(item) + "\n" for item in mismatched),
                encoding="utf-8",
            )
            invalid_identity_report = evaluate(
                path,
                expected_injections=3,
                injection_path=injections,
                attack_contract_path=contract,
                kernel_event_path=kernel,
                expected_run_id="blind-test",
            )
        self.assertTrue(report["latency_gate_p99_le_2s"])
        self.assertEqual(report["recall"], 1.0)
        self.assertTrue(report["injection_identity_gate"])
        self.assertTrue(report["attack_matrix_gate"])
        self.assertTrue(report["blind_evidence_valid"])
        self.assertTrue(report["kernel_timestamp_gate"])
        self.assertTrue(report["decision_policy_identity_gate"])
        self.assertTrue(report["run_identity_gate"])
        self.assertEqual(report["kernel_to_alert_seconds"]["p50"], 1.0)
        self.assertFalse(invalid_identity_report["injection_identity_gate"])
        self.assertEqual(invalid_identity_report["invalid_detection_identity_ids"], ["i0"])
        self.assertFalse(invalid_identity_report["blind_evidence_valid"])

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
