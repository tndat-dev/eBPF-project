import json
import tempfile
import unittest
from pathlib import Path

from sentinel_pulse.evaluate_normal import evaluate, wilson_interval


class PulseNormalEvaluationTests(unittest.TestCase):
    def test_zero_alerts_still_reports_nonzero_confidence_upper_bound(self):
        lower, upper = wilson_interval(0, 1000)
        self.assertEqual(lower, 0.0)
        self.assertGreater(upper, 0.0)
        self.assertLess(upper, 0.004)

    def test_normal_gate_requires_duration_and_alert_budget(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "normal.jsonl"
            records = [
                {
                    "schema": "sentinel-pulse-decision-v1",
                    "status": "normal",
                    "model_manifest_sha256": "a" * 64,
                    "workload_key": "production/catalog:app",
                    "window_end": float(index),
                }
                for index in range(10)
            ]
            path.write_text("".join(json.dumps(record) + "\n" for record in records), encoding="utf-8")
            report = evaluate(
                path,
                maximum_alerts=0,
                minimum_scored_windows=10,
                minimum_duration_hours=9.0 / 3600.0,
            )
            self.assertTrue(report["normal_gate"])
            self.assertEqual(report["alerts"], 0)
            self.assertEqual(report["workloads"]["production/catalog:app"]["scored_windows"], 10)

    def test_many_parallel_windows_do_not_fake_wall_clock_duration(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "short.jsonl"
            records = [
                {
                    "schema": "sentinel-pulse-decision-v1",
                    "status": "normal",
                    "model_manifest_sha256": "a" * 64,
                    "workload_key": "production/catalog:app",
                    "window_end": float(index % 100),
                }
                for index in range(1000)
            ]
            path.write_text("".join(json.dumps(record) + "\n" for record in records), encoding="utf-8")
            report = evaluate(
                path, maximum_alerts=0, minimum_scored_windows=1000, minimum_duration_hours=24.0
            )
            self.assertFalse(report["duration_gate"])
            self.assertFalse(report["normal_gate"])

    def test_mixed_model_identities_fail_normal_gate(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "mixed.jsonl"
            records = [
                {
                    "schema": "sentinel-pulse-decision-v1",
                    "status": "normal",
                    "model_manifest_sha256": identity * 64,
                    "workload_key": "production/catalog:app",
                    "window_end": float(index),
                }
                for index, identity in enumerate(("a", "b"))
            ]
            path.write_text(
                "".join(json.dumps(record) + "\n" for record in records),
                encoding="utf-8",
            )
            report = evaluate(
                path, minimum_scored_windows=2, minimum_duration_hours=1.0 / 3600.0
            )
            self.assertFalse(report["model_identity_gate"])
            self.assertFalse(report["normal_gate"])

    def test_sparse_endpoints_do_not_fake_wall_clock_coverage(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "sparse.jsonl"
            records = [
                {
                    "schema": "sentinel-pulse-decision-v1",
                    "status": "normal",
                    "model_manifest_sha256": "a" * 64,
                    "workload_key": "production/catalog:app",
                    "window_end": end,
                }
                for end in (0.0, 24.0 * 3600.0)
            ]
            path.write_text(
                "".join(json.dumps(record) + "\n" for record in records),
                encoding="utf-8",
            )
            report = evaluate(
                path, minimum_scored_windows=2, minimum_duration_hours=24.0
            )
            self.assertTrue(report["duration_gate"])
            self.assertFalse(report["coverage_gate"])
            self.assertFalse(report["normal_gate"])

    def test_suppressed_raw_anomaly_is_scored_but_not_hidden_or_counted_as_alert(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "suppressed.jsonl"
            records = [
                {
                    "schema": "sentinel-pulse-decision-v1",
                    "status": "suppressed" if index == 5 else "normal",
                    "model_manifest_sha256": "a" * 64,
                    "decision_policy_sha256": "b" * 64,
                    "workload_key": "production/catalog:app",
                    "window_end": float(index),
                }
                for index in range(10)
            ]
            path.write_text(
                "".join(json.dumps(record) + "\n" for record in records),
                encoding="utf-8",
            )
            report = evaluate(
                path,
                maximum_alerts=0,
                minimum_scored_windows=10,
                minimum_duration_hours=9.0 / 3600.0,
            )
            self.assertTrue(report["normal_gate"])
            self.assertEqual(report["scored_windows"], 10)
            self.assertEqual(report["alerts"], 0)
            self.assertEqual(report["suppressed_raw_anomalies"], 1)
            self.assertTrue(report["decision_policy_identity_gate"])


if __name__ == "__main__":
    unittest.main()
