import json
import hashlib
import tempfile
import unittest
from pathlib import Path

from sentinel_pulse.evaluate_normal import evaluate, wilson_interval


class PulseNormalEvaluationTests(unittest.TestCase):
    @staticmethod
    def _manifest(root: Path, *workloads: str) -> tuple[Path, str]:
        path = root / "manifest.json"
        path.write_text(
            json.dumps({"workloads": {workload: {} for workload in workloads}}),
            encoding="utf-8",
        )
        return path, hashlib.sha256(path.read_bytes()).hexdigest()

    def test_zero_alerts_still_reports_nonzero_confidence_upper_bound(self):
        lower, upper = wilson_interval(0, 1000)
        self.assertEqual(lower, 0.0)
        self.assertGreater(upper, 0.0)
        self.assertLess(upper, 0.004)

    def test_normal_gate_requires_duration_and_alert_budget(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest, manifest_sha256 = self._manifest(
                root, "production/catalog:app"
            )
            path = root / "normal.jsonl"
            records = [
                {
                    "schema": "sentinel-pulse-decision-v1",
                    "status": "normal",
                    "model_manifest_sha256": manifest_sha256,
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
                model_manifest_path=manifest,
            )
            self.assertTrue(report["normal_gate"])
            self.assertEqual(report["alerts"], 0)
            self.assertEqual(report["workloads"]["production/catalog:app"]["scored_windows"], 10)

    def test_many_parallel_windows_do_not_fake_wall_clock_duration(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest, manifest_sha256 = self._manifest(
                root, "production/catalog:app"
            )
            path = root / "short.jsonl"
            records = [
                {
                    "schema": "sentinel-pulse-decision-v1",
                    "status": "normal",
                    "model_manifest_sha256": manifest_sha256,
                    "workload_key": "production/catalog:app",
                    "window_end": float(index % 100),
                }
                for index in range(1000)
            ]
            path.write_text("".join(json.dumps(record) + "\n" for record in records), encoding="utf-8")
            report = evaluate(
                path,
                maximum_alerts=0,
                minimum_scored_windows=1000,
                minimum_duration_hours=24.0,
                model_manifest_path=manifest,
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
                path,
                minimum_scored_windows=2,
                minimum_duration_hours=1.0 / 3600.0,
                model_manifest_path=self._manifest(
                    Path(temporary), "production/catalog:app"
                )[0],
            )
            self.assertFalse(report["model_identity_gate"])
            self.assertFalse(report["normal_gate"])

    def test_sparse_endpoints_do_not_fake_wall_clock_coverage(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest, manifest_sha256 = self._manifest(
                root, "production/catalog:app"
            )
            path = root / "sparse.jsonl"
            records = [
                {
                    "schema": "sentinel-pulse-decision-v1",
                    "status": "normal",
                    "model_manifest_sha256": manifest_sha256,
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
                path,
                minimum_scored_windows=2,
                minimum_duration_hours=24.0,
                model_manifest_path=manifest,
            )
            self.assertTrue(report["duration_gate"])
            self.assertFalse(report["coverage_gate"])
            self.assertFalse(report["normal_gate"])

    def test_suppressed_raw_anomaly_is_scored_but_not_hidden_or_counted_as_alert(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest, manifest_sha256 = self._manifest(
                root, "production/catalog:app"
            )
            path = root / "suppressed.jsonl"
            records = [
                {
                    "schema": "sentinel-pulse-decision-v1",
                    "status": "suppressed" if index == 5 else "normal",
                    "model_manifest_sha256": manifest_sha256,
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
                model_manifest_path=manifest,
            )
            self.assertTrue(report["normal_gate"])
            self.assertEqual(report["scored_windows"], 10)
            self.assertEqual(report["alerts"], 0)
            self.assertEqual(report["suppressed_raw_anomalies"], 1)
            self.assertTrue(report["decision_policy_identity_gate"])

    def test_soak_marker_filters_early_rows_and_enforces_finalize_time(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest, manifest_sha256 = self._manifest(
                root, "production/catalog:app"
            )
            marker = root / "SOAK_START.json"
            marker.write_text(
                json.dumps(
                    {
                        "schema": "sentinel-pulse-semantic-soak-start-v4",
                        "blind_evaluation_started": False,
                        "model_manifest_sha256": manifest_sha256,
                        "decision_policy_sha256": "b" * 64,
                        "run_id": "soak-test",
                        "started_not_before": "1970-01-01T00:01:40+00:00",
                        "eligible_finalize_after": "1970-01-01T00:01:42+00:00",
                        "minimum_duration_hours_per_workload": 2.0 / 3600.0,
                        "minimum_coverage_ratio_per_workload": 0.95,
                        "maximum_alerts": 0,
                    }
                ),
                encoding="utf-8",
            )
            decisions = root / "normal.jsonl"
            decisions.write_text(
                "".join(
                    json.dumps(
                        {
                            "schema": "sentinel-pulse-decision-v1",
                            "status": "normal",
                            "model_manifest_sha256": manifest_sha256,
                            "decision_policy_sha256": "b" * 64,
                            "run_id": "soak-test",
                            "workload_key": "production/catalog:app",
                            "window_end": float(second),
                        }
                    )
                    + "\n"
                    for second in (99, 100, 101, 102)
                ),
                encoding="utf-8",
            )
            early = evaluate(
                decisions,
                minimum_scored_windows=3,
                minimum_duration_hours=2.0 / 3600.0,
                soak_marker_path=marker,
                now=101.9,
                model_manifest_path=manifest,
            )
            final = evaluate(
                decisions,
                minimum_scored_windows=3,
                minimum_duration_hours=2.0 / 3600.0,
                soak_marker_path=marker,
                now=102.0,
                model_manifest_path=manifest,
            )
            self.assertEqual(final["excluded_scored_windows_before_marker"], 1)
            self.assertFalse(early["marker_time_gate"])
            self.assertFalse(early["normal_gate"])
            self.assertTrue(final["soak_marker_gate"])
            self.assertTrue(final["normal_gate"])

    def test_manifest_workload_set_is_mandatory_and_exact(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest, manifest_sha256 = self._manifest(
                root, "production/catalog:app", "production/order:app"
            )
            decisions = root / "normal.jsonl"
            decisions.write_text(
                "".join(
                    json.dumps(
                        {
                            "schema": "sentinel-pulse-decision-v1",
                            "status": "normal",
                            "model_manifest_sha256": manifest_sha256,
                            "workload_key": "production/catalog:app",
                            "window_end": float(index),
                        }
                    )
                    + "\n"
                    for index in range(3)
                ),
                encoding="utf-8",
            )
            report = evaluate(
                decisions,
                minimum_scored_windows=3,
                minimum_duration_hours=2.0 / 3600.0,
                model_manifest_path=manifest,
            )
            self.assertFalse(report["expected_workload_gate"])
            self.assertEqual(report["missing_workloads"], ["production/order:app"])
            self.assertEqual(report["unexpected_workloads"], [])
            self.assertFalse(report["normal_gate"])

    def test_marker_cannot_pass_without_the_bound_model_manifest(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            marker = root / "SOAK_START.json"
            marker.write_text(
                json.dumps(
                    {
                        "schema": "sentinel-pulse-semantic-soak-start-v5",
                        "blind_evaluation_started": False,
                        "model_manifest_sha256": "a" * 64,
                        "decision_policy_sha256": "b" * 64,
                        "run_id": "soak-test",
                        "started_not_before": "1970-01-01T00:00:00+00:00",
                        "eligible_finalize_after": "1970-01-01T00:00:02+00:00",
                        "minimum_duration_hours_per_workload": 2.0 / 3600.0,
                        "minimum_coverage_ratio_per_workload": 0.95,
                        "maximum_alerts": 0,
                    }
                ),
                encoding="utf-8",
            )
            decisions = root / "normal.jsonl"
            decisions.write_text(
                "".join(
                    json.dumps(
                        {
                            "schema": "sentinel-pulse-decision-v1",
                            "status": "normal",
                            "model_manifest_sha256": "a" * 64,
                            "decision_policy_sha256": "b" * 64,
                            "run_id": "soak-test",
                            "workload_key": "production/catalog:app",
                            "window_end": float(index),
                        }
                    )
                    + "\n"
                    for index in range(3)
                ),
                encoding="utf-8",
            )
            report = evaluate(
                decisions,
                minimum_scored_windows=3,
                minimum_duration_hours=2.0 / 3600.0,
                soak_marker_path=marker,
                now=2.0,
            )
            self.assertFalse(report["model_manifest_gate"])
            self.assertFalse(report["expected_workload_gate"])
            self.assertFalse(report["normal_gate"])

    def test_multiple_node_files_are_aggregated_before_workload_gate(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest, manifest_sha256 = self._manifest(
                root, "production/catalog:app", "production/order:app"
            )
            decisions = []
            for workload in ("production/catalog:app", "production/order:app"):
                path = root / f"{workload.split('/')[1].split(':')[0]}.jsonl"
                path.write_text(
                    "".join(
                        json.dumps(
                            {
                                "schema": "sentinel-pulse-decision-v1",
                                "status": "normal",
                                "model_manifest_sha256": manifest_sha256,
                                "workload_key": workload,
                                "window_end": float(index),
                            }
                        )
                        + "\n"
                        for index in range(3)
                    ),
                    encoding="utf-8",
                )
                decisions.append(path)
            report = evaluate(
                decisions,
                minimum_scored_windows=6,
                minimum_duration_hours=2.0 / 3600.0,
                model_manifest_path=manifest,
            )
            self.assertTrue(report["expected_workload_gate"])
            self.assertTrue(report["normal_gate"])
            self.assertIsNone(report["path"])
            self.assertEqual(len(report["decision_files"]), 2)


if __name__ == "__main__":
    unittest.main()
