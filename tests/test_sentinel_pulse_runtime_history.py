import unittest

import numpy as np
from pathlib import Path

from sentinel_pulse.detect import PulseRuntime
from sentinel_pulse.encoding import compact_record, schema_digest
from sentinel_pulse.model import PulseExtraTrees


class _NormalEstimator:
    def predict_proba(self, rows):
        return np.column_stack((np.ones(len(rows)), np.zeros(len(rows))))


class _AnomalousEstimator:
    def predict_proba(self, rows):
        return np.column_stack((np.zeros(len(rows)), np.ones(len(rows))))


class PulseRuntimeHistoryTests(unittest.TestCase):
    def _runtime(self, anomalous=False, with_policy=False):
        columns = ["f0", "f1"]
        model = PulseExtraTrees(history=2, alpha=0.1)
        model.estimator = _AnomalousEstimator() if anomalous else _NormalEstimator()
        if anomalous:
            model.alpha = 0.5
        model.calibration_scores = np.asarray([0.1, 0.2], dtype=np.float32)
        model.feature_dim = 2
        runtime = PulseRuntime.__new__(PulseRuntime)
        runtime.history_size = 2
        runtime.max_contiguous_gap_seconds = 1.5
        runtime.model_manifest_sha256 = "a" * 64
        runtime.feature_schema_sha256 = schema_digest(columns)
        runtime.models = {"production/catalog:app": model}
        runtime.histories = {}
        runtime.history_metadata = {}
        runtime.decision_policy = None
        runtime.decision_policy_sha256 = None
        if with_policy:
            from sentinel_pulse.decision_policy import load_decision_policy

            policy_path = (
                Path(__file__).resolve().parents[1]
                / "sentinel_pulse" / "protocol" / "decision-policy-semantic-v1.json"
            )
            runtime.decision_policy, runtime.decision_policy_sha256 = (
                load_decision_policy(policy_path)
            )
        return runtime, columns

    def _record(self, columns, window_end, regime="steady", exact_counts=None):
        compact, _schema = compact_record(
            {
                "schema": "sentinel-pulse-feature-v1",
                "columns": columns,
                "vector": np.asarray([window_end, 0.0], dtype=np.float32),
                "workload_key": "production/catalog:app",
                "cgroup_id": 7,
                "node_name": "worker-a",
                "pod_uid": "pod-a",
                "pod_name": "catalog-a",
                "container_name": "app",
                "traffic_regime": regime,
                "window_start": window_end - 1.0,
                "window_end": window_end,
                "exact_counts": exact_counts or {},
            }
        )
        return compact

    def test_runtime_resets_history_on_gap_and_regime_change(self):
        runtime, columns = self._runtime()
        self.assertEqual(runtime.score(self._record(columns, 1.0))["status"], "warming")
        self.assertEqual(runtime.score(self._record(columns, 2.0))["status"], "warming")
        self.assertEqual(runtime.score(self._record(columns, 3.0))["status"], "normal")

        gap = runtime.score(self._record(columns, 10.0))
        self.assertEqual(gap["status"], "warming")
        self.assertEqual(gap["warming_reason"], "temporal_gap")
        runtime.score(self._record(columns, 11.0))
        changed = runtime.score(self._record(columns, 12.0, regime="toolmix"))
        self.assertEqual(changed["status"], "warming")
        self.assertEqual(changed["warming_reason"], "traffic_regime_change")

    def test_runtime_rejects_non_monotonic_source_window(self):
        runtime, columns = self._runtime()
        runtime.score(self._record(columns, 2.0))
        with self.assertRaisesRegex(ValueError, "non-monotonic live feature"):
            runtime.score(self._record(columns, 2.0))

    def test_same_window_policy_retains_raw_anomaly_but_suppresses_uncorroborated_alert(self):
        runtime, columns = self._runtime(anomalous=True, with_policy=True)
        warming = runtime.score(self._record(columns, 1.0))
        self.assertEqual(
            warming["decision_policy_sha256"], runtime.decision_policy_sha256
        )
        runtime.score(self._record(columns, 2.0))
        decision = runtime.score(
            self._record(columns, 3.0, exact_counts={"openat": 3, "read": 20})
        )
        self.assertEqual(decision["status"], "suppressed")
        self.assertTrue(decision["raw_model_anomalous"])
        self.assertFalse(decision["same_window_corroborated"])
        self.assertEqual(decision["security_activity_mass"], 0)
        self.assertEqual(len(decision["decision_policy_sha256"]), 64)

    def test_same_window_policy_alerts_corroborated_ml_anomaly_without_extra_window(self):
        runtime, columns = self._runtime(anomalous=True, with_policy=True)
        runtime.score(self._record(columns, 1.0))
        runtime.score(self._record(columns, 2.0))
        decision = runtime.score(
            self._record(columns, 3.0, exact_counts={"connect": 6})
        )
        self.assertEqual(decision["status"], "alert")
        self.assertTrue(decision["same_window_corroborated"])
        self.assertEqual(decision["security_activity_mass"], 6)
        self.assertEqual(decision["security_activity_fields"], {"connect": 6})


if __name__ == "__main__":
    unittest.main()
