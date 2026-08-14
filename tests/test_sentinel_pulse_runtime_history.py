import unittest

import numpy as np

from sentinel_pulse.detect import PulseRuntime
from sentinel_pulse.encoding import compact_record, schema_digest
from sentinel_pulse.model import PulseExtraTrees


class _NormalEstimator:
    def predict_proba(self, rows):
        return np.column_stack((np.ones(len(rows)), np.zeros(len(rows))))


class PulseRuntimeHistoryTests(unittest.TestCase):
    def _runtime(self):
        columns = ["f0", "f1"]
        model = PulseExtraTrees(history=2, alpha=0.1)
        model.estimator = _NormalEstimator()
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
        return runtime, columns

    def _record(self, columns, window_end, regime="steady"):
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


if __name__ == "__main__":
    unittest.main()
