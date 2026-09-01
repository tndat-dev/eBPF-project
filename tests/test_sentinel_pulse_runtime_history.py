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


class _MarginalAnomalousEstimator:
    def predict_proba(self, rows):
        probability = np.full(len(rows), 0.205)
        return np.column_stack((1.0 - probability, probability))


class PulseRuntimeHistoryTests(unittest.TestCase):
    def _runtime(
        self, anomalous=False, with_policy=False, score_policy=False,
        temporal_policy=False, eligible_temporal_groups=None,
    ):
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
        runtime.temporal_evidence = {}
        runtime.decision_policy = None
        runtime.decision_policy_sha256 = None
        if with_policy:
            from sentinel_pulse.decision_policy import load_decision_policy

            policy_path = (
                Path(__file__).resolve().parents[1]
                / "sentinel_pulse"
                / "protocol"
                / (
                    "decision-policy-semantic-v2.json"
                    if score_policy
                    else "decision-policy-semantic-v1.json"
                )
            )
            runtime.decision_policy, runtime.decision_policy_sha256 = (
                load_decision_policy(policy_path)
            )
            if temporal_policy:
                runtime.decision_policy["bounded_event_time_corroboration"] = {
                    "mode": "bounded_model_semantic_join",
                    "maximum_evidence_age_seconds": 1.0,
                    "requires_raw_model_anomaly": True,
                    "requires_score_corroboration": True,
                    "requires_semantic_corroboration": True,
                    "consume_on_alert": True,
                    "normal_only_calibration": True,
                }
                if eligible_temporal_groups is not None:
                    runtime.decision_policy["bounded_event_time_corroboration"][
                        "eligible_semantic_signal_groups"
                    ] = eligible_temporal_groups
        return runtime, columns

    def test_v2_policy_suppresses_raw_tail_inside_operational_score_margin(self):
        runtime, columns = self._runtime(
            anomalous=True, with_policy=True, score_policy=True
        )
        runtime.models["production/catalog:app"].estimator = _MarginalAnomalousEstimator()
        runtime.score(self._record(columns, 1.0))
        runtime.score(self._record(columns, 2.0))
        decision = runtime.score(
            self._record(columns, 3.0, exact_counts={"connect": 6})
        )
        self.assertTrue(decision["raw_model_anomalous"])
        self.assertTrue(decision["semantic_corroborated"])
        self.assertFalse(decision["score_corroborated"])
        self.assertEqual(decision["status"], "suppressed")
        self.assertAlmostEqual(decision["score_excess_over_calibration_max"], 0.005)

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
        self.assertEqual(gap["schema"], "sentinel-pulse-decision-v1")
        self.assertEqual(gap["warming_reason"], "temporal_gap")
        self.assertEqual(gap["node_name"], "worker-a")
        self.assertEqual(gap["pod_uid"], "pod-a")
        self.assertEqual(gap["container_name"], "app")
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

    def test_bounded_event_time_join_alerts_without_waiting_for_third_window(self):
        runtime, columns = self._runtime(
            anomalous=True, with_policy=True, score_policy=True,
            temporal_policy=True,
        )
        runtime.score(self._record(columns, 1.0))
        runtime.score(self._record(columns, 2.0))
        model_only = runtime.score(self._record(columns, 3.0))
        self.assertEqual(model_only["status"], "suppressed")
        runtime.models["production/catalog:app"].estimator = _NormalEstimator()
        joined = runtime.score(
            self._record(columns, 3.5, exact_counts={"connect": 6})
        )
        self.assertEqual(joined["status"], "alert")
        self.assertFalse(joined["raw_model_anomalous"])
        self.assertTrue(joined["bounded_event_time_corroborated"])
        self.assertEqual(joined["evidence_span_seconds"], 0.5)
        self.assertEqual(joined["model_evidence_score"], 1.0)
        self.assertEqual(joined["semantic_evidence_security_activity_mass"], 6)
        self.assertEqual(joined["semantic_evidence_triggered_groups"], [])
        self.assertEqual(runtime.temporal_evidence, {})

    def test_risk_tiered_join_does_not_carry_ineligible_group_across_windows(self):
        runtime, columns = self._runtime(
            anomalous=True, with_policy=True, score_policy=True,
            temporal_policy=True,
            eligible_temporal_groups=["namespace_probe"],
        )
        runtime.score(self._record(columns, 1.0))
        runtime.score(self._record(columns, 2.0))
        model_only = runtime.score(self._record(columns, 3.0))
        self.assertEqual(model_only["status"], "suppressed")
        runtime.models["production/catalog:app"].estimator = _NormalEstimator()
        ineligible = runtime.score(
            self._record(columns, 3.5, exact_counts={"connect": 6})
        )
        self.assertNotEqual(ineligible["status"], "alert")
        self.assertFalse(ineligible["bounded_event_time_corroborated"])
        self.assertEqual(ineligible["eligible_temporal_semantic_groups"], ["namespace_probe"])

    def test_risk_tiered_policy_keeps_same_window_alert_for_ineligible_group(self):
        runtime, columns = self._runtime(
            anomalous=True, with_policy=True, score_policy=True,
            temporal_policy=True,
            eligible_temporal_groups=["namespace_probe"],
        )
        runtime.score(self._record(columns, 1.0))
        runtime.score(self._record(columns, 2.0))
        decision = runtime.score(
            self._record(columns, 3.0, exact_counts={"connect": 6})
        )
        self.assertEqual(decision["status"], "alert")
        self.assertTrue(decision["same_window_corroborated"])

    def test_bounded_event_time_join_expires_and_resets_on_gap(self):
        runtime, columns = self._runtime(
            anomalous=True, with_policy=True, score_policy=True,
            temporal_policy=True,
        )
        runtime.score(self._record(columns, 1.0))
        runtime.score(self._record(columns, 2.0))
        runtime.score(self._record(columns, 3.0))
        runtime.models["production/catalog:app"].estimator = _NormalEstimator()
        expired = runtime.score(
            self._record(columns, 4.2, exact_counts={"connect": 6})
        )
        self.assertNotEqual(expired["status"], "alert")
        reset = runtime.score(
            self._record(columns, 10.0, exact_counts={"connect": 6})
        )
        self.assertEqual(reset["status"], "warming")
        self.assertEqual(reset["warming_reason"], "temporal_gap")
        self.assertEqual(runtime.temporal_evidence, {})


if __name__ == "__main__":
    unittest.main()
