import json
import tempfile
import unittest
from pathlib import Path

from sentinel_pulse.features import PulseFeatureBuilder, PulseSnapshot
from sentinel_pulse.validate_capture import validate


class PulseCaptureValidationTests(unittest.TestCase):
    def test_accepts_lossless_one_second_capture(self):
        builder = PulseFeatureBuilder()
        builder.ingest(PulseSnapshot(1, 1.0, {0: 10}, {}), "production/catalog:app")
        rows = []
        cumulative = 10
        for second in range(2, 7):
            cumulative += 10
            feature = builder.ingest(PulseSnapshot(1, float(second), {0: cumulative}, {}), "production/catalog:app")
            record = feature.as_record()
            record["emitted_at"] = float(second) + 0.01
            record["snapshot_read_seconds"] = 0.012
            record["collector_stats"] = {
                "count_insert_fail": 0,
                "transition_insert_fail": 0,
                "task_state_update_fail": 0,
            }
            rows.append(record)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "capture.jsonl"
            path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
            report = validate(path, minimum_rows_per_workload=5)
        self.assertTrue(report["valid"], report["errors"])
        self.assertLess(report["ingest_lag_seconds"]["p99"], 0.02)
        self.assertLess(report["window_start_to_emit_seconds"]["p99"], 1.02)
        self.assertAlmostEqual(report["snapshot_read_seconds"]["p99"], 0.012)

    def test_rejects_reported_bpf_loss(self):
        builder = PulseFeatureBuilder()
        builder.ingest(PulseSnapshot(1, 1.0, {0: 10}, {}), "w")
        feature = builder.ingest(PulseSnapshot(1, 2.0, {0: 20}, {}), "w")
        record = feature.as_record()
        record["collector_stats"] = {"count_insert_fail": 1}
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "capture.jsonl"
            path.write_text(json.dumps(record) + "\n", encoding="utf-8")
            report = validate(path, minimum_rows_per_workload=1)
        self.assertFalse(report["valid"])
        self.assertTrue(any("collector loss" in error for error in report["errors"]))

    def test_accepts_explicit_half_second_interval_contract(self):
        builder = PulseFeatureBuilder(rolling_windows=10)
        builder.ingest(PulseSnapshot(1, 1.0, {0: 10}, {}), "production/catalog:app")
        rows = []
        cumulative = 10
        for tick in range(1, 6):
            observed_at = 1.0 + tick * 0.5
            cumulative += 5
            feature = builder.ingest(
                PulseSnapshot(1, observed_at, {0: cumulative}, {}),
                "production/catalog:app",
            )
            record = feature.as_record()
            record["emitted_at"] = observed_at + 0.01
            record["collector_stats"] = {}
            rows.append(record)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "capture.jsonl"
            path.write_text(
                "".join(json.dumps(row) + "\n" for row in rows),
                encoding="utf-8",
            )
            report = validate(
                path,
                minimum_rows_per_workload=5,
                interval_min_seconds=0.35,
                interval_max_seconds=0.80,
            )
        self.assertTrue(report["valid"], report["errors"])
        self.assertEqual(
            report["accepted_interval_seconds"],
            {"minimum": 0.35, "maximum": 0.80},
        )
        self.assertLess(report["window_start_to_emit_seconds"]["p99"], 0.52)

    def test_same_cgroup_number_on_different_nodes_is_not_timestamp_drift(self):
        builder_a = PulseFeatureBuilder()
        builder_b = PulseFeatureBuilder()
        builder_a.ingest(PulseSnapshot(7, 10.0, {0: 1}, {}), "w")
        builder_b.ingest(PulseSnapshot(7, 1.0, {0: 1}, {}), "w")
        records = []
        for node, feature in (
            ("worker-a", builder_a.ingest(PulseSnapshot(7, 11.0, {0: 2}, {}), "w")),
            ("worker-b", builder_b.ingest(PulseSnapshot(7, 2.0, {0: 2}, {}), "w")),
        ):
            record = feature.as_record()
            record.update({"node_name": node, "pod_uid": node, "container_name": "app"})
            records.append(record)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "capture.jsonl"
            path.write_text("".join(json.dumps(record) + "\n" for record in records), encoding="utf-8")
            report = validate(path, minimum_rows_per_workload=2)
        self.assertTrue(report["valid"], report["errors"])


if __name__ == "__main__":
    unittest.main()
