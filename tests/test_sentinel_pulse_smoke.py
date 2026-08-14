import json
import tempfile
import unittest
from pathlib import Path

from sentinel_pulse.encoding import compact_record
from sentinel_pulse.smoke_collect import smoke


class PulseSmokeTests(unittest.TestCase):
    def _capture(self, path: Path, drop: int = 0) -> None:
        rows = []
        header_written = False
        for second in range(1000, 1122):
            record, header = compact_record(
                {
                    "schema": "sentinel-pulse-feature-v1",
                    "columns": ["f0", "f1"],
                    "vector": [1.0, 2.0],
                    "workload_key": "production/catalog:app",
                    "cgroup_id": 7,
                    "node_name": "worker-a",
                    "pod_uid": "pod-a",
                    "container_name": "app",
                    "window_start": float(second - 1),
                    "window_end": float(second),
                    "exact_counts": {"read": 1},
                    "exact_total": 1,
                    "emitted_at": float(second) + 0.02,
                    "snapshot_read_seconds": 0.01,
                    "collector_stats": {
                        "count_insert_fail": drop,
                        "transition_insert_fail": 0,
                        "task_state_update_fail": 0,
                        "snapshot_total_mismatch": 0,
                        "target_snapshot_gap": 0,
                    },
                }
            )
            if not header_written:
                rows.append(header)
                header_written = True
            rows.append(record)
        path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")

    def test_recent_lossless_slice_passes(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "features.jsonl"
            self._capture(path)
            report = smoke(path, duration_seconds=120, now=1123.0)
            self.assertTrue(report["valid"], report)
            self.assertEqual(report["node_names"], ["worker-a"])
            self.assertTrue(report["gates"]["single_node_identity"])

    def test_collector_loss_fails_canary(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "features.jsonl"
            self._capture(path, drop=1)
            report = smoke(path, duration_seconds=120, now=1123.0)
            self.assertFalse(report["valid"])
            self.assertFalse(report["gates"]["capture_integrity"])


if __name__ == "__main__":
    unittest.main()
