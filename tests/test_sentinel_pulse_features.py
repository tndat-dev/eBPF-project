import unittest

import numpy as np

from sentinel_pulse.features import PulseFeatureBuilder, PulseSnapshot
from sentinel_pulse.capture import SnapshotAssembler


class PulseFeatureBuilderTests(unittest.TestCase):
    def test_uses_exact_deltas_and_keeps_transition_distribution(self):
        builder = PulseFeatureBuilder(rolling_windows=3, transition_bins=16)
        first = PulseSnapshot(7, 10.0, {0: 100, 42: 2}, {(0, 0): 90, (0, 42): 2})
        second = PulseSnapshot(7, 11.0, {0: 5100, 42: 5}, {(0, 0): 5080, (0, 42): 5})
        self.assertIsNone(builder.ingest(first, "production/catalog-service"))
        feature = builder.ingest(second, "production/catalog-service")
        self.assertEqual(feature.exact_counts["read"], 5000)
        self.assertEqual(feature.exact_counts["connect"], 3)
        self.assertEqual(feature.exact_total, 5003)
        transition = feature.vector[[i for i, name in enumerate(feature.columns) if name.startswith("transition_bin:")]]
        self.assertAlmostEqual(float(transition.sum()), 1.0, places=6)
        syscall_bins = feature.vector[[i for i, name in enumerate(feature.columns) if name.startswith("syscall_bin:")]]
        self.assertAlmostEqual(float(syscall_bins.sum()), 1.0, places=6)

    def test_counter_reset_does_not_create_negative_features(self):
        builder = PulseFeatureBuilder()
        builder.ingest(PulseSnapshot(8, 1.0, {0: 100}, {}), "w")
        feature = builder.ingest(PulseSnapshot(8, 2.0, {0: 4}, {}), "w")
        self.assertEqual(feature.exact_counts["read"], 4)
        self.assertTrue(np.all(feature.vector >= 0))

    def test_rejects_non_monotonic_snapshot(self):
        builder = PulseFeatureBuilder()
        builder.ingest(PulseSnapshot(9, 2.0, {1: 3}, {}), "w")
        self.assertIsNone(builder.ingest(PulseSnapshot(9, 2.0, {1: 4}, {}), "w"))

    def test_collector_drop_counters_survive_snapshot_assembly(self):
        assembler = SnapshotAssembler()
        assembler.add({"type": "count", "cgroup_id": 2, "syscall_id": 0, "cumulative": 3})
        assembler.add({"type": "stat", "name": "count_insert_fail", "cumulative": 0})
        snapshots, stats = assembler.snapshots(5.0)
        self.assertEqual(len(snapshots), 1)
        self.assertEqual(stats["count_insert_fail"], 0)

    def test_preaggregated_kernel_bins_define_exact_total(self):
        builder = PulseFeatureBuilder(syscall_bins=8, transition_bins=8)
        builder.ingest(PulseSnapshot(3, 1.0, {0: 2}, {}, {0: 100}, {1: 90}), "w")
        feature = builder.ingest(PulseSnapshot(3, 2.0, {0: 4}, {}, {0: 5100, 1: 3}, {1: 5080, 2: 2}), "w")
        self.assertEqual(feature.exact_total, 5003)
        syscall_bins = feature.vector[[i for i, name in enumerate(feature.columns) if name.startswith("syscall_bin:")]]
        self.assertAlmostEqual(float(syscall_bins.sum()), 1.0, places=6)

    def test_compact_snapshot_is_parsed_and_integrity_checked(self):
        assembler = SnapshotAssembler()
        record = {
            "type": "cgroup_snapshot",
            "cgroup_id": 4,
            "total": 5,
            "counts": {"0": 5},
            "syscall_bins": [5] + [0] * 63,
            "transition_bins": [4] + [0] * 63,
        }
        assembler.add(record)
        snapshots, stats = assembler.snapshots(2.0)
        self.assertEqual(snapshots[0].syscall_bins[0], 5)
        self.assertEqual(stats.get("snapshot_total_mismatch", 0), 0)

    def test_target_snapshot_gap_is_a_loss_signal(self):
        assembler = SnapshotAssembler()
        assembler.stats["target_snapshot_gap"] = 2
        _snapshots, stats = assembler.snapshots(2.0)
        self.assertEqual(stats["target_snapshot_gap"], 2)


if __name__ == "__main__":
    unittest.main()
