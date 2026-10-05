import argparse
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from sentinel_pulse.node_clock_probe import clock_delta, positive_finite, run, sample


class NodeClockProbeTests(unittest.TestCase):
    def clocks(self, real, mono, boot=None):
        return {"realtime": real, "monotonic": mono,
                "boottime": mono if boot is None else boot}

    def test_normal_interval(self):
        delta = clock_delta(self.clocks(100, 10), self.clocks(101, 11), 1)
        self.assertFalse(delta["observer_late"])
        self.assertFalse(delta["clock_offset_changed"])

    def test_node_or_observer_stall_is_not_a_clock_step(self):
        delta = clock_delta(self.clocks(100, 10), self.clocks(110, 20), 1)
        self.assertTrue(delta["observer_late"])
        self.assertFalse(delta["clock_offset_changed"])

    def test_wall_clock_step_not_mislabeled_scheduler_delay(self):
        delta = clock_delta(self.clocks(100, 10), self.clocks(111, 11), 1)
        self.assertFalse(delta["observer_late"])
        self.assertTrue(delta["clock_offset_changed"])

    def test_suspend_difference_retained(self):
        delta = clock_delta(self.clocks(100, 10, 20), self.clocks(106, 11, 26), 1)
        self.assertEqual(delta["boottime_minus_monotonic_seconds"], 5)

    def test_missing_psi_is_explicit(self):
        with patch.object(Path, "read_text", side_effect=PermissionError("denied")):
            row = sample()
        self.assertEqual(set(row["read_errors"]), {"cpu", "io", "memory"})
        self.assertEqual(row["pressure"], {})

    def test_reject_bad_durations(self):
        for value in ("nan", "inf", "0", "-1"):
            with self.subTest(value=value), self.assertRaises(argparse.ArgumentTypeError):
                positive_finite(value)

    def test_exclusive_output(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "clock.jsonl"
            path.write_text("preserved\n")
            with self.assertRaises(FileExistsError):
                run(path, 0.1, 0.1)
            self.assertEqual(path.read_text(), "preserved\n")

    def test_bounded_run_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "clock.jsonl"
            summary = run(path, 0.15, 0.1)
            rows = [json.loads(line) for line in path.read_text().splitlines()]
        self.assertEqual(rows[0]["purpose"], "infrastructure_diagnostic_only")
        self.assertEqual(rows[-1], summary)
        self.assertGreaterEqual(summary["samples"], 1)
        self.assertEqual(sum(row["record_type"] == "sample" for row in rows), summary["samples"])

    def test_run_bounds(self):
        for duration, interval in ((90001, 1), (0, 1), (1, 0.01), (1, 61), (float("nan"), 1)):
            with self.subTest(duration=duration, interval=interval), self.assertRaises(ValueError):
                run(Path("not-created"), duration, interval)


if __name__ == "__main__":
    unittest.main()
