import tempfile
import threading
import time
import unittest
from pathlib import Path

from sentinel_pulse.detect import RotatingJsonlFollower


class PulseFollowerTests(unittest.TestCase):
    def test_follower_reopens_atomic_replacement_from_beginning(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "features.jsonl"
            path.write_text("old-row\n", encoding="utf-8")
            follower = RotatingJsonlFollower(path, from_start=True, poll_seconds=0)
            self.assertEqual(follower.readline(), "old-row\n")

            path.replace(path.with_suffix(".frozen"))
            path.write_text("new-schema\nnew-row\n", encoding="utf-8")
            self.assertEqual(follower.readline(), "new-schema\n")
            self.assertEqual(follower.readline(), "new-row\n")
            follower.close()

    def test_initial_tail_skips_old_rows_but_reads_rotated_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "features.jsonl"
            path.write_text("old-row\n", encoding="utf-8")
            follower = RotatingJsonlFollower(path, from_start=False, poll_seconds=0)
            self.assertTrue(follower._open())

            path.replace(path.with_suffix(".frozen"))
            path.write_text("new-row\n", encoding="utf-8")
            self.assertEqual(follower.readline(), "new-row\n")
            follower.close()

    def test_follower_waits_for_terminating_newline_before_returning_json(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "features.jsonl"
            path.write_text('{"schema":"sentinel-pulse-feature-v1"', encoding="utf-8")
            follower = RotatingJsonlFollower(path, from_start=True, poll_seconds=0.001)

            def finish_record():
                time.sleep(0.02)
                with path.open("a", encoding="utf-8") as output:
                    output.write('}\n')

            writer = threading.Thread(target=finish_record)
            writer.start()
            self.assertEqual(
                follower.readline(),
                '{"schema":"sentinel-pulse-feature-v1"}\n',
            )
            writer.join(timeout=1)
            follower.close()


if __name__ == "__main__":
    unittest.main()
