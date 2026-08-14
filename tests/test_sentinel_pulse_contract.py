import tempfile
import unittest
from pathlib import Path
import subprocess
import sys

from sentinel_pulse.prepare_contract import prepare


class PulseContractTests(unittest.TestCase):
    def test_package_import_does_not_eagerly_import_numpy(self):
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                "import sentinel_pulse,sys; "
                "assert 'numpy' not in sys.modules; "
                "assert 'sentinel_pulse.features' not in sys.modules",
            ],
            check=False,
        )
        self.assertEqual(result.returncode, 0)

    def test_absolute_schedule_is_frozen_with_transition_gaps(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "contract.json"
            contract = prepare(path, "pulse-c1", 1000.0, 300, 30, ["worker-a"])
            self.assertEqual(
                [item["regime"] for item in contract["intervals"]],
                ["steady", "toolmix", "burst", "recovery"],
            )
            self.assertEqual(contract["intervals"][1]["start"], 1330.0)
            with self.assertRaisesRegex(ValueError, "overwrite"):
                prepare(path, "pulse-c2", 2000.0, 300, 30, ["worker-a"])


if __name__ == "__main__":
    unittest.main()
