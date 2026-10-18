import tempfile
import unittest
from pathlib import Path

import numpy as np

from sentinel_pulse.integrity import contained_artifact, sha256_file, verify_sha256


class _PickleEstimator:
    def predict_proba(self, rows):
        return np.column_stack((np.ones(len(rows)), np.zeros(len(rows))))


class PulseIntegrityTests(unittest.TestCase):
    def test_checksum_and_containment_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifact = root / "model.pkl"
            artifact.write_bytes(b"candidate")
            verify_sha256(artifact, sha256_file(artifact))
            with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                verify_sha256(artifact, "0" * 64)
            with self.assertRaisesRegex(ValueError, "unsafe artifact path"):
                contained_artifact(root, "../model.pkl")



if __name__ == "__main__":
    unittest.main()
