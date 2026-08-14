import unittest

import numpy as np

from sentinel_pulse.encoding import compact_record, decode_vector


class PulseEncodingTests(unittest.TestCase):
    def test_compact_round_trip_is_float32_exact(self):
        source = np.linspace(0, 1, 249, dtype=np.float32)
        compact, schema = compact_record({"columns": [f"f{i}" for i in range(249)], "vector": source})
        restored = decode_vector(compact)
        np.testing.assert_array_equal(restored, source)
        self.assertEqual(compact["feature_schema_sha256"], schema["feature_schema_sha256"])
        self.assertNotIn("columns", compact)


if __name__ == "__main__":
    unittest.main()
