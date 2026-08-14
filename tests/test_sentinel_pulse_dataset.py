import json
import tempfile
import unittest
from pathlib import Path

import numpy as np

from sentinel_pulse.encoding import compact_record
from sentinel_pulse.train import load_sequences


class PulseDatasetTests(unittest.TestCase):
    def test_same_cgroup_id_on_two_nodes_stays_two_sequences(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "capture.jsonl"
            lines = []
            schema_written = False
            for node, value in (("worker-a", 1.0), ("worker-b", 2.0)):
                for second in range(4):
                    compact, schema = compact_record(
                        {
                            "schema": "sentinel-pulse-feature-v1",
                            "columns": ["f0", "f1"],
                            "vector": np.asarray([value, second], dtype=np.float32),
                            "workload_key": "production/catalog:app",
                            "cgroup_id": 7,
                            "node_name": node,
                            "pod_uid": f"pod-{node}",
                            "container_name": "app",
                            "window_end": float(second),
                        }
                    )
                    if not schema_written:
                        lines.append(schema)
                        schema_written = True
                    lines.append(compact)
            path.write_text("".join(json.dumps(record) + "\n" for record in lines), encoding="utf-8")
            sequences, columns = load_sequences(path)
            workload_sequences = sequences["production/catalog:app"]
            self.assertEqual(columns, ["f0", "f1"])
            self.assertEqual(len(workload_sequences), 2)
            self.assertEqual({sequence[0][0] for sequence in workload_sequences}, {1.0, 2.0})


if __name__ == "__main__":
    unittest.main()
