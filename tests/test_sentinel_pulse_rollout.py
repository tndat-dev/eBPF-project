import json
import tempfile
import unittest
from pathlib import Path

from sentinel_pulse.validate_rollout import validate


class PulseRolloutTests(unittest.TestCase):
    def test_validates_node_identity_and_workload_union(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            reports = []
            for index, node in enumerate(("worker-a", "worker-b")):
                path = root / f"{node}.json"
                path.write_text(
                    json.dumps(
                        {
                            "schema": "sentinel-pulse-collect-smoke-v1",
                            "valid": True,
                            "node_names": [node],
                            "rows": 120,
                            "workloads": {
                                f"production/workload-{index}:app": 120
                            },
                        }
                    ),
                    encoding="utf-8",
                )
                reports.append(path)
            result = validate(
                reports,
                expected_nodes={"worker-a", "worker-b"},
                required_workloads={"workload-0", "workload-1"},
            )
            self.assertTrue(result["valid"], result)

    def test_rejects_duplicate_node_and_missing_workload(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            reports = []
            for index in range(2):
                path = root / f"report-{index}.json"
                path.write_text(
                    json.dumps(
                        {
                            "schema": "sentinel-pulse-collect-smoke-v1",
                            "valid": True,
                            "node_names": ["worker-a"],
                            "rows": 120,
                            "workloads": {"production/only-one:app": 120},
                        }
                    ),
                    encoding="utf-8",
                )
                reports.append(path)
            result = validate(
                reports,
                expected_nodes={"worker-a", "worker-b"},
                required_workloads={"only-one", "missing"},
            )
            self.assertFalse(result["valid"])
            self.assertTrue(any("duplicate" in error for error in result["errors"]))
            self.assertTrue(any("missing" in error for error in result["errors"]))


if __name__ == "__main__":
    unittest.main()
