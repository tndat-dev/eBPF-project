import json
import tempfile
import unittest
from pathlib import Path

import numpy as np

from sentinel_pulse.assemble_dataset import assemble
from sentinel_pulse.encoding import compact_record
from sentinel_pulse.integrity import sha256_file
from sentinel_pulse.train import load_dataset_manifest


class PulseDatasetAssemblyTests(unittest.TestCase):
    def _source(self, path: Path, node: str, times: tuple[float, ...]) -> None:
        records = []
        header_written = False
        for end in times:
            row, header = compact_record(
                {
                    "schema": "sentinel-pulse-feature-v1",
                    "columns": ["f0", "f1"],
                    "vector": np.asarray([1.0, end], dtype=np.float32),
                    "node_name": node,
                    "pod_uid": f"pod-{node}",
                    "container_name": "app",
                    "cgroup_id": 1,
                    "workload_key": "production/catalog:app",
                    "window_start": end - 1.0,
                    "window_end": end,
                }
            )
            if not header_written:
                records.append(header)
                header_written = True
            records.append(row)
        path.write_text("".join(json.dumps(record) + "\n" for record in records), encoding="utf-8")

    def _manifest(
        self,
        path: Path,
        source: Path,
        contract: Path,
        node: str,
        rows: int,
        in_contract_rows: int,
        start: float = 10.0,
        end: float = 30.0,
    ) -> None:
        source.chmod(0o444)
        path.write_text(
            json.dumps(
                {
                    "schema": "sentinel-pulse-node-capture-manifest-v1",
                    "campaign_id": "pulse-c1",
                    "contract_sha256": sha256_file(contract),
                    "node_name": node,
                    "capture_sha256": sha256_file(source),
                    "capture_bytes": source.stat().st_size,
                    "rows": rows,
                    "in_contract_rows": in_contract_rows,
                    "campaign_start": start,
                    "campaign_end": end,
                    "collector_max_integrity": {"target_snapshot_gap": 0},
                }
            ),
            encoding="utf-8",
        )

    def test_assembly_filters_contract_and_labels_regime(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            contract = root / "contract.json"
            contract.write_text(
                json.dumps(
                    {
                        "schema": "sentinel-pulse-capture-contract-v1",
                        "campaign_id": "pulse-c1",
                        "normal_only": True,
                        "expected_nodes": ["worker-a", "worker-b"],
                        "intervals": [
                            {"regime": "steady", "start": 10.0, "end": 20.0},
                            {"regime": "burst", "start": 20.0, "end": 30.0},
                        ],
                    }
                ), encoding="utf-8"
            )
            left, right = root / "left.jsonl", root / "right.jsonl"
            self._source(left, "worker-a", (9.0, 11.0, 21.0))
            self._source(right, "worker-b", (12.0, 22.0, 31.0))
            left_manifest = root / "left-manifest.json"
            right_manifest = root / "right-manifest.json"
            self._manifest(left_manifest, left, contract, "worker-a", 3, 2)
            self._manifest(right_manifest, right, contract, "worker-b", 3, 2)
            output = root / "dataset.jsonl"
            manifest = assemble(
                contract,
                {"worker-a": left, "worker-b": right},
                {"worker-a": left_manifest, "worker-b": right_manifest},
                output,
            )
            self.assertEqual(manifest["rows"], 4)
            self.assertEqual(manifest["excluded_outside_contract"], 2)
            self.assertEqual(manifest["rows_by_regime"], {"burst": 2, "steady": 2})
            rows = [json.loads(line) for line in output.read_text().splitlines()]
            features = [row for row in rows if row.get("schema") == "sentinel-pulse-feature-v1"]
            self.assertEqual({row["campaign_id"] for row in features}, {"pulse-c1"})
            manifest_path, loaded = load_dataset_manifest(output)
            self.assertTrue(manifest_path.is_file())
            self.assertEqual(loaded["campaign_id"], "pulse-c1")

            output.write_text(output.read_text() + "\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "hash differs"):
                load_dataset_manifest(output)

    def test_node_identity_mismatch_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            contract = root / "contract.json"
            contract.write_text(
                json.dumps(
                    {
                        "schema": "sentinel-pulse-capture-contract-v1",
                        "campaign_id": "pulse-c1",
                        "normal_only": True,
                        "expected_nodes": ["worker-a"],
                        "intervals": [{"regime": "steady", "start": 0.0, "end": 10.0}],
                    }
                ), encoding="utf-8"
            )
            source = root / "source.jsonl"
            self._source(source, "worker-b", (2.0,))
            source_manifest = root / "source-manifest.json"
            self._manifest(
                source_manifest, source, contract, "worker-a", 1, 1, start=0.0, end=10.0
            )
            with self.assertRaisesRegex(ValueError, "node identity"):
                assemble(
                    contract,
                    {"worker-a": source},
                    {"worker-a": source_manifest},
                    root / "dataset.jsonl",
                )

    def test_v1_manifest_span_count_may_include_transition_gap(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            contract = root / "contract.json"
            contract.write_text(
                json.dumps(
                    {
                        "schema": "sentinel-pulse-capture-contract-v1",
                        "campaign_id": "pulse-c1",
                        "normal_only": True,
                        "expected_nodes": ["worker-a"],
                        "intervals": [
                            {"regime": "steady", "start": 10.0, "end": 20.0},
                            {"regime": "burst", "start": 30.0, "end": 40.0},
                        ],
                    }
                ),
                encoding="utf-8",
            )
            source = root / "source.jsonl"
            self._source(source, "worker-a", (11.0, 25.0, 31.0))
            source_manifest = root / "source-manifest.json"
            # V1 finalizers counted all three rows in the broad 10..40 span.
            self._manifest(
                source_manifest, source, contract, "worker-a", 3, 3, start=10.0, end=40.0
            )
            output = root / "dataset.jsonl"
            manifest = assemble(
                contract,
                {"worker-a": source},
                {"worker-a": source_manifest},
                output,
            )
            self.assertEqual(manifest["rows"], 2)
            self.assertEqual(manifest["excluded_outside_contract"], 1)
            self.assertEqual(manifest["campaign_span_rows_by_node"], {"worker-a": 3})
            self.assertEqual(
                manifest["source_manifest_schema"]["worker-a"],
                "sentinel-pulse-node-capture-manifest-v1",
            )

    def test_capture_manifest_hash_mismatch_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            contract = root / "contract.json"
            contract.write_text(
                json.dumps(
                    {
                        "schema": "sentinel-pulse-capture-contract-v1",
                        "campaign_id": "pulse-c1",
                        "normal_only": True,
                        "expected_nodes": ["worker-a"],
                        "intervals": [{"regime": "steady", "start": 10.0, "end": 30.0}],
                    }
                ),
                encoding="utf-8",
            )
            source = root / "source.jsonl"
            self._source(source, "worker-a", (11.0,))
            source_manifest = root / "source-manifest.json"
            self._manifest(source_manifest, source, contract, "worker-a", 1, 1)
            document = json.loads(source_manifest.read_text(encoding="utf-8"))
            document["capture_sha256"] = "0" * 64
            source_manifest.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "provenance mismatch"):
                assemble(
                    contract,
                    {"worker-a": source},
                    {"worker-a": source_manifest},
                    root / "dataset.jsonl",
                )


if __name__ == "__main__":
    unittest.main()
