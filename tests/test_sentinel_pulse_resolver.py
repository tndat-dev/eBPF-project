import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sentinel_pulse.cgroup_resolver import infer_role, infer_workload_name, resolve_cgroups


class PulseResolverTests(unittest.TestCase):
    def test_role_resolution(self):
        self.assertEqual(infer_role("aims-kafka-dual-role-0"), "kafka-broker")
        self.assertEqual(infer_role("aims-redis-sentinel-sentinel-0"), "redis-sentinel")
        self.assertEqual(infer_role("catalog-service-deadbeef"), "stateless-http")
        self.assertEqual(infer_workload_name("catalog-service-74cf5f59b9-h944d"), "catalog-service")
        self.assertEqual(infer_workload_name("aims-kafka-dual-role-2"), "aims-kafka-dual-role")

    def test_includes_leaf_container_cgroup(self):
        pod = {"pod_uid": "1234-abcd", "pod_name": "catalog-service-x", "namespace": "production", "role": "stateless-http"}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pod_path = root / "kubepods-pod1234_abcd.slice"
            leaf = pod_path / "cri-containerd-test.scope"
            leaf.mkdir(parents=True)
            found = resolve_cgroups([pod], root, [{"pod_uid": "1234-abcd", "container_id": "test", "container_name": "app"}])
            paths = {item["cgroup_path"] for item in found.values()}
            self.assertIn(str(pod_path), paths)
            self.assertIn(str(leaf), paths)
            leaf_item = next(value for value in found.values() if value["cgroup_path"] == str(leaf))
            self.assertEqual(leaf_item["container_name"], "app")


if __name__ == "__main__":
    unittest.main()
