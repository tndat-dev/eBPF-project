import unittest

from sentinel_pulse.cluster_health import unhealthy_nodes, unhealthy_pods


def pod(name, phase, created, ready=None):
    status = {"phase": phase}
    if ready is not None:
        status["containerStatuses"] = [{"name": "app", "ready": ready}]
    return {
        "metadata": {
            "namespace": "production",
            "name": name,
            "creationTimestamp": created,
        },
        "status": status,
    }


class PulseClusterHealthTests(unittest.TestCase):
    def test_new_pending_job_is_inside_grace_but_stale_pending_is_bad(self):
        payload = {
            "items": [
                pod("new-job", "Pending", "1970-01-01T00:15:00Z"),
                pod("stale", "Pending", "1970-01-01T00:00:00Z"),
            ]
        }
        bad = unhealthy_pods(payload, now=1000.0, grace_seconds=300.0)
        self.assertEqual([item["pod"] for item in bad], ["stale"])

    def test_old_running_unready_pod_is_bad_and_ready_pod_passes(self):
        payload = {
            "items": [
                pod("crashing", "Running", "1970-01-01T00:00:00Z", False),
                pod("healthy", "Running", "1970-01-01T00:00:00Z", True),
            ]
        }
        bad = unhealthy_pods(payload, now=1000.0, grace_seconds=300.0)
        self.assertEqual([item["pod"] for item in bad], ["crashing"])

    def test_failed_pod_is_immediately_bad_and_succeeded_job_passes(self):
        payload = {
            "items": [
                pod("failed", "Failed", "1970-01-01T00:16:39Z"),
                pod("done", "Succeeded", "1970-01-01T00:00:00Z"),
            ]
        }
        bad = unhealthy_pods(payload, now=1000.0, grace_seconds=300.0)
        self.assertEqual([item["reason"] for item in bad], ["failed"])

    def test_ready_node_with_disk_pressure_is_unhealthy(self):
        payload = {
            "items": [
                {
                    "metadata": {"name": "worker3"},
                    "spec": {
                        "taints": [
                            {
                                "key": "node.kubernetes.io/disk-pressure",
                                "effect": "NoSchedule",
                            }
                        ]
                    },
                    "status": {
                        "conditions": [
                            {"type": "Ready", "status": "True"},
                            {"type": "DiskPressure", "status": "True"},
                            {"type": "MemoryPressure", "status": "False"},
                            {"type": "PIDPressure", "status": "False"},
                        ]
                    },
                }
            ]
        }
        bad = unhealthy_nodes(payload)
        self.assertEqual([item["node"] for item in bad], ["worker3"])
        self.assertIn("DiskPressure=True", bad[0]["reasons"])
        self.assertIn("taint:node.kubernetes.io/disk-pressure", bad[0]["reasons"])

    def test_ready_pressure_free_node_is_healthy(self):
        payload = {
            "items": [
                {
                    "metadata": {"name": "worker1"},
                    "spec": {},
                    "status": {
                        "conditions": [
                            {"type": "Ready", "status": "True"},
                            {"type": "DiskPressure", "status": "False"},
                            {"type": "MemoryPressure", "status": "False"},
                            {"type": "PIDPressure", "status": "False"},
                        ]
                    },
                }
            ]
        }
        self.assertEqual(unhealthy_nodes(payload), [])


if __name__ == "__main__":
    unittest.main()
