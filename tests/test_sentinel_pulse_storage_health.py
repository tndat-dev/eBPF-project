import unittest

from sentinel_pulse.storage_health import (
    colocated_running_replicas,
    duplicate_disk_uuids,
)


class PulseStorageHealthTests(unittest.TestCase):
    def test_duplicate_longhorn_disk_uuid_is_rejected(self):
        payload = {
            "items": [
                {
                    "metadata": {"name": "worker3"},
                    "status": {"diskStatus": {"disk-a": {"diskUUID": "same"}}},
                },
                {
                    "metadata": {"name": "worker4"},
                    "status": {"diskStatus": {"disk-b": {"diskUUID": "same"}}},
                },
            ]
        }
        self.assertEqual(
            duplicate_disk_uuids(payload),
            [
                {
                    "reason": "duplicate_disk_uuid",
                    "disk_uuid": "same",
                    "nodes": ["worker3", "worker4"],
                }
            ],
        )

    def test_unique_or_missing_disk_uuid_passes(self):
        payload = {
            "items": [
                {
                    "metadata": {"name": "worker1"},
                    "status": {"diskStatus": {"a": {"diskUUID": "one"}}},
                },
                {
                    "metadata": {"name": "worker2"},
                    "status": {"diskStatus": {"b": {"diskUUID": "two"}}},
                },
            ]
        }
        self.assertEqual(duplicate_disk_uuids(payload), [])

    def test_two_running_replicas_on_one_manager_are_rejected(self):
        payload = {
            "items": [
                {
                    "metadata": {"name": "replica-a"},
                    "spec": {"volumeName": "volume-a"},
                    "status": {
                        "currentState": "running",
                        "instanceManagerName": "manager-worker3",
                    },
                },
                {
                    "metadata": {"name": "replica-b"},
                    "spec": {"volumeName": "volume-a"},
                    "status": {
                        "currentState": "running",
                        "instanceManagerName": "manager-worker3",
                    },
                },
            ]
        }
        issues = colocated_running_replicas(payload)
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0]["volume"], "volume-a")

    def test_replicas_on_distinct_managers_pass(self):
        payload = {
            "items": [
                {
                    "metadata": {"name": "replica-a"},
                    "spec": {"volumeName": "volume-a"},
                    "status": {
                        "currentState": "running",
                        "instanceManagerName": "manager-worker3",
                    },
                },
                {
                    "metadata": {"name": "replica-b"},
                    "spec": {"volumeName": "volume-a"},
                    "status": {
                        "currentState": "running",
                        "instanceManagerName": "manager-worker4",
                    },
                },
            ]
        }
        self.assertEqual(colocated_running_replicas(payload), [])


if __name__ == "__main__":
    unittest.main()
