import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from sentinel_pulse.validate_infrastructure_rejection import validate


def write(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value, encoding="utf-8")


class PulseInfrastructureRejectionTests(unittest.TestCase):
    def fixture(self) -> Path:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        write(
            root / "SOAK_START.json",
            json.dumps(
                {
                    "run_id": "run-a1",
                    "started_not_before": "2026-08-20T10:12:56+00:00",
                }
            ),
        )
        write(root / "FAILED", "reason=normal_alert_observed\n")
        alert = {"pod_name": "postgres-1", "alerted_at": 1787222499.075225}
        alert_path = root / "workers/node/raw/alerts.jsonl"
        write(alert_path, json.dumps(alert) + "\n")
        digest = hashlib.sha256(alert_path.read_bytes()).hexdigest()
        write(
            root / "RAW_SHA256SUMS",
            f"{digest}  workers/node/raw/alerts.jsonl\n",
        )
        write(
            root / "infrastructure-failure/cnpg-2-events.json",
            json.dumps(
                {
                    "items": [
                        {
                            "reason": "Evicted",
                            "lastTimestamp": "2026-08-20T10:41:37Z",
                            "message": "low on ephemeral-storage",
                        }
                    ]
                }
            ),
        )
        write(
            root / "infrastructure-failure/DISPOSITION.json",
            json.dumps(
                {
                    "run_id": "run-a1",
                    "terminal_run_status": "rejected_infrastructure_failure",
                    "candidate_status": "not_evaluated_by_this_run",
                    "recorded_at_unix": 1787223065.0,
                    "observed_alerts": 1,
                    "alert_evidence": [alert],
                    "data_use": {
                        "normal_gate": False,
                        "training": False,
                        "tuning": False,
                        "blind_attack": False,
                    },
                }
            ),
        )
        return root

    def test_valid_machine_correlated_rejection(self):
        report = validate(self.fixture())
        self.assertTrue(report["valid"], report["errors"])
        self.assertEqual(report["raw_alerts"], 1)

    def test_checksum_tamper_fails_closed(self):
        root = self.fixture()
        with (root / "workers/node/raw/alerts.jsonl").open("a") as output:
            output.write("{}\n")
        report = validate(root)
        self.assertFalse(report["valid"])
        self.assertIn("raw checksum mismatch", report["errors"][0])

    def test_unrelated_late_alert_is_not_rejected_as_infrastructure(self):
        root = self.fixture()
        disposition_path = root / "infrastructure-failure/DISPOSITION.json"
        disposition = json.loads(disposition_path.read_text())
        disposition["alert_evidence"][0]["alerted_at"] += 60.0
        disposition_path.write_text(json.dumps(disposition), encoding="utf-8")
        report = validate(root)
        self.assertFalse(report["valid"])
        self.assertIn("declared alerts do not match raw alert evidence", report["errors"])


if __name__ == "__main__":
    unittest.main()
