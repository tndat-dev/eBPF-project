import copy
import json
from pathlib import Path
import tempfile
import unittest
import os
import shutil
import subprocess
from unittest.mock import patch

from sentinel_pulse.operational_soak import (
    bind, classify_health, digest, load_binding, merge_intervals, observe, validate_profile,
)
from sentinel_pulse.evaluate_operational_soak import evaluate_operational
from sentinel_pulse.classify_normal_failure import classify


ROOT = Path(__file__).resolve().parents[1]


def profile():
    result = json.loads((ROOT / "sentinel_pulse/protocol/operational-soak-v1.json").read_text())
    result["additional_workloads"] = []
    return result


def pod(name="catalog-abcdef1234-abcde", claim="data"):
    return {"metadata": {"namespace": "production", "name": name},
            "status": {"phase": "Running", "conditions": [{"type": "Ready", "status": "True"}]},
            "spec": {"volumes": [{"persistentVolumeClaim": {"claimName": claim}}]}}


def binding():
    pvs = {"items": [{"metadata": {"name": "pv"}, "status": {"phase": "Bound"},
             "spec": {"claimRef": {"namespace": "production", "name": "data"},
                      "csi": {"driver": "driver.longhorn.io", "volumeHandle": "volume-a"}}}]}
    return bind(profile(), {"workloads": {"production/catalog:app": {}}},
                {"items": [pod()]}, pvs, ["w1", "w2", "w3"])


def health(binding_value, robustness="healthy", state="attached"):
    nodes = {"items": [{"metadata": {"name": n}, "status": {"conditions":
             [{"type": "Ready", "status": "True"}] +
             [{"type": c, "status": "False"} for c in ("DiskPressure", "MemoryPressure", "PIDPressure")]}}
             for n in ("w1", "w2", "w3")]}
    volumes = {"items": [{"metadata": {"name": "volume-a"},
                          "status": {"state": state, "robustness": robustness}}]}
    return classify_health(binding_value, nodes, {"items": [pod()]}, volumes, {"items": []})


class OperationalHealthTests(unittest.TestCase):
    def test_scope_from_model_and_pvc_handles(self):
        b = binding()
        self.assertEqual(b["longhorn_volumes"], ["volume-a"])
        self.assertEqual(b["minimum_ready_pods"], {"production/catalog": 1})

    def test_missing_pv_fails_registration(self):
        with self.assertRaisesRegex(ValueError, "Bound PV"):
            bind(profile(), {"workloads": {"production/catalog:app": {}}},
                 {"items": [pod()]}, {"items": []}, ["w1", "w2", "w3"])

    def test_stateless_hpa_reduction_not_false_infrastructure_incident(self):
        b = binding()
        b["ready_pods_at_registration"]["production/catalog"] = 4
        self.assertFalse(health(b)["transient"])

    def test_auxiliary_volume_is_warning_not_exclusion(self):
        b = binding()
        b["longhorn_volumes"] = []
        h = health(b, "degraded")
        self.assertFalse(h["fatal"] or h["transient"])
        self.assertEqual(len(h["warnings"]), 1)

    def test_dependency_degraded_can_recover(self):
        b = binding()
        a = observe(b, [], health(b, "degraded"), 1060, 1000)
        recovered = observe(b, [a], health(b), 1120, 1000)
        self.assertFalse(recovered["fatal"])
        self.assertEqual(recovered["excluded_interval"], [1000, 1150])
        self.assertFalse(recovered["degraded"])

    def test_faulted_and_detached_dependency_are_fatal(self):
        for robustness, state in (("faulted", "attached"), ("healthy", "detached"), (None, "attached")):
            with self.subTest(robustness=robustness, state=state):
                self.assertTrue(health(binding(), robustness, state)["fatal"])

    def test_recovery_and_total_budget_are_bounded(self):
        b = binding()
        rows = []
        h = health(b, "degraded")
        for t in range(1060, 1421, 60):
            rows.append(observe(b, rows, h, t, 1000))
        self.assertIn({"reason": "recovery_budget_exceeded"}, rows[-1]["fatal"])
        self.assertFalse(h["fatal"], "observe must not mutate the input snapshot")
        b["profile"]["maximum_excluded_seconds"] = 300
        b["profile_sha256"] = digest(b["profile"])
        rows = []
        for t in range(1060, 1301, 60):
            rows.append(observe(b, rows, h, t, 1000))
        self.assertIn({"reason": "total_degraded_budget_exceeded"}, rows[-1]["fatal"])

    def test_health_monitor_gap_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "observation gap"):
            observe(binding(), [], health(binding()), 1300, 1000)

    def test_profile_tamper_fails_closed(self):
        b = binding()
        b["profile"]["maximum_recovery_seconds"] = 600
        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            health(b)

    def test_automatic_blind_forbidden(self):
        p = profile()
        p["automatic_blind_evaluation"] = True
        with self.assertRaisesRegex(ValueError, "interlocks"):
            validate_profile(p)

    def test_interval_union_does_not_double_count(self):
        self.assertEqual(merge_intervals([[10, 15], [11, 17], [18, 19]]), [[10, 17], [18, 19]])

    def test_cannot_weaken_telemetry(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "marker.json"
            path.write_text(json.dumps({"operational_evaluation_contract": binding(),
                "telemetry_availability_contract": {"minimum_availability": 0.99, "maximum_single_gap_seconds": 10}}))
            with self.assertRaisesRegex(ValueError, "weaken telemetry"):
                load_binding(path)

    def test_nan_telemetry_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "marker.json"
            path.write_text(json.dumps({"operational_evaluation_contract": binding(),
                "telemetry_availability_contract": {"minimum_availability": float("nan"), "maximum_single_gap_seconds": 10}}))
            with self.assertRaisesRegex(ValueError, "weaken telemetry"):
                load_binding(path)


class OperationalEvaluationTests(unittest.TestCase):
    def fixture(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        b = binding()
        b["profile"]["maximum_alerts_per_workload_hour"] = 1.0
        b["profile"]["maximum_alerts_per_hour_per_workload"] = 1.0
        b["profile_sha256"] = digest(b["profile"])
        contract = {"nominal_interval_seconds": 0.5, "minimum_availability": 0.999, "maximum_single_gap_seconds": 10}
        marker = {"operational_evaluation_contract": b, "telemetry_availability_contract": contract,
                  "started_not_before": "1970-01-01T00:16:40+00:00", "run_id": "test",
                  "model_manifest_sha256": "a"*64, "decision_policy_sha256": "b"*64,
                  "registered_collector_duration_seconds": 90000,
                  "minimum_duration_hours_per_workload": 1/3600}
        paths = [root / x for x in ("marker.json", "health.jsonl", "decisions.jsonl", "manifest.json", "telemetry.json")]
        paths[0].write_text(json.dumps(marker))
        paths[1].write_text(json.dumps(observe(b, [], health(b), 1060, 1000)) + "\n")
        def row(begin, end, status="normal"):
            return {"schema": "sentinel-pulse-decision-v1", "status": status,
                    "window_start": begin, "window_end": end, "node_name": "w1",
                    "workload_key": "production/catalog:app", "model_manifest_sha256": "a"*64,
                    "decision_policy_sha256": "b"*64, "run_id": "test", "pod_uid": "pod", "cgroup_id": 1}
        paths[2].write_text("\n".join(json.dumps(row(begin, begin+0.5)) for begin in (1058, 1058.5, 1059, 1059.5)) + "\n")
        paths[3].write_text("{}")
        paths[4].write_text(json.dumps({"valid": True, "run_id": "test", "contract": contract,
                            "nodes": {n: {"valid": True} for n in ("w1", "w2", "w3")}}))
        strict = {k: True for k in ("model_identity_gate", "model_manifest_gate", "expected_workload_gate",
                          "decision_policy_identity_gate", "run_identity_gate", "soak_marker_gate")}
        strict.update({"expected_workloads": b["expected_workloads"], "decision_files": [], "normal_gate": True})
        return paths, strict, row

    def evaluate(self, paths, strict):
        with patch("sentinel_pulse.evaluate_operational_soak.evaluate", return_value=strict), \
             patch("sentinel_pulse.evaluate_operational_soak.poisson_rate_interval", return_value=None):
            return evaluate_operational(paths[0], paths[1], [paths[2]], paths[3], paths[4])

    def test_union_exposure_not_replica_count(self):
        paths, strict, _ = self.fixture()
        result = self.evaluate(paths, strict)
        self.assertAlmostEqual(result["total_valid_workload_hours"], 2/3600)
        self.assertTrue(result["operational_normal_gate"])
        self.assertFalse(result["automatic_blind_evaluation"])

    def test_one_alert_not_hidden_by_degraded_exclusion(self):
        paths, strict, row = self.fixture()
        with paths[2].open("a") as stream:
            stream.write(json.dumps(row(1060, 1060.5, "alert")) + "\n")
        b = json.loads(paths[0].read_text())["operational_evaluation_contract"]
        # Incident bounds must be produced by observe, not handpicked by score.
        previous = json.loads(paths[1].read_text())
        degraded = observe(b, [previous], health(b, "degraded"), 1120, 1000)
        recovered = observe(b, [previous, degraded], health(b), 1180, 1000)
        with paths[1].open("a") as stream:
            stream.write(json.dumps(degraded)+"\n"+json.dumps(recovered)+"\n")
        result = self.evaluate(paths, strict)
        self.assertEqual(result["all_alerts"], 1)
        self.assertEqual(result["workloads"]["production/catalog:app"]["alerts_during_degraded"], 1)
        self.assertFalse(result["operational_normal_gate"])

    def test_cannot_use_bad_telemetry_to_pass(self):
        paths, strict, _ = self.fixture()
        data = json.loads(paths[4].read_text()); data["valid"] = False
        paths[4].write_text(json.dumps(data))
        self.assertFalse(self.evaluate(paths, strict)["operational_normal_gate"])

    def test_cannot_tamper_exclusion_interval(self):
        paths, strict, _ = self.fixture()
        data = json.loads(paths[1].read_text()); data["excluded_interval"] = [1000, 1060]
        paths[1].write_text(json.dumps(data)+"\n")
        with self.assertRaisesRegex(ValueError, "interval log"):
            self.evaluate(paths, strict)

    def test_duplicate_input_rejected(self):
        paths, strict, _ = self.fixture()
        with self.assertRaisesRegex(ValueError, "duplicate decision path"):
            evaluate_operational(paths[0], paths[1], [paths[2], paths[2]], paths[3], paths[4])

    def test_runtime_identity_mismatch_rejected(self):
        paths, strict, row = self.fixture()
        data = row(1060, 1060.5); data["run_id"] = "different-run"
        with paths[2].open("a") as stream: stream.write(json.dumps(data)+"\n")
        with self.assertRaisesRegex(ValueError, "identity mismatch"):
            self.evaluate(paths, strict)

    def test_insufficient_exposure_not_claimed_as_model_rejection(self):
        paths, _, _ = self.fixture()
        report = {"schema": "sentinel-pulse-operational-soak-report-v1", "identity_gate": True,
                  "telemetry_gate": True, "health_gate": True, "operational_normal_gate": False,
                  "workloads": {"production/catalog:app": {"exposure_gate": False}}}
        (paths[0].parent / "OPERATIONAL_REPORT.json").write_text(json.dumps(report))
        self.assertEqual(classify(paths[0].parent), "operational_exposure_gate_failed")

    def test_rate_failure_is_not_relabelled_as_infrastructure(self):
        paths, _, _ = self.fixture()
        report = {"schema": "sentinel-pulse-operational-soak-report-v1", "identity_gate": True,
                  "telemetry_gate": True, "health_gate": True, "operational_normal_gate": False,
                  "workloads": {"production/catalog:app": {"exposure_gate": True, "rate_gate": False}}}
        (paths[0].parent / "OPERATIONAL_REPORT.json").write_text(json.dumps(report))
        self.assertEqual(classify(paths[0].parent), "operational_normal_gate_failed")


@unittest.skipUnless(shutil.which("jq"), "shell integration requires jq")
class OperationalMonitorIntegrationTests(unittest.TestCase):
    def monitor(self, operational=True, bad_tail=False, fatal_health=False,
                projected=False, bad_collector=False, bad_start=False):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        commands = root / "bin"; commands.mkdir()
        evidence = root / "evidence"; evidence.mkdir()
        marker = {"eligible_finalize_after": "1970-01-01T00:00:00+00:00",
                  "minimum_root_available_bytes": 0, "maximum_root_used_percent": 80,
                  "registered_collector_duration_seconds": 86400,
                  "telemetry_availability_contract": {"nominal_interval_seconds": 0.5,
                      "minimum_availability": 0.999, "maximum_single_gap_seconds": 10}}
        if operational: marker["operational_evaluation_contract"] = binding()
        if projected:
            marker["run_id"] = "projected-test"
            marker["collector_contract"] = {"variant": "projected"}
        (evidence / "SOAK_START.json").write_text(json.dumps(marker))
        import hashlib
        digest = hashlib.sha256((evidence / "SOAK_START.json").read_bytes()).hexdigest()
        if bad_start: digest = "0" * 64
        (evidence / "START_SHA256SUMS").write_text(digest + "  SOAK_START.json\n")
        (evidence / "WORKLOAD_FINGERPRINT.json").write_text("{}\n")
        (evidence / "workers.txt").write_text("test-host test-node /test/features.jsonl\n")
        (evidence / "ACTIVE").touch()
        programs = {
            "kubectl": '#!/bin/bash\necho \'{"items":[]}\'\n',
            "gate-python": '#!/bin/bash\ncase "$*" in\n'
               '*operational_soak*) echo \'{"fatal":[],"transient":[{"reason":"dependency_degraded"}],"warnings":[]}\'; exit "${TEST_FATAL_HEALTH:-0}";;\n'
               '*workload_fingerprint*) while (($#)); do if [[ $1 == --output ]]; then echo "{}" > "$2"; break; fi; shift; done;;\n'
               '*) echo 0;;\nesac\n',
            "sshpass": '#!/bin/bash\ncase "$*" in\n'
               '*"df -B1"*) echo "100000000000 50%";;\n'
               '*"systemctl is-enabled"*) printf "masked\\nmasked\\nmasked\\n";;\n'
               '*inspect_feature_tail*) echo \'{"valid":true}\'; exit "${TEST_BAD_TAIL:-0}";;\n'
               '*collector_contract*) echo \'{"valid":true}\'; exit "${TEST_BAD_COLLECTOR:-0}";;\n'
               '*) printf "collector=active\\nlegacy=inactive\\ndetector=active\\nrestarts=0\\ndecisions=100\\nalerts=1\\nfeature=/test/features.jsonl\\n";;\nesac\n',
        }
        for name, program in programs.items():
            path = commands / name; path.write_text(program); path.chmod(0o755)
        env = {**os.environ, "PATH": f'{commands}:{os.environ["PATH"]}', "SSHPASS": "fixture-only",
               "PYTHON": str(commands / "gate-python"), "LOCAL_ROOT": str(ROOT),
               "POLL_SECONDS": "0", "TEST_BAD_TAIL": str(int(bad_tail)),
               "TEST_BAD_COLLECTOR": str(int(bad_collector)),
               "TEST_FATAL_HEALTH": str(int(fatal_health))}
        result = subprocess.run(["bash", str(ROOT / "sentinel_pulse/monitor_500ms_normal_soak.sh"), str(evidence)],
                                env=env, capture_output=True, text=True, timeout=8)
        return result, evidence

    def test_operational_alert_and_recoverable_health_do_not_abort(self):
        result, evidence = self.monitor()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((evidence / "READY_TO_FINALIZE").exists())
        self.assertFalse((evidence / "NORMAL_PASS").exists())
        self.assertFalse((evidence / "OPERATIONAL_PASS").exists())

    def test_legacy_one_alert_still_rejects(self):
        result, evidence = self.monitor(operational=False)
        self.assertEqual(result.returncode, 1)
        self.assertIn("normal_alert_observed", (evidence / "FAILED").read_text())

    def test_operational_integrity_failure_is_still_fatal(self):
        result, evidence = self.monitor(bad_tail=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn("collector_integrity_violation", (evidence / "FAILED").read_text())

    def test_operational_fatal_health_is_not_ignored(self):
        result, evidence = self.monitor(fatal_health=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn("operational_health_gate_failed", (evidence / "FAILED").read_text())

    def test_projected_runtime_contract_is_checked(self):
        result, evidence = self.monitor(projected=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((evidence / "collector-contract-test-host.json").exists())

    def test_projected_binary_drift_aborts(self):
        result, evidence = self.monitor(projected=True, bad_collector=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn("collector_provenance_drift", (evidence / "FAILED").read_text())

    def test_registered_start_tampering_aborts_before_poll(self):
        result, evidence = self.monitor(bad_start=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn("registered_start_checksum_drift", (evidence / "FAILED").read_text())


if __name__ == "__main__":
    unittest.main()
