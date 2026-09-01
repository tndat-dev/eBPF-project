import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from sentinel_pulse.blind_contract import expected_matrix, load_contract, marker_matrix_key


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "sentinel_pulse" / "protocol" / "blind-attack-contract.json"


class PulseBlindContractTests(unittest.TestCase):
    def test_frozen_contract_expands_to_complete_450_trial_matrix(self):
        contract = load_contract(CONTRACT)
        matrix = expected_matrix(contract)
        self.assertEqual(len(matrix), 450)
        self.assertEqual(len(contract["matrix"]["workload_controllers"]), 18)
        self.assertEqual(len(contract["matrix"]["scenarios"]), 5)

    def test_weakened_safety_or_duplicate_trial_fails_closed(self):
        contract = json.loads(CONTRACT.read_text())
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "contract.json"
            contract["safety_contract"]["external_network"] = True
            path.write_text(json.dumps(contract), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "unsafe"):
                load_contract(path)

            contract = json.loads(CONTRACT.read_text())
            contract["matrix"]["trials"].append(contract["matrix"]["trials"][0])
            contract["expected_injections"] += 90
            path.write_text(json.dumps(contract), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "unique"):
                load_contract(path)

    def test_marker_controller_must_match_target_workload_and_cgroup(self):
        marker = {
            "workload_controller": "catalog-service",
            "workload_key": "production/order-service:app",
            "cgroup_id": 42,
            "injected_at": 10.0,
            "scenario": "namespace_probe",
            "seed": 11003,
            "rate_per_second": 6,
        }
        with self.assertRaisesRegex(ValueError, "target identity"):
            marker_matrix_key(marker)

    def test_successor_contract_is_bound_and_excludes_a2_scenarios(self):
        contract = load_contract(
            ROOT / "sentinel_pulse" / "protocol" / "blind-attack-contract-b1.json"
        )
        self.assertEqual(contract["expected_injections"], 450)
        self.assertTrue(contract["frozen_before_candidate_evaluation"])
        self.assertFalse(
            set(contract["matrix"]["scenarios"])
            & set(contract["independence"]["excluded_predecessor_scenarios"])
        )

    def test_b2_contract_rebinds_the_unopened_set_to_risk_tiered_policy(self):
        contract = load_contract(
            ROOT / "sentinel_pulse" / "protocol" / "blind-attack-contract-b2.json"
        )
        b1_path = ROOT / "sentinel_pulse" / "protocol" / "blind-attack-contract-b1.json"
        policy_path = (
            ROOT / "sentinel_pulse" / "protocol" / "decision-policy-temporal-b2.json"
        )
        self.assertEqual(
            contract["candidate_binding"]["decision_policy_sha256"],
            hashlib.sha256(policy_path.read_bytes()).hexdigest(),
        )
        self.assertEqual(
            contract["independence"]["derived_from_unused_contract_sha256"],
            hashlib.sha256(b1_path.read_bytes()).hexdigest(),
        )
        self.assertFalse(
            contract["independence"][
                "predecessor_contract_candidate_evaluation_started"
            ]
        )

    def test_b3_contract_is_frozen_unopened_for_the_consecutive_policy(self):
        contract_path = (
            ROOT / "sentinel_pulse" / "protocol" / "blind-attack-contract-b3.json"
        )
        predecessor_path = (
            ROOT / "sentinel_pulse" / "protocol" / "blind-attack-contract-b2.json"
        )
        policy_path = (
            ROOT / "sentinel_pulse" / "protocol" / "decision-policy-temporal-b3.json"
        )
        implementation_path = (
            ROOT
            / "sentinel_pulse"
            / "protocol"
            / "attack-implementation-contract-b1.json"
        )
        contract = load_contract(contract_path)
        predecessor = load_contract(predecessor_path)
        implementation = json.loads(implementation_path.read_text())

        self.assertEqual(
            contract["candidate_binding"]["decision_policy_sha256"],
            hashlib.sha256(policy_path.read_bytes()).hexdigest(),
        )
        self.assertEqual(
            contract["independence"]["derived_from_unused_contract_sha256"],
            hashlib.sha256(predecessor_path.read_bytes()).hexdigest(),
        )
        self.assertFalse(
            contract["independence"][
                "predecessor_contract_candidate_evaluation_started"
            ]
        )
        self.assertTrue(
            contract["independence"][
                "scenario_set_reused_only_from_unopened_predecessor_contract"
            ]
        )
        self.assertEqual(contract["matrix"], predecessor["matrix"])
        self.assertEqual(
            set(contract["matrix"]["scenarios"]),
            set(implementation["scenarios"]),
        )

    def test_successor_predecessor_binding_fails_closed(self):
        contract = json.loads(
            (
                ROOT
                / "sentinel_pulse"
                / "protocol"
                / "blind-attack-contract-b3.json"
            ).read_text()
        )
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "contract.json"
            contract["independence"][
                "predecessor_contract_candidate_evaluation_started"
            ] = True
            path.write_text(json.dumps(contract), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "predecessor binding"):
                load_contract(path)


if __name__ == "__main__":
    unittest.main()
