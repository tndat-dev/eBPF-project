import json
import tempfile
import unittest
from pathlib import Path

from sentinel_pulse.blind_contract import expected_matrix, load_contract


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


if __name__ == "__main__":
    unittest.main()
