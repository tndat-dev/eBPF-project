import json
import unittest
from pathlib import Path


class SyscallSelectionProtocolV2Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.protocol = json.loads(Path(
            'sentinel_pulse/protocol/syscall-selection-evaluation-v2.json').read_text())

    def test_registered_paired_matrix_size(self):
        protocol = self.protocol
        self.assertEqual(protocol['status'], 'prospective_protocol_not_yet_executed')
        self.assertEqual(protocol['candidate_coverage']['frozen_pulse_bundle_workload_keys'], 21)
        design = protocol['data_partitions']['trial_design']
        self.assertIn('2,520 paired attack intervals', design)
        self.assertEqual(len(protocol['data_partitions']['fresh_blind_family_descriptions']), 8)
        self.assertEqual(len(protocol['data_partitions']['excluded_as_non_blind_reuse']), 6)

    def test_selection_is_nonzero_budget_and_noninferiority_rule(self):
        endpoint = self.protocol['primary_endpoint']
        self.assertTrue(endpoint['no_zero_gate'])
        self.assertIn('0.1', endpoint['false_alert_budget'])
        self.assertIn('-0.03', endpoint['selection_rule'])

    def test_required_group_masks_and_rare_security_arm_are_registered(self):
        arms = self.protocol['arms']
        self.assertEqual(len(arms['group_ablation']), 4)
        self.assertIn('finit_module(313)', arms['threat_model_addition'])
        self.assertIn('io_uring_setup(425)', arms['threat_model_addition'])


if __name__ == '__main__':
    unittest.main()
