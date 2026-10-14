import unittest

from sentinel_pulse.syscall_addition_experiment import (
    build_contexts, choose_variants, histogram_vector, phase_for,
)


class RegistrationTests(unittest.TestCase):
    def test_rank_excludes_existing_ids_and_breaks_ties_by_id(self):
        variants, ranked = choose_variants({0: 1000, 202: 8, 232: 8, 262: 3}, {0: 'read'})
        self.assertEqual(ranked, [202, 232, 262])
        self.assertEqual(variants['base29'], (0,))
        self.assertEqual(variants['plus_top8'], (0, 202, 232, 262))

    def test_selection_embargo_and_holdout_are_separate(self):
        self.assertEqual(phase_for(10, 11, 0, 100, 'selection'), 'train')
        self.assertIsNone(phase_for(69, 70, 0, 100, 'selection'))
        self.assertEqual(phase_for(73, 74, 0, 100, 'selection'), 'calibration')
        self.assertEqual(phase_for(69, 70, 0, 100, 'holdout'), 'holdout')
        self.assertIsNone(phase_for(-1, 1, 0, 100, 'holdout'))

    def test_invalid_histogram_rank_rejected(self):
        with self.assertRaises(ValueError): choose_variants({202: -1}, {0: 'read'})


class FeatureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            import numpy
        except ImportError:
            raise unittest.SkipTest('NumPy needed for feature tests; execute in experiment venv')

    def test_addition_reassigns_other_without_changing_total_or_bins(self):
        import numpy as np
        counts = {0: 10, 202: 20, 232: 30}
        base, _ = histogram_vector(counts, 1., [], (0,), frozenset())
        extra, _ = histogram_vector(counts, 1., [], (0, 202), frozenset())
        self.assertEqual(len(base), 4*1+69)
        self.assertEqual(len(extra), 4*2+69)
        self.assertAlmostEqual(float(base[2]), np.log1p(50), places=5)
        self.assertAlmostEqual(float(extra[4]), np.log1p(30), places=5)
        np.testing.assert_array_equal(base[7:71], extra[9:73])

    def test_full_rolling_and_temporal_warmup(self):
        rows = [dict(workload='production/x:app', identity=('n', 'p', 'app', 'rev', 1),
                     phase='holdout', begin=i, end=i+1., counts={0: 2}, regime='steady', run_id='capture')
                for i in range(20)]
        contexts, metadata, _ = build_contexts(rows, (0,), frozenset())
        self.assertEqual(contexts['production/x:app']['holdout'].shape, (7, 292))
        self.assertEqual(metadata['production/x:app'][0]['begin'], 13)

    def test_history_does_not_cross_partition_or_capture(self):
        rows = [dict(workload='production/x:app', identity=('n', 'p', 'app', 'rev', 1),
                     phase='train' if i < 12 else 'calibration', begin=i, end=i+1.,
                     counts={}, regime='steady', run_id='capture') for i in range(24)]
        contexts, _, _ = build_contexts(rows, (0,), frozenset())
        self.assertEqual(contexts, {})
        for i, row in enumerate(rows):
            row['phase'] = 'holdout'; row['run_id'] = 'a' if i < 12 else 'b'
        contexts, _, _ = build_contexts(rows, (0,), frozenset())
        self.assertEqual(contexts, {})


if __name__ == '__main__':
    unittest.main()
