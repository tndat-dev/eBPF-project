import unittest

import numpy as np

from sentinel_pulse.model import PulseExtraTrees


class _FakeEstimator:
    def __init__(self):
        self.maximum_batch_rows = 0

    def predict_proba(self, rows):
        self.maximum_batch_rows = max(self.maximum_batch_rows, len(rows))
        score = np.clip(np.mean(rows[:, -4:], axis=1), 0.0, 1.0)
        return np.column_stack((1.0 - score, score))


class PulseModelTests(unittest.TestCase):
    def test_alpha_defines_required_calibration_resolution(self):
        self.assertEqual(PulseExtraTrees(alpha=1e-4).minimum_calibration_examples, 9999)
        self.assertEqual(PulseExtraTrees(alpha=0.2).minimum_calibration_examples, 4)

    def test_temporal_examples_never_cross_sequence_boundary(self):
        model = PulseExtraTrees(history=2)
        left = np.arange(240, dtype=np.float32).reshape(60, 4)
        right = np.arange(400, 640, dtype=np.float32).reshape(60, 4)
        train_x, _train_y, calibration_x, _calibration_y, feature_dim = model._split_sequences(
            [left, right], 0.7
        )
        self.assertEqual(feature_dim, 4)
        # Every context belongs completely to the low or high sequence.
        self.assertTrue(all(np.all(row < 240) or np.all(row >= 400) for row in train_x))
        self.assertTrue(all(np.all(row < 240) or np.all(row >= 400) for row in calibration_x))

    def test_predict_reports_measured_inference_and_conformal_tail(self):
        model = PulseExtraTrees(history=2, alpha=0.2)
        model.estimator = _FakeEstimator()
        model.feature_dim = 4
        model.calibration_scores = np.asarray([0.1, 0.2, 0.3, 0.4], dtype=np.float32)
        result = model.predict(np.zeros((2, 4)), np.ones(4))
        self.assertGreater(result.score, 0.4)
        self.assertEqual(result.conformal_p, 0.2)
        self.assertTrue(result.anomalous)
        self.assertGreaterEqual(result.inference_ms, 0.0)

    def test_example_layout_and_scoring_are_memory_bounded(self):
        model = PulseExtraTrees(history=2)
        rows = np.arange(48, dtype=np.float32).reshape(12, 4)
        history, current = model._examples(rows)
        self.assertEqual(history.shape, (10, 8))
        np.testing.assert_array_equal(history[0], rows[:2].reshape(-1))
        np.testing.assert_array_equal(current[0], rows[2])

        model.estimator = _FakeEstimator()
        scores = model._raw_scores(history, current, batch_rows=3)
        self.assertEqual(len(scores), 10)
        self.assertEqual(model.estimator.maximum_batch_rows, 3)

    def test_corruption_is_chunked_deterministic_float32(self):
        rows = np.ones((25, 12), dtype=np.float32)
        left = PulseExtraTrees(random_state=7)._corrupt(rows, chunk_rows=4)
        right = PulseExtraTrees(random_state=7)._corrupt(rows, chunk_rows=4)
        self.assertEqual(left.dtype, np.float32)
        np.testing.assert_array_equal(left, right)
        self.assertFalse(np.array_equal(left, rows))


if __name__ == "__main__":
    unittest.main()
