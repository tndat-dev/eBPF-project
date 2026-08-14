import unittest

import numpy as np

from sentinel_pulse.model import PulseExtraTrees


class _FakeEstimator:
    def predict_proba(self, rows):
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


if __name__ == "__main__":
    unittest.main()
