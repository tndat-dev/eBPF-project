"""Self-supervised ExtraTrees temporal detector for Sentinel Pulse."""

from __future__ import annotations

from dataclasses import dataclass
import math
from pathlib import Path
from typing import Iterable, Sequence
import os
import pickle
import tempfile
import time

import numpy as np


MAX_CONTIGUOUS_GAP_SECONDS = 1.5


@dataclass(frozen=True)
class PulseDecision:
    score: float
    conformal_p: float
    anomalous: bool
    inference_ms: float


class PulseExtraTrees:
    """Rank temporal corruption using only ordered normal windows.

    Synthetic negatives are deterministic corruptions of normal feature rows,
    not attack samples. A held-out normal split converts the classifier score
    into a conformal p-value; blind attacks never alter model or threshold.
    """

    def __init__(self, history: int = 3, alpha: float = 1e-4, random_state: int = 73021):
        if history < 1:
            raise ValueError("history must be positive")
        if not 0.0 < alpha < 1.0:
            raise ValueError("alpha must be between zero and one")
        self.history = history
        self.alpha = alpha
        self.random_state = random_state
        self.estimator = None
        self.calibration_scores: np.ndarray | None = None
        self.feature_dim: int | None = None

    @property
    def minimum_calibration_examples(self) -> int:
        """Minimum sample count that can represent a conformal p <= alpha."""
        return max(1, math.ceil(1.0 / self.alpha) - 1)

    def _examples(self, rows: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
        rows = np.asarray(rows, dtype=np.float32)
        if rows.ndim != 2 or len(rows) <= self.history:
            raise ValueError("not enough ordered windows for temporal examples")
        examples = len(rows) - self.history
        feature_dim = rows.shape[1]
        x = np.empty((examples, self.history * feature_dim), dtype=np.float32)
        for offset in range(self.history):
            left = offset * feature_dim
            x[:, left:left + feature_dim] = rows[offset:offset + examples]
        y = rows[self.history:]
        return x, y

    def _split_sequences(
        self, ordered_sequences: Iterable[Sequence[Sequence[float]]], train_fraction: float
    ) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray, int]:
        train_x, train_y, calibration_x, calibration_y = [], [], [], []
        feature_dim = None
        total_rows = 0
        for sequence in ordered_sequences:
            rows = np.asarray(sequence, dtype=np.float32)
            if rows.ndim != 2 or len(rows) <= self.history * 2 + 2:
                continue
            if feature_dim is None:
                feature_dim = rows.shape[1]
            if rows.shape[1] != feature_dim:
                raise ValueError("all sequences must use the same feature schema")
            split = int(len(rows) * train_fraction)
            if split <= self.history or len(rows) - split <= self.history:
                continue
            x, y = self._examples(rows[:split])
            cx, cy = self._examples(rows[split - self.history:])
            train_x.append(x); train_y.append(y)
            calibration_x.append(cx); calibration_y.append(cy)
            total_rows += len(rows)
        if total_rows < 100 or not train_x or not calibration_x:
            raise ValueError("at least 100 usable ordered normal windows are required")
        def combine(parts: list[np.ndarray]) -> np.ndarray:
            return parts[0] if len(parts) == 1 else np.concatenate(parts)

        return (
            combine(train_x), combine(train_y),
            combine(calibration_x), combine(calibration_y),
            int(feature_dim),
        )

    @staticmethod
    def _contexts(history: np.ndarray, current: np.ndarray) -> np.ndarray:
        return np.concatenate((history, current), axis=1)

    def _corrupt(self, current: np.ndarray, chunk_rows: int = 8192) -> np.ndarray:
        if chunk_rows <= 0:
            raise ValueError("corruption chunk size must be positive")
        rng = np.random.default_rng(self.random_state)
        corrupted = current.copy()
        donor_indices = rng.permutation(len(current))
        for start in range(0, len(current), chunk_rows):
            stop = min(len(current), start + chunk_rows)
            target = corrupted[start:stop]
            donor = current[donor_indices[start:stop]]
            swap_mask = rng.random(target.shape, dtype=np.float32) < 0.15
            target[swap_mask] = donor[swap_mask]
            scale_mask = rng.random(target.shape, dtype=np.float32) < 0.08
            factor_count = int(np.count_nonzero(scale_mask))
            if factor_count:
                factors = np.exp(
                    rng.uniform(np.log(0.25), np.log(4.0), size=factor_count)
                ).astype(np.float32)
                target[scale_mask] *= factors
        return corrupted.astype(np.float32)

    def _raw_scores(
        self, x: np.ndarray, y: np.ndarray, batch_rows: int = 8192
    ) -> np.ndarray:
        if batch_rows <= 0:
            raise ValueError("prediction batch size must be positive")
        if len(x) != len(y):
            raise ValueError("history/current batch length mismatch")
        scores = np.empty(len(x), dtype=np.float64)
        for start in range(0, len(x), batch_rows):
            stop = min(len(x), start + batch_rows)
            scores[start:stop] = self.estimator.predict_proba(
                self._contexts(x[start:stop], y[start:stop])
            )[:, 1]
        return scores

    def fit(self, ordered_normal_rows: Sequence[Sequence[float]], train_fraction: float = 0.7) -> dict:
        return self.fit_sequences([ordered_normal_rows], train_fraction=train_fraction)

    def fit_sequences(
        self,
        ordered_normal_sequences: Iterable[Sequence[Sequence[float]]],
        train_fraction: float = 0.7,
    ) -> dict:
        try:
            from sklearn.ensemble import ExtraTreesClassifier
        except ImportError as exc:
            raise RuntimeError("scikit-learn is required to train Sentinel Pulse") from exc

        train_x, train_y, calibration_x, calibration_y, self.feature_dim = self._split_sequences(
            ordered_normal_sequences, train_fraction
        )
        if len(calibration_x) < self.minimum_calibration_examples:
            raise ValueError(
                f"alpha={self.alpha:g} requires at least "
                f"{self.minimum_calibration_examples} calibration examples; got {len(calibration_x)}"
            )
        examples = len(train_x)
        history_dim = train_x.shape[1]
        current_dim = train_y.shape[1]
        fit_x = np.empty(
            (examples * 2, history_dim + current_dim), dtype=np.float32
        )
        fit_x[:examples, :history_dim] = train_x
        fit_x[:examples, history_dim:] = train_y
        fit_x[examples:, :history_dim] = train_x
        corrupted_current = self._corrupt(train_y)
        fit_x[examples:, history_dim:] = corrupted_current
        fit_matrix_bytes = int(fit_x.nbytes)
        del corrupted_current
        fit_y = np.concatenate(
            (np.zeros(examples, dtype=np.uint8), np.ones(examples, dtype=np.uint8))
        )
        self.estimator = ExtraTreesClassifier(
            n_estimators=192,
            max_depth=16,
            min_samples_leaf=4,
            max_features="sqrt",
            class_weight="balanced",
            n_jobs=-1,
            random_state=self.random_state,
        )
        started = time.perf_counter()
        self.estimator.fit(fit_x, fit_y)
        train_seconds = time.perf_counter() - started
        del fit_x, fit_y
        self.calibration_scores = np.sort(self._raw_scores(calibration_x, calibration_y))
        # A single live window should not fan out a prediction thread pool.
        self.estimator.n_jobs = 1
        return {
            "train_examples": int(len(train_x)),
            "calibration_examples": int(len(calibration_x)),
            "minimum_calibration_examples": self.minimum_calibration_examples,
            "minimum_conformal_p": 1.0 / (len(calibration_x) + 1.0),
            "feature_dim": int(self.feature_dim),
            "fit_matrix_bytes": fit_matrix_bytes,
            "train_seconds": train_seconds,
            "calibration_score_p99": float(np.quantile(self.calibration_scores, 0.99)),
        }

    def predict(self, history_rows: Sequence[Sequence[float]], current_row: Sequence[float]) -> PulseDecision:
        if self.estimator is None or self.calibration_scores is None:
            raise RuntimeError("model has not been fitted")
        history = np.asarray(history_rows, dtype=np.float32)
        current = np.asarray(current_row, dtype=np.float32)
        if history.shape != (self.history, self.feature_dim) or current.shape != (self.feature_dim,):
            raise ValueError("feature shape does not match fitted Pulse model")
        started = time.perf_counter()
        score = float(self._raw_scores(history.reshape(1, -1), current.reshape(1, -1))[0])
        greater_or_equal = len(self.calibration_scores) - int(np.searchsorted(self.calibration_scores, score, side="left"))
        conformal_p = (greater_or_equal + 1.0) / (len(self.calibration_scores) + 1.0)
        inference_ms = (time.perf_counter() - started) * 1000.0
        return PulseDecision(score, conformal_p, conformal_p <= self.alpha, inference_ms)

    def save(self, path: str | Path) -> None:
        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary_name = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="wb", dir=destination.parent, prefix=f".{destination.name}.", delete=False
            ) as handle:
                temporary_name = handle.name
                pickle.dump(self, handle, protocol=pickle.HIGHEST_PROTOCOL)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary_name, destination)
        finally:
            if temporary_name is not None:
                try:
                    os.unlink(temporary_name)
                except FileNotFoundError:
                    pass

    @classmethod
    def load(cls, path: str | Path) -> "PulseExtraTrees":
        with open(path, "rb") as handle:
            model = pickle.load(handle)
        if not isinstance(model, cls):
            raise TypeError("artifact is not a Sentinel Pulse model")
        return model
