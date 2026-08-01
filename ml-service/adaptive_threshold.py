"""Per-workload robust thresholding for streaming anomaly scores.

The old fixed 0.80 cutoff treated every workload and every noisy window alike.
This module uses the empirical tail of real baseline scores (POT-style) and a
robust fallback when there are too few samples.
"""
from dataclasses import dataclass, field
from collections import deque
import json
import os
import tempfile
import numpy as np

try:
    from scipy.stats import genpareto
except ImportError:  # deterministic empirical fallback remains available
    genpareto = None

@dataclass
class POTThreshold:
    minimum: float = 0.80
    quantile: float = 0.995
    margin: float = 0.05
    min_samples: int = 30
    tail_quantile: float = 0.90
    min_exceedances: int = 10
    fit_method: str = field(init=False, default="unfitted")
    diagnostics: dict = field(init=False, default_factory=dict)

    def fit(self, scores):
        x = np.asarray(scores, dtype=float)
        x = x[np.isfinite(x)]
        if x.size < self.min_samples:
            self.fit_method = "minimum"
            self.diagnostics = {"samples": int(x.size)}
            return self.minimum

        # Peaks Over Threshold: fit a Generalized Pareto Distribution to
        # exceedances above u and extrapolate the requested global quantile.
        # Bounded/degenerate score tails can make the MLE unstable, in which
        # case the empirical robust fallback below is deliberately used.
        u = float(np.quantile(x, self.tail_quantile))
        excess = x[x > u] - u
        tail_fraction = float(excess.size / x.size)
        if genpareto is not None and excess.size >= self.min_exceedances:
            try:
                shape, _, scale = genpareto.fit(excess, floc=0.0)
                conditional_q = 1.0 - (1.0 - self.quantile) / tail_fraction
                tail_value = float(genpareto.ppf(
                    conditional_q, shape, loc=0.0, scale=scale
                ))
                estimate = u + tail_value
                if (
                    np.isfinite(estimate)
                    and np.isfinite(shape)
                    and np.isfinite(scale)
                    and -1.0 < shape < 2.0
                    and scale > 0.0
                ):
                    mad = float(np.median(np.abs(x - np.median(x))))
                    result = float(np.clip(
                        max(self.minimum, estimate + self.margin * max(mad, 1e-3)),
                        self.minimum,
                        0.995,
                    ))
                    self.fit_method = "evt-gpd"
                    self.diagnostics = {
                        "samples": int(x.size),
                        "exceedances": int(excess.size),
                        "u": u,
                        "shape": float(shape),
                        "scale": float(scale),
                        "threshold": result,
                    }
                    return result
            except (ValueError, FloatingPointError, OverflowError):
                pass

        # Conservative finite-sample/degenerate-tail fallback.
        q = float(np.quantile(x, self.quantile))
        mad = float(np.median(np.abs(x - np.median(x))))
        result = float(np.clip(
            max(self.minimum, q + self.margin * max(mad, 1e-3)),
            self.minimum,
            0.995,
        ))
        self.fit_method = "empirical"
        self.diagnostics = {
            "samples": int(x.size),
            "exceedances": int(excess.size),
            "u": u,
            "threshold": result,
        }
        return result

class StreamingThreshold:
    """Online calibration from real runtime windows for one workload."""
    def __init__(self, minimum=0.80, warmup=10, capacity=120,
                 event_floor_quantile=0.10, event_floor_fraction=0.50,
                 event_ceiling_quantile=0.99, event_ceiling_factor=2.0):
        if not 0.0 <= event_floor_quantile <= 1.0:
            raise ValueError("event floor quantile must be within [0, 1]")
        if not 0.0 < event_floor_fraction <= 1.0:
            raise ValueError("event floor fraction must be within (0, 1]")
        if not 0.0 <= event_ceiling_quantile <= 1.0:
            raise ValueError("event ceiling quantile must be within [0, 1]")
        if event_ceiling_factor <= 1.0:
            raise ValueError("event ceiling factor must be greater than 1")
        self.minimum = minimum
        self.warmup = warmup
        self.scores = deque(maxlen=capacity)
        self.event_counts = deque(maxlen=capacity)
        self.estimator = POTThreshold(minimum=minimum)
        self.current = minimum
        self.event_floor_quantile = event_floor_quantile
        self.event_floor_fraction = event_floor_fraction
        self.event_ceiling_quantile = event_ceiling_quantile
        self.event_ceiling_factor = event_ceiling_factor

    def observe(self, score, event_count=None):
        if np.isfinite(score):
            self.scores.append(float(score))
            self.current = self.estimator.fit(list(self.scores))
            if event_count is not None and int(event_count) > 0:
                self.event_counts.append(int(event_count))
        return self.current

    @property
    def ready(self):
        return len(self.scores) >= self.warmup

    @property
    def event_guard_ready(self):
        return len(self.event_counts) >= self.warmup

    @property
    def minimum_event_count(self):
        """Reject partial captures below half the lower normal-volume tail."""
        if not self.event_guard_ready:
            return 0
        lower_normal = float(np.quantile(
            self.event_counts, self.event_floor_quantile
        ))
        return max(1, int(lower_normal * self.event_floor_fraction))

    @property
    def maximum_event_count(self):
        """Return a conservative upper bound learned only from clean windows.

        This is independent corroborating evidence for attacks that preserve a
        workload's syscall proportions while multiplying total kernel-event
        volume.  A high quantile and a 2x safety margin keep ordinary load
        variation below the bound.  The detector still requires both a full ML
        threshold crossing and persistence; volume alone is never actionable.
        """
        if not self.event_guard_ready:
            return 0
        upper_normal = float(np.quantile(
            self.event_counts, self.event_ceiling_quantile
        ))
        return max(1, int(np.ceil(upper_normal * self.event_ceiling_factor)))

def load_calibrators(path, minimum=.80, warmup=10,
                     event_ceiling_factor=2.0):
    """Restore per-workload clean score history; malformed state is ignored."""
    try:
        with open(path) as f:
            data = json.load(f)
    except (OSError, ValueError, TypeError):
        return {}
    payload = data.get("workloads", {}) if isinstance(data, dict) and (
        data.get("schema_version") == 2
    ) else data
    result = {}
    for key, state in payload.items():
        if isinstance(state, dict):
            scores = state.get("scores", [])
            event_counts = state.get("event_counts", [])
        else:
            scores = state
            event_counts = []
        cal = StreamingThreshold(
            minimum=minimum, warmup=warmup,
            event_ceiling_factor=event_ceiling_factor,
        )
        for score in scores:
            cal.observe(score)
        for event_count in event_counts:
            if int(event_count) > 0:
                cal.event_counts.append(int(event_count))
        result[key] = cal
    return result

def save_calibrators(path, calibrators):
    """Atomically persist clean score history."""
    path = os.fspath(path)
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    descriptor, tmp = tempfile.mkstemp(
        prefix=f".{os.path.basename(path)}.", suffix=".tmp",
        dir=directory, text=True,
    )
    try:
        with os.fdopen(descriptor, "w") as f:
            json.dump({
                "schema_version": 2,
                "workloads": {
                    key: {
                        "scores": list(cal.scores),
                        "event_counts": list(cal.event_counts),
                    }
                    for key, cal in calibrators.items()
                },
            }, f, sort_keys=True)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass

def load_thresholds(model_manager, minimum=0.80):
    """Derive a threshold per loaded model from its stored baseline vectors."""
    out = {}
    bundles = getattr(model_manager, "_models", {})
    for key, bundle in bundles.items():
        scores = list(getattr(bundle, "baseline_scores", []))
        out[key] = POTThreshold(minimum=minimum).fit(scores)
    return out
