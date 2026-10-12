"""Score the frozen idle-aware candidate in shadow mode; never emit alerts."""
from __future__ import annotations

import argparse
from collections import OrderedDict, deque
import json
import os
from pathlib import Path
import sys
import time

import numpy as np

from .detect import RotatingJsonlFollower
from .encoding import decode_vector
from .idle_candidate import FEATURE_CONTRACT, FEATURE_DIM, IdleCandidateScorer
from .candidate_policy import CandidatePreviewPolicy


EXTENDED_SCHEMA = "sentinel-pulse-extended-feature-v2"


class SegmentedJsonlFollower:
    """Follow append-only feature files across collector segment boundaries."""

    def __init__(self, root: Path, *, from_start: bool = False,
                 poll_seconds: float = 0.05):
        if poll_seconds < 0:
            raise ValueError("poll interval cannot be negative")
        self.root = root
        self.segments = root / "segments"
        self.from_start = from_start
        self.poll_seconds = poll_seconds
        self.source = None
        self.current_dir = None
        self.current_number = 0
        self._initial = True

    def _available(self):
        if not self.segments.is_dir():
            return []
        result = []
        for directory in self.segments.glob("s[0-9]*"):
            try:
                number = int(directory.name[1:])
            except ValueError:
                continue
            path = directory / "features.jsonl"
            if path.is_file():
                result.append((number, directory, path))
        return sorted(result)

    def _open_next(self) -> bool:
        available = self._available()
        if not available:
            return False
        if self._initial:
            if self.from_start:
                selected = available[0]
            else:
                active = [item for item in available
                          if not (item[1] / "TERMINAL.json").exists()]
                selected = active[-1] if active else available[-1]
        else:
            selected = next((item for item in available
                             if item[0] > self.current_number), None)
            if selected is None:
                return False
        number, directory, path = selected
        try:
            source = path.open(encoding="utf-8")
        except FileNotFoundError:
            return False
        # A restarted live scorer must not replay a potentially large stale
        # backlog. New segments after this one are consumed from their start.
        if self._initial and not self.from_start:
            source.seek(0, os.SEEK_END)
        self.source = source
        self.current_dir = directory
        self.current_number = number
        self._initial = False
        return True

    def readline(self) -> str:
        while True:
            if self.source is None and not self._open_next():
                time.sleep(self.poll_seconds)
                continue
            line = self.source.readline()
            if line.endswith("\n"):
                return line
            if (self.current_dir / "TERMINAL.json").is_file():
                self.source.close()
                self.source = None
                self.current_dir = None
                continue
            time.sleep(self.poll_seconds)

    def close(self) -> None:
        if self.source is not None:
            self.source.close()
            self.source = None


class CandidateShadowRuntime:
    """Maintain per-container contiguous history and write score-only records."""

    def __init__(self, scorer: IdleCandidateScorer, *,
                 max_gap_seconds: float = 0.8, max_identities: int = 10_000,
                 policy: CandidatePreviewPolicy | None = None):
        if not 0.35 <= max_gap_seconds <= 1.5:
            raise ValueError("max gap must cover a 500 ms cadence and stay <= 1.5 s")
        if max_identities < 1:
            raise ValueError("max_identities must be positive")
        self.scorer = scorer
        self.history_size = int(scorer.manifest["history_windows"])
        self.max_gap_seconds = max_gap_seconds
        self.max_identities = max_identities
        if policy is not None and policy.scorer is not scorer:
            raise ValueError("preview policy must use the same pinned scorer")
        self.policy = policy
        self.histories: OrderedDict[tuple, tuple[float, deque]] = OrderedDict()

    @staticmethod
    def _identity(record: dict) -> tuple:
        fields = ("workload_key", "pod_uid", "container_name",
                  "workload_revision", "cgroup_id")
        values = tuple(record.get(field) for field in fields)
        if (not all(value is not None and str(value) for value in values)
                or any(str(value).lower() == "unknown" for value in values)):
            raise ValueError("feature record has incomplete workload identity")
        return values

    def observe(self, record: dict, *, processed_at: float | None = None) -> dict:
        now = time.time() if processed_at is None else float(processed_at)
        if record.get("schema") != EXTENDED_SCHEMA:
            raise ValueError("record is not idle-aware extended feature v2")
        if record.get("telemetry_contract") != FEATURE_CONTRACT:
            raise ValueError("record telemetry contract does not match candidate")
        if record.get("vector_dim") != FEATURE_DIM:
            raise ValueError("feature record must declare a 249-dimensional vector")
        vector = decode_vector(record)
        if vector.shape != (FEATURE_DIM,) or not np.isfinite(vector).all():
            raise ValueError("feature vector must contain 249 finite values")
        end = float(record["window_end"])
        if not np.isfinite(end):
            raise ValueError("window_end must be finite")
        identity = self._identity(record)
        prior = self.histories.pop(identity, None)
        reset_reason = None
        history = deque(maxlen=self.history_size + 1)
        collector_stats = record.get("collector_stats") or {}
        hard_errors = ("task_state_update_fail", "snapshot_projection_fail")
        if any(int(collector_stats.get(name, 0)) > 0 for name in hard_errors):
            base = {
                "schema": "sentinel-pulse-candidate-shadow-score-v1",
                "status": "degraded_telemetry",
                "candidate_manifest_sha256": self.scorer.manifest_sha256,
                "workload_key": str(identity[0]),
                "pod_uid": str(identity[1]),
                "container_name": str(identity[2]),
                "workload_revision": str(identity[3]),
                "cgroup_id": str(identity[4]),
                "window_end": end,
                "processed_at": now,
                "history_available": 0,
                "history_required": self.history_size + 1,
                "reset_reason": "collector_integrity_error",
                "collector_stats": collector_stats,
                "alert": False,
                "policy_applied": False,
                "serving_compatible": False,
            }
            return base
        if prior is not None:
            previous_end, previous_history = prior
            gap = end - previous_end
            if not 0.35 <= gap <= self.max_gap_seconds:
                reset_reason = "non_contiguous_window"
            else:
                history = previous_history
        history.append(vector)
        self.histories[identity] = (end, history)
        evicted = None
        if len(self.histories) > self.max_identities:
            evicted, _ = self.histories.popitem(last=False)

        base = {
            "schema": "sentinel-pulse-candidate-shadow-score-v1",
            "status": "warming",
            "candidate_manifest_sha256": self.scorer.manifest_sha256,
            "workload_key": str(identity[0]),
            "pod_uid": str(identity[1]),
            "container_name": str(identity[2]),
            "workload_revision": str(identity[3]),
            "cgroup_id": str(identity[4]),
            "window_end": end,
            "processed_at": now,
            "history_available": len(history),
            "history_required": self.history_size + 1,
            "reset_reason": reset_reason,
            "alert": False,
            "policy_applied": False,
            "serving_compatible": False,
            "evicted_identity": list(evicted) if evicted is not None else None,
        }
        if len(history) < self.history_size + 1:
            return base

        context = np.stack(history).reshape(-1)
        started = time.perf_counter()
        score = self.scorer.score_context(str(identity[0]), context)
        base["inference_ms"] = (time.perf_counter() - started) * 1000
        base.update(score)
        base["status"] = score["status"]
        if self.policy is not None:
            base.update(self.policy.evaluate(score))
        else:
            base.update(policy_evaluated=False, candidate_alert_preview=None,
                        preview_reason="no_policy_registered")
        base["alert"] = False  # Keep this invariant even if scorer API evolves.
        base["policy_applied"] = False
        base["serving_compatible"] = False
        # This is feature-window-end-to-score age, not kernel-to-alert latency.
        # Keep the sign so clock skew is visible rather than silently clamped.
        base["feature_event_age_seconds"] = now - end
        return base


def run(features: Path, output: Path, candidate_dir: Path,
        manifest_sha256: str, run_id: str, *, from_start: bool = False,
        max_gap_seconds: float = 0.8, policy_path: Path | None = None,
        segmented: bool = False) -> None:
    scorer = IdleCandidateScorer(candidate_dir, manifest_sha256)
    policy = CandidatePreviewPolicy.load(policy_path, scorer) if policy_path else None
    runtime = CandidateShadowRuntime(scorer, max_gap_seconds=max_gap_seconds,
                                     policy=policy)
    output.parent.mkdir(parents=True, exist_ok=True)
    follower = (SegmentedJsonlFollower(features, from_start=from_start)
                if segmented else RotatingJsonlFollower(features, from_start=from_start))
    try:
        with output.open("a", encoding="utf-8") as sink:
            while True:
                line = follower.readline()
                try:
                    record = json.loads(line)
                    decision = runtime.observe(record)
                    decision["run_id"] = run_id
                except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
                    decision = {
                        "schema": "sentinel-pulse-candidate-shadow-score-v1",
                        "status": "record_rejected",
                        "reason": type(exc).__name__,
                        "run_id": run_id,
                        "processed_at": time.time(),
                        "alert": False,
                        "policy_applied": False,
                        "serving_compatible": False,
                    }
                sink.write(json.dumps(decision, sort_keys=True, allow_nan=False) + "\n")
                sink.flush()
    finally:
        follower.close()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    feature_source = parser.add_mutually_exclusive_group(required=True)
    feature_source.add_argument("--features", type=Path,
                                help="one append-only JSONL feature file")
    feature_source.add_argument("--features-root", type=Path,
                                help="collector root containing segments/sNNNN/features.jsonl")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--candidate-dir", type=Path, required=True)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--policy", type=Path,
                        help="optional frozen candidate preview policy; still cannot emit alerts")
    parser.add_argument("--from-start", action="store_true")
    parser.add_argument("--max-gap-seconds", type=float, default=0.8)
    args = parser.parse_args(argv)
    try:
        run(args.features or args.features_root, args.output, args.candidate_dir,
            args.manifest_sha256, args.run_id, from_start=args.from_start,
            max_gap_seconds=args.max_gap_seconds, policy_path=args.policy,
            segmented=args.features_root is not None)
    except (OSError, ValueError) as exc:
        print(f"candidate shadow unavailable: {type(exc).__name__}", file=sys.stderr)
        return 65
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
