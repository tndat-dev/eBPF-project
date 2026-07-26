"""Profile complete detector callbacks without enabling a live responder."""

import argparse
import cProfile
import json
import os
import pstats
import tempfile
import time
from pathlib import Path

import numpy as np


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--model-dir", required=True)
    parser.add_argument("--vocab", default=None,
                        help="Defaults to <model-dir>/vocab.pkl")
    parser.add_argument("--dataset", required=True)
    parser.add_argument("--pod-key", default="production/nginx")
    parser.add_argument("--iterations", type=int, default=50)
    parser.add_argument("--output-prefix", default="detection-cycle-profile")
    args = parser.parse_args()
    model_dir = Path(args.model_dir).resolve()
    vocab = Path(args.vocab).resolve() if args.vocab else model_dir / "vocab.pkl"
    if not vocab.is_file():
        raise FileNotFoundError(vocab)

    with tempfile.TemporaryDirectory(prefix="sentinel-profile-") as temporary:
        os.environ["SENTINEL_METRICS"] = str(Path(temporary) / "metrics.jsonl")
        os.environ["SENTINEL_CALIBRATION"] = str(
            Path(temporary) / "calibration.json"
        )
        os.environ["SENTINEL_WARMUP_WINDOWS"] = "1"

        # Import after setting telemetry paths; telemetry resolves its output
        # location at module import time.
        from anomaly_detector2 import AnomalyDetector
        from feature_engineering import FeatureVector
        from ml_models import ModelManager

        manager = ModelManager(str(model_dir), str(vocab))
        manager.load_all()
        if args.pod_key not in manager.list_models():
            raise KeyError(args.pod_key)
        data = np.load(args.dataset, allow_pickle=False)
        vector = data[0]
        namespace, deployment = args.pod_key.split("/", 1)
        event_count = 1000
        feature = FeatureVector(
            pod_name=f"{deployment}-0000000000-00000",
            pod_namespace=namespace,
            node_name="profile-node",
            window_start=time.time() - 30,
            window_end=time.time(),
            vector=vector,
            raw_syscalls=["read"] * event_count,
            syscall_counts={"read": event_count},
        )
        detector = AnomalyDetector(manager, on_alert=lambda _alert: None)
        profiler = cProfile.Profile()
        profiler.enable()
        started = time.perf_counter()
        for _ in range(args.iterations):
            detector.handle_feature_vector(feature)
        wall_seconds = time.perf_counter() - started
        profiler.disable()

        prefix = Path(args.output_prefix)
        profiler.dump_stats(str(prefix.with_suffix(".prof")))
        with prefix.with_suffix(".txt").open("w") as handle:
            stats = pstats.Stats(profiler, stream=handle)
            stats.sort_stats("cumulative")
            stats.print_stats(20)
        report = {
            "model_dir": str(model_dir),
            "vocab": str(vocab),
            "dataset": str(Path(args.dataset).resolve()),
            "pod_key": args.pod_key,
            "iterations": args.iterations,
            "wall_seconds": wall_seconds,
            "mean_cycle_ms": wall_seconds * 1000.0 / args.iterations,
            "profile": str(prefix.with_suffix(".prof")),
            "top20": str(prefix.with_suffix(".txt")),
        }
        prefix.with_suffix(".json").write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n"
        )
        print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
