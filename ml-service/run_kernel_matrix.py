"""Run the real-syscall regression suite against every production model."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from artifact_integrity import model_release_hashes

TARGETS = (
    ("production/nginx", "production", "app=nginx"),
    ("production/redis", "production", "app=redis"),
    ("default/postgres", "default", "app=postgres"),
)
RUNTIME_FILES = (
    "adaptive_threshold.py", "anomaly_detector2.py", "feature_engineering.py",
    "feature_capture_io.py",
    "graph_signals.py", "ml_models.py", "tetragon_consumer.py",
    "workload_identity.py", "sentinel/fast_path.py", "sentinel/telemetry.py",
)
VALIDATION_POLICY_DEFAULTS = {
    "SENTINEL_CONFIRMATION_FLOOR_RATIO": "0.94",
    "SENTINEL_BEHAVIOR_CONFIRMATION_FLOOR": "0.45",
    "SENTINEL_FAST_PATH_CONFIRMATION_FLOOR": "0.20",
    "SENTINEL_POD_STARTUP_GRACE_SECONDS": "60",
    "SENTINEL_EXTREME_VOLUME_FACTOR": "2.0",
}


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def percentile(values, fraction):
    if not values:
        return None
    ordered = sorted(values)
    position = (len(ordered) - 1) * fraction
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model-dir", required=True)
    parser.add_argument("--normal-calibration", required=True)
    parser.add_argument("--runtime-binary", default="runtime_attack")
    parser.add_argument("--window", type=int,
                        default=int(os.environ.get("SENTINEL_WINDOW_SECONDS", "10")),
                        help="Feature window in seconds; must match candidate training")
    parser.add_argument("--attack-seconds", type=int, default=70)
    parser.add_argument("--rate", type=int, default=20)
    parser.add_argument("--post-attack-wait", type=int, default=45)
    parser.add_argument("--output-root", default="kernel-regression-matrix")
    parser.add_argument(
        "--feature-capture-mode", choices=("off", "aggregate", "sequence"),
        default=os.environ.get("SENTINEL_FEATURE_CAPTURE", "off"),
    )
    parser.add_argument("--capture-release-id", default=None)
    args = parser.parse_args()
    if args.window < 5:
        raise ValueError("--window must be at least 5 seconds")
    for name, value in VALIDATION_POLICY_DEFAULTS.items():
        os.environ.setdefault(name, value)

    model_dir = Path(args.model_dir).resolve()
    vocab = model_dir / "vocab.pkl"
    calibration = Path(args.normal_calibration).resolve()
    runtime_binary = Path(args.runtime_binary).resolve()
    if not vocab.is_file():
        raise FileNotFoundError(vocab)
    if not calibration.is_file():
        raise FileNotFoundError(calibration)
    if not runtime_binary.is_file():
        raise FileNotFoundError(runtime_binary)

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    root = Path(args.output_root) / stamp
    root.mkdir(parents=True, exist_ok=False)
    aggregate = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "method": "real in-container syscalls through Tetragon, all workloads",
        "model_dir": str(model_dir),
        "model_release_sha256": model_release_hashes(model_dir),
        "vocab": str(vocab),
        "vocab_sha256": sha256(vocab),
        "normal_calibration": str(calibration),
        "normal_calibration_sha256": sha256(calibration),
        "window_seconds": args.window,
        "confirmation_policy": {
            "hysteresis_ratio": float(os.environ.get(
                "SENTINEL_CONFIRMATION_FLOOR_RATIO", "1.0"
            )),
            "behavior_confirmation_floor": float(os.environ.get(
                "SENTINEL_BEHAVIOR_CONFIRMATION_FLOOR", ".8"
            )),
            "fast_path_confirmation_floor": float(os.environ.get(
                "SENTINEL_FAST_PATH_CONFIRMATION_FLOOR", ".8"
            )),
            "pod_startup_grace_seconds": float(os.environ.get(
                "SENTINEL_POD_STARTUP_GRACE_SECONDS", "0"
            )),
            "extreme_volume_factor": float(os.environ.get(
                "SENTINEL_EXTREME_VOLUME_FACTOR", "2.0"
            )),
        },
        "runtime_binary": str(runtime_binary),
        "runtime_binary_sha256": sha256(runtime_binary),
        "runtime_code_sha256": {
            name: sha256(Path(name).resolve()) for name in RUNTIME_FILES
        },
        "validation_harness_sha256": sha256(Path(__file__).resolve()),
        "workloads": {},
    }

    for pod_key, namespace, selector in TARGETS:
        label = pod_key.replace("/", "__")
        output = root / label
        command = [
            sys.executable,
            "run_kernel_regression.py",
            "--model-dir", str(model_dir),
            "--normal-calibration", str(calibration),
            "--runtime-binary", str(runtime_binary),
            "--window", str(args.window),
            "--namespace", namespace,
            "--selector", selector,
            "--attack-seconds", str(args.attack_seconds),
            "--rate", str(args.rate),
            "--post-attack-wait", str(args.post_attack_wait),
            "--output-dir", str(output),
            "--feature-capture-mode", args.feature_capture_mode,
        ]
        if args.feature_capture_mode != "off":
            if not args.capture_release_id:
                raise ValueError(
                    "--capture-release-id is required when capture is enabled"
                )
            command.extend([
                "--capture-release-id", args.capture_release_id,
                "--capture-run-id", f"{stamp}:{label}",
            ])
        result = subprocess.run(command)
        reports = sorted(output.glob("*/report.json"))
        report = json.loads(reports[-1].read_text()) if reports else {
            "all_passed": False,
            "detected": 0,
            "total": 5,
            "error": "child report missing",
        }
        aggregate["workloads"][pod_key] = {
            "exit_code": result.returncode,
            "report_path": str(reports[-1].resolve()) if reports else None,
            "report": report,
        }
        (root / "report.partial.json").write_text(
            json.dumps(aggregate, indent=2, sort_keys=True) + "\n"
        )

    aggregate["detected"] = sum(
        int(item["report"].get("detected", 0))
        for item in aggregate["workloads"].values()
    )
    aggregate["total"] = sum(
        int(item["report"].get("total", 5))
        for item in aggregate["workloads"].values()
    )
    aggregate["all_passed"] = bool(
        len(aggregate["workloads"]) == len(TARGETS)
        and aggregate["detected"] == aggregate["total"] == 15
        and all(
            item["exit_code"] == 0
            and item["report"].get("all_passed")
            and Path(item["report"].get("model_dir", "")).resolve() == model_dir
            and item["report"].get("vocab_sha256") == aggregate["vocab_sha256"]
            and item["report"].get("runtime_binary_sha256")
            == aggregate["runtime_binary_sha256"]
            and item["report"].get("window_seconds") == args.window
            and item["report"].get("runtime_code_sha256")
            == aggregate["runtime_code_sha256"]
            and item["report"].get("model_release_sha256")
            == aggregate["model_release_sha256"]
            for item in aggregate["workloads"].values()
        )
    )
    fast_path_rows = [
        scenario
        for workload in aggregate["workloads"].values()
        for scenario in workload["report"].get("scenarios", {}).values()
        if scenario.get("fast_path_warning")
    ]
    fast_path_latencies = [
        float(scenario["fast_path_latency_seconds"])
        for scenario in fast_path_rows
        if scenario.get("fast_path_latency_seconds") is not None
    ]
    fast_path_expected = [
        scenario
        for workload in aggregate["workloads"].values()
        for scenario in workload["report"].get("scenarios", {}).values()
        if scenario.get("fast_path_expected")
    ]
    aggregate["fast_path"] = {
        "warning_scenarios": len(fast_path_rows),
        "expected_warning_scenarios": len(fast_path_expected),
        "expected_warning_matched": sum(
            bool(scenario.get("fast_path_expected_matched"))
            for scenario in fast_path_expected
        ),
        "total_scenarios": aggregate["total"],
        "latency_seconds_p50": percentile(fast_path_latencies, 0.50),
        "latency_seconds_p95": percentile(fast_path_latencies, 0.95),
        "latency_seconds_max": max(fast_path_latencies) if fast_path_latencies else None,
        "note": (
            "observability only: fast path is early-warning and does not "
            "replace the all-scenario ML confirmation gate"
        ),
    }
    final = root / "report.json"
    final.write_text(json.dumps(aggregate, indent=2, sort_keys=True) + "\n")
    print(f"report={final}")
    return 0 if aggregate["all_passed"] else 8


if __name__ == "__main__":
    raise SystemExit(main())
