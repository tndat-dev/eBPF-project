"""Run the real-syscall regression suite against every production model."""
from __future__ import annotations

import argparse
import hashlib
import json
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
    "graph_signals.py", "ml_models.py", "tetragon_consumer.py",
    "sentinel/telemetry.py",
)


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model-dir", required=True)
    parser.add_argument("--normal-calibration", required=True)
    parser.add_argument("--runtime-binary", default="runtime_attack")
    parser.add_argument("--attack-seconds", type=int, default=70)
    parser.add_argument("--rate", type=int, default=20)
    parser.add_argument("--post-attack-wait", type=int, default=45)
    parser.add_argument("--output-root", default="kernel-regression-matrix")
    args = parser.parse_args()

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
            "--namespace", namespace,
            "--selector", selector,
            "--attack-seconds", str(args.attack_seconds),
            "--rate", str(args.rate),
            "--post-attack-wait", str(args.post_attack_wait),
            "--output-dir", str(output),
        ]
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
            and item["report"].get("runtime_code_sha256")
            == aggregate["runtime_code_sha256"]
            and item["report"].get("model_release_sha256")
            == aggregate["model_release_sha256"]
            for item in aggregate["workloads"].values()
        )
    )
    final = root / "report.json"
    final.write_text(json.dumps(aggregate, indent=2, sort_keys=True) + "\n")
    print(f"report={final}")
    return 0 if aggregate["all_passed"] else 8


if __name__ == "__main__":
    raise SystemExit(main())
