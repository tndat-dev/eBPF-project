"""Run safe, real-syscall attacks through Tetragon and the candidate detector.

Unlike ``--simulate-attack``, this harness executes a static binary inside the
monitored nginx container. Results therefore cover container syscall entry,
Tetragon export/rotation, stream parsing, windowing, inference and response.
"""

import argparse
import hashlib
import json
import os
import shutil
import signal
import statistics
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

from artifact_integrity import model_release_hashes

SCENARIOS = (
    "reverse_shell",
    "container_escape",
    "cryptomining",
    "privilege_escalation",
    "data_exfiltration",
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


def percentile(values, fraction):
    if not values:
        return None
    x = sorted(values)
    position = (len(x) - 1) * fraction
    low = int(position)
    high = min(low + 1, len(x) - 1)
    return x[low] + (x[high] - x[low]) * (position - low)


def read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    rows = []
    for line in path.read_text().splitlines():
        try:
            rows.append(json.loads(line))
        except (ValueError, TypeError):
            continue
    return rows


def ready_pod_names(payload: dict) -> list[str]:
    """Return newest-first pods that are Running, Ready and not terminating."""
    candidates = []
    for item in payload.get("items", []):
        metadata = item.get("metadata", {})
        status = item.get("status", {})
        conditions = {
            condition.get("type"): condition.get("status")
            for condition in status.get("conditions", [])
        }
        containers = status.get("containerStatuses", [])
        if (
            status.get("phase") != "Running"
            or metadata.get("deletionTimestamp")
            or conditions.get("Ready") != "True"
            or not containers
            or not all(container.get("ready") for container in containers)
        ):
            continue
        name = metadata.get("name")
        if name:
            candidates.append((metadata.get("creationTimestamp", ""), name))
    return [name for _, name in sorted(candidates, reverse=True)]


def select_ready_pod(namespace: str, selector: str) -> str:
    raw = subprocess.check_output(
        [
            "kubectl", "get", "pod", "-n", namespace, "-l", selector,
            "-o", "json",
        ],
        text=True,
    )
    payload = json.loads(raw)
    pods = ready_pod_names(payload)
    if not pods:
        observed = [
            {
                "name": item.get("metadata", {}).get("name"),
                "phase": item.get("status", {}).get("phase"),
            }
            for item in payload.get("items", [])
        ]
        raise RuntimeError(
            f"no Running+Ready target pod for {namespace} selector={selector}: "
            f"{observed}"
        )
    return pods[0]


def install_runtime_binary(
    namespace: str,
    selector: str,
    runtime_binary: Path,
    container_binary: str,
    attempts: int = 6,
) -> str:
    """Install into a stable Ready pod, retrying a concurrent rollout."""
    errors = []
    for attempt in range(1, attempts + 1):
        pod = select_ready_pod(namespace, selector)
        copy_result = subprocess.run(
            [
                "kubectl", "cp", str(runtime_binary),
                f"{namespace}/{pod}:{container_binary}",
            ],
            text=True,
            capture_output=True,
        )
        if copy_result.returncode == 0:
            chmod_result = subprocess.run(
                [
                    "kubectl", "exec", "-n", namespace, pod, "--",
                    "chmod", "0755", container_binary,
                ],
                text=True,
                capture_output=True,
            )
            if chmod_result.returncode == 0:
                return pod
            errors.append(
                f"attempt={attempt} pod={pod} chmod: "
                f"{chmod_result.stderr.strip()}"
            )
        else:
            errors.append(
                f"attempt={attempt} pod={pod} copy: "
                f"{copy_result.stderr.strip()}"
            )
        if attempt < attempts:
            time.sleep(2)
    raise RuntimeError("could not install runtime binary: " + " | ".join(errors))


def wait_ready(log_path: Path, process: subprocess.Popen, timeout=30):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if process.poll() is not None:
            raise RuntimeError(
                f"detector exited early rc={process.returncode}: "
                f"{log_path.read_text()[-4000:]}"
            )
        if log_path.exists() and "Anomaly Detector khởi động" in log_path.read_text():
            return
        time.sleep(0.5)
    raise TimeoutError("detector did not become ready")


def stop_process(process: subprocess.Popen):
    if process.poll() is not None:
        return
    process.send_signal(signal.SIGTERM)
    try:
        process.wait(timeout=15)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model-dir", default="models_candidate")
    parser.add_argument("--vocab", default=None,
                        help="Defaults to <model-dir>/vocab.pkl")
    parser.add_argument("--normal-calibration", required=True)
    parser.add_argument("--runtime-binary", default="runtime_attack")
    parser.add_argument("--namespace", default="production")
    parser.add_argument("--selector", default="app=nginx")
    parser.add_argument("--attack-seconds", type=int, default=70)
    parser.add_argument("--rate", type=int, default=20)
    parser.add_argument("--post-attack-wait", type=int, default=45)
    parser.add_argument("--output-dir", default="kernel-regression-results")
    args = parser.parse_args()

    model_dir = Path(args.model_dir).resolve()
    vocab = Path(args.vocab).resolve() if args.vocab else model_dir / "vocab.pkl"
    runtime_binary = Path(args.runtime_binary).resolve()
    if not vocab.is_file():
        raise FileNotFoundError(vocab)
    if not runtime_binary.is_file():
        raise FileNotFoundError(runtime_binary)

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output_dir = Path(args.output_dir) / stamp
    output_dir.mkdir(parents=True, exist_ok=False)
    calibration_source = Path(args.normal_calibration).resolve()
    if not calibration_source.is_file():
        raise FileNotFoundError(calibration_source)

    container_binary = f"/tmp/sentinel-runtime-attack-{os.getpid()}"
    pod = install_runtime_binary(
        args.namespace, args.selector, runtime_binary, container_binary,
    )
    pod_key = f"{args.namespace}/{pod}"

    report = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "method": "real in-container syscalls through Tetragon",
        "model_dir": str(model_dir),
        "model_release_sha256": model_release_hashes(model_dir),
        "vocab": str(vocab),
        "vocab_sha256": sha256(vocab),
        "runtime_binary": str(runtime_binary),
        "runtime_binary_sha256": sha256(runtime_binary),
        "runtime_code_sha256": {
            name: sha256(Path(name).resolve()) for name in RUNTIME_FILES
        },
        "validation_harness_sha256": sha256(Path(__file__).resolve()),
        "calibration_source": str(calibration_source),
        "pod_key": pod_key,
        "attack_seconds": args.attack_seconds,
        "rate_per_second": args.rate,
        "scenarios": {},
    }

    try:
        for scenario in SCENARIOS:
            metrics = output_dir / f"{scenario}.jsonl"
            detector_log = output_dir / f"{scenario}.log"
            calibration = output_dir / f"{scenario}-calibration.json"
            shutil.copy2(calibration_source, calibration)
            env = os.environ.copy()
            env.update({
                "SENTINEL_METRICS": str(metrics.resolve()),
                "SENTINEL_CALIBRATION": str(calibration.resolve()),
                "SENTINEL_WARMUP_WINDOWS": "10",
                # Keep the regression detector identical to the sampled-policy
                # production service.  Falling back to the historical
                # 100-event floor would silently discard valid nginx windows
                # after in-kernel rate limiting and invalidate latency/recall.
                "SENTINEL_MIN_EVENTS": "20",
                "SENTINEL_QUEUE_SIZE": "100000",
                "SENTINEL_CONSUMER_LOG_INTERVAL": "100000",
            })
            with detector_log.open("w") as log_handle:
                detector = subprocess.Popen(
                    [
                        "/home/dat/ml-venv/bin/python", "-u",
                        "anomaly_detector2.py", "--mode", "kubectl",
                        "--model-dir", str(model_dir),
                        "--vocab", str(vocab), "--window", "30",
                        "--threshold", "0.80", "--dry-run",
                    ],
                    stdout=log_handle,
                    stderr=subprocess.STDOUT,
                    env=env,
                )
            attack_started = None
            attack_acknowledged = False
            command_result = None
            try:
                wait_ready(detector_log, detector)
                time.sleep(3)
                command = [
                    "kubectl", "exec", "-n", args.namespace, pod, "--",
                    container_binary, scenario, str(args.attack_seconds),
                    str(args.rate),
                ]
                attack_process = subprocess.Popen(
                    command, text=True, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, bufsize=1,
                )
                # The static binary writes this acknowledgement immediately
                # before issuing its first attack syscall. Timestamp receipt
                # on the master so injection and detection use the same clock,
                # excluding kubectl startup time from the latency metric.
                ack_lines = []
                for _ in range(4):
                    line = attack_process.stderr.readline()
                    if not line:
                        break
                    ack_lines.append(line)
                    if "sentinel-runtime-attack start" in line:
                        attack_acknowledged = True
                        break
                start_ack = "".join(ack_lines)
                attack_started = time.time()
                with metrics.open("a") as metrics_handle:
                    metrics_handle.write(json.dumps({
                        "kind": "injection",
                        "ts": attack_started,
                        "pod_key": pod_key,
                        "attack_type": scenario,
                        "source": "in-container-static-binary-start-ack",
                        "ack": start_ack.strip(),
                    }, sort_keys=True) + "\n")
                try:
                    attack_stdout, attack_stderr = attack_process.communicate(
                        timeout=args.attack_seconds + 30,
                    )
                except subprocess.TimeoutExpired:
                    attack_process.kill()
                    attack_stdout, attack_stderr = attack_process.communicate()
                command_result = subprocess.CompletedProcess(
                    command, attack_process.returncode, attack_stdout,
                    start_ack + attack_stderr,
                )

                deadline = time.time() + args.post_attack_wait
                while time.time() < deadline:
                    detections = [
                        row for row in read_jsonl(metrics)
                        if row.get("kind") == "detection"
                        and row.get("pod_key") == pod_key
                        and row.get("ts", 0) >= attack_started
                    ]
                    if detections:
                        break
                    if detector.poll() is not None:
                        break
                    time.sleep(1)
            finally:
                stop_process(detector)

            rows = read_jsonl(metrics)
            normal_detections = [
                row for row in rows
                if row.get("kind") == "detection"
                and attack_started is not None
                and row.get("ts", 0) < attack_started
            ]
            detections = [
                row for row in rows
                if row.get("kind") == "detection"
                and row.get("pod_key") == pod_key
                and attack_started is not None
                and row.get("ts", 0) >= attack_started
            ]
            inference = [
                float(row["inference_ms"]) for row in rows
                if row.get("kind") == "inference"
                and row.get("inference_ms") is not None
            ]
            first = detections[0] if detections else None
            measured_latency = (
                float(first["ts"] - attack_started) if first else None
            )
            telemetry_latency = (
                float(first["detection_latency"])
                if first and first.get("detection_latency") is not None
                else None
            )
            result = {
                "detected": first is not None,
                "detection_latency_seconds": measured_latency,
                "telemetry_detection_latency_seconds": telemetry_latency,
                "latency_clock_agreement_seconds": (
                    abs(measured_latency - telemetry_latency)
                    if measured_latency is not None
                    and telemetry_latency is not None else None
                ),
                "normal_alerts_before_attack": len(normal_detections),
                "detector_exit_code": detector.returncode,
                "attack_exit_code": (
                    command_result.returncode if command_result else None
                ),
                "attack_start_ack": (
                    command_result.stderr[:1000]
                    if command_result and command_result.stderr else ""
                ),
                "attack_acknowledged": attack_acknowledged,
                "attack_stdout": command_result.stdout[-1000:] if command_result else "",
                "attack_stderr": command_result.stderr[-1000:] if command_result else "",
                "inference_count": len(inference),
                "inference_median_ms": statistics.median(inference) if inference else None,
                "inference_p95_ms": percentile(inference, 0.95),
                "inference_p99_ms": percentile(inference, 0.99),
                "detection": first,
            }
            report["scenarios"][scenario] = result
            (output_dir / "report.partial.json").write_text(
                json.dumps(report, indent=2, sort_keys=True) + "\n"
            )
            print(json.dumps({scenario: result}, sort_keys=True), flush=True)
    finally:
        subprocess.run(
            ["kubectl", "exec", "-n", args.namespace, pod, "--",
             "rm", "-f", container_binary],
            check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )

    report["detected"] = sum(
        bool(item["detected"]) for item in report["scenarios"].values()
    )
    report["total"] = len(SCENARIOS)
    report["all_passed"] = (
        report["detected"] == report["total"]
        and all(
            item["normal_alerts_before_attack"] == 0
            and item["detector_exit_code"] == 0
            and item["attack_exit_code"] == 0
            and item["attack_acknowledged"]
            and item["inference_count"] >= 2
            and item["detection_latency_seconds"] is not None
            and item["telemetry_detection_latency_seconds"] is not None
            and item["latency_clock_agreement_seconds"] <= 0.25
            for item in report["scenarios"].values()
        )
    )
    final_path = output_dir / "report.json"
    final_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(f"report={final_path}")
    return 0 if report["all_passed"] else 4


if __name__ == "__main__":
    raise SystemExit(main())
