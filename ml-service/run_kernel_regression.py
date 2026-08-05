"""Run safe, real-syscall attacks through Tetragon and the candidate detector.

Unlike ``--simulate-attack``, this harness executes a static binary inside the
monitored nginx container. Results therefore cover container syscall entry,
Tetragon export/rotation, stream parsing, windowing, inference and response.
"""

import argparse
import hashlib
import json
import os
import selectors
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
BLIND_SCENARIOS = (
    "local_socket_beacon",
    "namespace_probe",
    "process_fanout",
    "identity_transition_probe",
    "credential_read_burst",
)
SUPPORTED_SCENARIOS = SCENARIOS + BLIND_SCENARIOS
# The static in-container attack binary enters through execve and these two
# scenarios then make an unsampled privilege/namespace syscall.  They are the
# only deterministic fast-path coverage cases. Network-only scenarios remain
# ML-confirmed unless the executed binary itself is a reviewed shell/network
# utility, which protects the normal service-connect path from false positives.
FAST_PATH_EXPECTED_SCENARIOS = frozenset({
    "container_escape", "privilege_escalation",
})
RUNTIME_FILES = (
    "adaptive_threshold.py", "anomaly_detector2.py", "feature_engineering.py",
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
KUBECTL_READ_TIMEOUT_SECONDS = 15
KUBECTL_COPY_TIMEOUT_SECONDS = 30
KUBECTL_MUTATION_TIMEOUT_SECONDS = 15
ATTACK_ACK_TIMEOUT_SECONDS = 20


def sensor_snapshot_healthy(health: dict) -> bool:
    if not isinstance(health, dict):
        return False
    active = health.get("active_tetragon_pods", [])
    expected = health.get("expected_tetragon_pods")
    return bool(
        health.get("require_full_coverage")
        and health.get("coverage_healthy") is True
        and isinstance(expected, int) and expected > 0
        and len(active) == expected
        and int(health.get("backpressure_events", 0)) == 0
        and int(health.get("membership_failures", 0)) == 0
        and int(health.get("coverage_failures", 0)) == 0
        and int(health.get("stream_failures", 0)) == 0
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
        timeout=KUBECTL_READ_TIMEOUT_SECONDS,
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
) -> tuple[str, str]:
    """Install into a stable Ready pod, retrying a concurrent rollout."""
    errors = []
    for attempt in range(1, attempts + 1):
        pod = select_ready_pod(namespace, selector)
        try:
            copy_result = subprocess.run(
                [
                    "kubectl", "cp", str(runtime_binary),
                    f"{namespace}/{pod}:{container_binary}",
                ],
                text=True,
                capture_output=True,
                timeout=KUBECTL_COPY_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired:
            copy_result = None
            errors.append(
                f"attempt={attempt} pod={pod} kubectl-cp timed out after "
                f"{KUBECTL_COPY_TIMEOUT_SECONDS}s"
            )
        if copy_result is not None and copy_result.returncode == 0:
            try:
                chmod_result = subprocess.run(
                    [
                        "kubectl", "exec", "-n", namespace, pod, "--",
                        "chmod", "0755", container_binary,
                    ],
                    text=True,
                    capture_output=True,
                    timeout=KUBECTL_MUTATION_TIMEOUT_SECONDS,
                )
            except subprocess.TimeoutExpired:
                chmod_result = None
                errors.append(
                    f"attempt={attempt} pod={pod} chmod timed out after "
                    f"{KUBECTL_MUTATION_TIMEOUT_SECONDS}s"
                )
            if chmod_result is not None and chmod_result.returncode == 0:
                return pod, "kubectl-cp"
            if chmod_result is not None:
                errors.append(
                    f"attempt={attempt} pod={pod} chmod: "
                    f"{chmod_result.stderr.strip()}"
                )
        elif copy_result is not None:
            errors.append(
                f"attempt={attempt} pod={pod} kubectl-cp: "
                f"{copy_result.stderr.strip()}"
            )

        # ``kubectl cp`` is a tar-over-SPDY stream and can hang against an
        # otherwise healthy pod.  A bounded stdin stream uses the same exec
        # transport but removes tar negotiation.  The frozen binary bytes are
        # unchanged and are hash-checked in the report.
        try:
            stream_result = subprocess.run(
                [
                    "kubectl", "exec", "-i", "-n", namespace, pod, "--",
                    "sh", "-c", 'cat > "$1" && chmod 0755 "$1"',
                    "sentinel-copy", container_binary,
                ],
                input=runtime_binary.read_bytes(),
                capture_output=True,
                timeout=KUBECTL_COPY_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired:
            stream_result = None
            errors.append(
                f"attempt={attempt} pod={pod} exec-stdin timed out after "
                f"{KUBECTL_COPY_TIMEOUT_SECONDS}s"
            )
        if stream_result is not None and stream_result.returncode == 0:
            return pod, "kubectl-exec-stdin"
        if stream_result is not None:
            stderr = stream_result.stderr.decode(errors="replace")
            errors.append(
                f"attempt={attempt} pod={pod} exec-stdin: {stderr.strip()}"
            )
        if attempt < attempts:
            time.sleep(2)
    raise RuntimeError("could not install runtime binary: " + " | ".join(errors))


def read_attack_start_ack(
    process: subprocess.Popen,
    timeout: float = ATTACK_ACK_TIMEOUT_SECONDS,
    max_lines: int = 4,
) -> tuple[str, bool]:
    """Read the attack start marker without an unbounded ``readline``."""
    if process.stderr is None:
        return "", False
    selector = selectors.DefaultSelector()
    selector.register(process.stderr, selectors.EVENT_READ)
    lines = []
    deadline = time.monotonic() + timeout
    try:
        while len(lines) < max_lines:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not selector.select(remaining):
                break
            line = process.stderr.readline()
            if not line:
                break
            lines.append(line)
            if "sentinel-runtime-attack start" in line:
                return "".join(lines), True
    finally:
        selector.close()
    return "".join(lines), False


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


def require_tetragon_full_coverage() -> None:
    """Fail before injecting attacks if the eBPF sensor set is incomplete."""
    result = subprocess.run(
        ["kubectl", "-n", "kube-system", "get", "daemonset", "tetragon",
         "-o", "jsonpath={.status.desiredNumberScheduled},{.status.numberReady},{.status.numberAvailable}"],
        check=True, capture_output=True, text=True,
        timeout=KUBECTL_READ_TIMEOUT_SECONDS,
    )
    try:
        desired, ready, available = (int(value) for value in result.stdout.strip().split(","))
    except ValueError as exc:
        raise RuntimeError(
            f"cannot parse Tetragon coverage: {result.stdout!r}"
        ) from exc
    if desired <= 0 or ready != desired or available != desired:
        raise RuntimeError(
            "refusing kernel validation with incomplete Tetragon coverage: "
            f"desired={desired} ready={ready} available={available}"
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model-dir", default="models_candidate")
    parser.add_argument("--vocab", default=None,
                        help="Defaults to <model-dir>/vocab.pkl")
    parser.add_argument("--normal-calibration", required=True)
    parser.add_argument("--runtime-binary", default="runtime_attack")
    parser.add_argument("--namespace", default="production")
    parser.add_argument("--selector", default="app=nginx")
    parser.add_argument("--window", type=int,
                        default=int(os.environ.get("SENTINEL_WINDOW_SECONDS", "10")),
                        help="Feature window in seconds; must match candidate training")
    parser.add_argument("--minimum-events", type=int, default=20,
                        help="Runtime event floor; must match the release contract")
    parser.add_argument("--attack-seconds", type=int, default=70)
    parser.add_argument("--rate", type=int, default=20)
    parser.add_argument("--post-attack-wait", type=int, default=45)
    parser.add_argument("--output-dir", default="kernel-regression-results")
    parser.add_argument(
        "--scenarios", default=",".join(SCENARIOS),
        help="Comma-separated subset for diagnosis; release matrix uses all five",
    )
    parser.add_argument(
        "--fast-path-expected",
        default=",".join(sorted(FAST_PATH_EXPECTED_SCENARIOS)),
        help="Comma-separated selected scenarios required to emit early-warning",
    )
    parser.add_argument("--seed", type=int, default=0,
                        help="Frozen attack-trial seed passed to the runtime binary")
    args = parser.parse_args()
    if args.window < 5:
        raise ValueError("--window must be at least 5 seconds")
    if args.minimum_events < 1:
        raise ValueError("--minimum-events must be positive")
    for name, value in VALIDATION_POLICY_DEFAULTS.items():
        os.environ.setdefault(name, value)
    scenarios = tuple(
        item.strip() for item in args.scenarios.split(",") if item.strip()
    )
    unknown_scenarios = sorted(set(scenarios) - set(SUPPORTED_SCENARIOS))
    if (not scenarios or unknown_scenarios
            or len(scenarios) != len(set(scenarios))):
        raise ValueError(
            "invalid scenario selection: values must be known and unique; "
            f"unknown={unknown_scenarios}"
        )
    fast_path_expected = frozenset(
        item.strip() for item in args.fast_path_expected.split(",")
        if item.strip()
    )
    if not fast_path_expected.issubset(scenarios):
        raise ValueError(
            "--fast-path-expected must be a subset of selected scenarios: "
            f"unexpected={sorted(fast_path_expected - set(scenarios))}"
        )

    require_tetragon_full_coverage()

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
    pod, binary_delivery_method = install_runtime_binary(
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
        "binary_delivery_method": binary_delivery_method,
        "runtime_code_sha256": {
            name: sha256(Path(name).resolve()) for name in RUNTIME_FILES
        },
        "validation_harness_sha256": sha256(Path(__file__).resolve()),
        "calibration_source": str(calibration_source),
        "pod_key": pod_key,
        "window_seconds": args.window,
        "minimum_events": args.minimum_events,
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
        "attack_seconds": args.attack_seconds,
        "rate_per_second": args.rate,
        "seed": args.seed,
        "fast_path_expected_scenarios": sorted(fast_path_expected),
        "scenarios": {},
    }

    try:
        for scenario in scenarios:
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
                "SENTINEL_MIN_EVENTS": str(args.minimum_events),
                "SENTINEL_QUEUE_SIZE": "100000",
                "SENTINEL_CONSUMER_LOG_INTERVAL": "100000",
                "SENTINEL_REQUIRE_FULL_TETRAGON_COVERAGE": "true",
                "SENTINEL_TETRAGON_DAEMONSET": "tetragon",
            })
            with detector_log.open("w") as log_handle:
                detector = subprocess.Popen(
                    [
                        "/home/dat/ml-venv/bin/python", "-u",
                        "anomaly_detector2.py", "--mode", "kubectl",
                        "--model-dir", str(model_dir),
                        "--vocab", str(vocab), "--window", str(args.window),
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
                    str(args.rate), str(args.seed),
                ]
                attack_process = subprocess.Popen(
                    command, text=True, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, bufsize=1,
                )
                # The static binary writes this acknowledgement immediately
                # before issuing its first attack syscall. Timestamp receipt
                # on the master so injection and detection use the same clock,
                # excluding kubectl startup time from the latency metric.
                start_ack, attack_acknowledged = read_attack_start_ack(
                    attack_process,
                )
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
            early_warnings = [
                row for row in rows
                if row.get("kind") == "early_warning"
                and row.get("pod_key") == pod_key
                and attack_started is not None
                and row.get("ts", 0) >= attack_started
            ]
            health_rows = [
                row for row in rows if row.get("kind") == "runtime_health"
            ]
            sensors_healthy = bool(health_rows) and all(
                sensor_snapshot_healthy(row.get("sensor_health"))
                for row in health_rows
            )
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
            first_early = early_warnings[0] if early_warnings else None
            early_latency = (
                float(first_early["ts"] - attack_started)
                if first_early else None
            )
            early_telemetry_latency = (
                float(first_early["detection_latency"])
                if first_early and first_early.get("detection_latency") is not None
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
                "sensor_health_samples": len(health_rows),
                "sensor_health_healthy": sensors_healthy,
                "sensor_health": (
                    health_rows[-1].get("sensor_health") if health_rows else None
                ),
                # Fast path is measured, but deliberately not part of the
                # all-scenario ML release gate: it is an early-warning lane
                # for high-specificity syscall sequences only.
                "fast_path_warning_count": len(early_warnings),
                "fast_path_expected": scenario in fast_path_expected,
                "fast_path_expected_matched": (
                    bool(first_early)
                    if scenario in fast_path_expected else None
                ),
                "fast_path_latency_seconds": early_latency,
                "fast_path_telemetry_latency_seconds": early_telemetry_latency,
                "fast_path_latency_clock_agreement_seconds": (
                    abs(early_latency - early_telemetry_latency)
                    if early_latency is not None
                    and early_telemetry_latency is not None else None
                ),
                "fast_path_event_to_warning_seconds": (
                    first_early.get("event_to_warning_seconds")
                    if first_early else None
                ),
                "fast_path_processing_ms": (
                    first_early.get("processing_ms") if first_early else None
                ),
                "fast_path_warning": first_early,
                "detection": first,
            }
            report["scenarios"][scenario] = result
            (output_dir / "report.partial.json").write_text(
                json.dumps(report, indent=2, sort_keys=True) + "\n"
            )
            print(json.dumps({scenario: result}, sort_keys=True), flush=True)
    finally:
        try:
            subprocess.run(
                ["kubectl", "exec", "-n", args.namespace, pod, "--",
                 "rm", "-f", container_binary],
                check=False, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=KUBECTL_MUTATION_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired:
            # Cleanup is best effort and must not erase a completed trial.
            pass

    report["detected"] = sum(
        bool(item["detected"]) for item in report["scenarios"].values()
    )
    report["total"] = len(scenarios)
    report["all_passed"] = (
        report["detected"] == report["total"]
        and all(
            item["normal_alerts_before_attack"] == 0
            and item["detector_exit_code"] == 0
            and item["attack_exit_code"] == 0
            and item["attack_acknowledged"]
            and item["sensor_health_healthy"]
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
