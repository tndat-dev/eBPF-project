"""Execute the frozen Sentinel Pulse blind matrix without a promotion path.

This runner is intentionally usable only after ``start_500ms_blind_matrix.sh``
has bound an exact passed normal report, model, policy, attack contract and
static binary.  Detection misses are retained.  Any transport, pod identity or
kernel-event provenance failure invalidates the campaign instead of silently
rerunning a trial.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import random
import subprocess
import time

from .blind_contract import expected_matrix, load_contract, marker_matrix_key
from .integrity import sha256_file
from .tetragon_evidence import EXEC_PROVENANCE_POLICY, find_execve_kprobe_event


DEFAULT_BINARY_IN_CONTAINER = "/tmp/sentinel-runtime-attack-blind"
# CloudNativePG mounts /tmp read-only, while /run is an ephemeral writable
# runtime filesystem.  Tetragon was also empirically verified to emit the
# exact /run process_exec identity; /dev/shm execution was not observable.
CONTROLLER_BINARY_PATHS = {
    "aims-postgres-cnpg": "/run/sentinel-runtime-attack-blind",
}
PRIMARY_CONTAINER_ORDER = (
    "app", "web", "kafka", "postgres", "rabbitmq", "aims-redis",
    "aims-redis-sentinel-sentinel", "istio-proxy", "minio",
    "topic-operator", "pod-slice",
)


def binary_path_for_controller(controller: str) -> str:
    return CONTROLLER_BINARY_PATHS.get(controller, DEFAULT_BINARY_IN_CONTAINER)


def atomic_json(path: Path, payload: dict) -> None:
    temporary = path.with_suffix(path.suffix + f".tmp-{os.getpid()}")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    temporary.replace(path)


def append_jsonl(path: Path, payload: dict) -> None:
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n")
        handle.flush()
        os.fsync(handle.fileno())


def build_schedule(contract: dict, seed: int) -> list[dict]:
    rows = [
        {
            "workload_controller": workload,
            "scenario": scenario,
            "seed": int(trial["seed"]),
            "rate_per_second": int(trial["rate_per_second"]),
        }
        for workload, scenario, trial_seed, trial_rate in expected_matrix(contract)
        for trial in contract["matrix"]["trials"]
        if int(trial["seed"]) == trial_seed
        and int(trial["rate_per_second"]) == trial_rate
    ]
    # expected_matrix is a set, so sort before applying the pre-registered shuffle.
    rows.sort(key=lambda item: (
        item["workload_controller"], item["scenario"],
        item["seed"], item["rate_per_second"],
    ))
    random.Random(seed).shuffle(rows)
    return rows


def load_pilot_schedule(path: Path, contract: dict, start: dict) -> list[dict]:
    """Load a pre-attack engineering subset without weakening the formal path."""
    document = json.loads(path.read_text(encoding="utf-8"))
    if document.get("schema") != "sentinel-pulse-attack-latency-pilot-plan-v1":
        raise ValueError("unsupported attack-latency pilot plan")
    if start.get("evidence_class") != "nonformal_attack_latency_pilot":
        raise ValueError("pilot run must be explicitly non-formal")
    if start.get("accuracy_claim_allowed") is not False:
        raise ValueError("pilot run must forbid accuracy claims")
    if start.get("automatic_promotion") is not False:
        raise ValueError("pilot run must forbid automatic promotion")
    if start.get("pilot_plan_sha256") != sha256_file(path):
        raise ValueError("pilot plan differs from frozen start binding")
    schedule = document.get("schedule")
    if not isinstance(schedule, list) or not schedule:
        raise ValueError("pilot plan has no schedule")
    expected = int(start.get("expected_injections", -1))
    if len(schedule) != expected:
        raise ValueError("pilot schedule size differs from start marker")
    required = {"workload_controller", "scenario", "seed", "rate_per_second"}
    normalized = []
    for item in schedule:
        if not isinstance(item, dict) or set(item) != required:
            raise ValueError("pilot schedule row has unexpected fields")
        normalized.append({
            "workload_controller": str(item["workload_controller"]),
            "scenario": str(item["scenario"]),
            "seed": int(item["seed"]),
            "rate_per_second": int(item["rate_per_second"]),
        })
    keys = {
        (row["workload_controller"], row["scenario"], row["seed"], row["rate_per_second"])
        for row in normalized
    }
    if len(keys) != len(normalized):
        raise ValueError("pilot schedule contains duplicate trials")
    allowed = {
        (row["workload_controller"], row["scenario"], row["seed"], row["rate_per_second"])
        for row in build_schedule(contract, int(start["schedule_seed"]))
    }
    if not keys <= allowed:
        raise ValueError("pilot schedule is not a subset of the frozen full matrix")
    return normalized


def controller_model_workload(manifest: dict, controller: str) -> str:
    prefix = f"production/{controller}:"
    candidates = [
        key for key, value in manifest.get("workloads", {}).items()
        if key.startswith(prefix) and value.get("status") == "candidate"
    ]
    if not candidates:
        raise ValueError(f"candidate has no model for controller {controller}")
    by_container = {item.split(":", 1)[1]: item for item in candidates}
    for container in PRIMARY_CONTAINER_ORDER:
        if container in by_container:
            return by_container[container]
    return sorted(candidates)[0]


def ready_pods(payload: dict, controller: str) -> list[dict]:
    result = []
    for pod in payload.get("items", []):
        metadata, status, spec = pod.get("metadata", {}), pod.get("status", {}), pod.get("spec", {})
        name = str(metadata.get("name", ""))
        conditions = {item.get("type"): item.get("status") for item in status.get("conditions", [])}
        containers = status.get("containerStatuses", [])
        if (
            (name == controller or name.startswith(controller + "-"))
            and status.get("phase") == "Running"
            and conditions.get("Ready") == "True"
            and containers
            and all(item.get("ready") is True for item in containers)
            and not metadata.get("deletionTimestamp")
        ):
            result.append({
                "name": name,
                "uid": metadata.get("uid"),
                "node_name": spec.get("nodeName"),
                "containers": [item.get("name") for item in spec.get("containers", [])],
            })
    return sorted(result, key=lambda item: (item["node_name"], item["name"]))


def select_cgroup(metadata: dict, pod_uid: str, model_container: str) -> tuple[int, dict]:
    matches = [
        (int(cgroup_id), value)
        for cgroup_id, value in metadata.get("cgroups", {}).items()
        if value.get("pod_uid") == pod_uid
        and value.get("container_name") == model_container
    ]
    if not matches:
        raise ValueError(
            f"expected a {model_container} cgroup for pod {pod_uid}, observed 0"
        )
    # A gVisor pod can expose both the parent pod slice and its deeper sentry
    # scope as ``pod-slice`` because CRI does not report a normal leaf container
    # ID.  The eBPF current-cgroup counter observes the deepest scope.  Resolve
    # by cgroup topology only; attack outcomes are never consulted.
    depths = [
        (str(item.get("cgroup_path", "")).count("/"), cgroup_id, item)
        for cgroup_id, item in matches
    ]
    maximum = max(depth for depth, _cgroup_id, _item in depths)
    leaves = [
        (cgroup_id, item)
        for depth, cgroup_id, item in depths
        if depth == maximum
    ]
    if len(leaves) != 1:
        raise ValueError(
            f"ambiguous deepest {model_container} cgroup for pod {pod_uid}: {len(leaves)}"
        )
    return leaves[0]


class Runtime:
    def __init__(self, password: str, ssh_user: str = "dat"):
        self.password = password
        self.ssh_user = ssh_user
        self.environment = dict(os.environ, SSHPASS=password)

    def run(self, command: list[str], *, input_bytes=None, timeout=60, check=True):
        return subprocess.run(
            command, input=input_bytes, capture_output=True, timeout=timeout,
            check=check, env=self.environment,
        )

    def kubectl_json(self, *arguments: str) -> dict:
        result = self.run(["kubectl", *arguments], timeout=30)
        return json.loads(result.stdout)

    def remote_sudo(self, host: str, command: str, *, payload: bytes = b"", timeout=30):
        stdin = self.password.encode() + b"\n" + payload
        return self.run(
            [
                "sshpass", "-e", "ssh", "-o", "StrictHostKeyChecking=no",
                "-o", "ConnectTimeout=8", f"{self.ssh_user}@{host}",
                f"sudo -S -p '' {command}",
            ],
            input_bytes=stdin,
            timeout=timeout,
        )


def cluster_gate(runtime: Runtime) -> None:
    nodes = runtime.kubectl_json("get", "nodes", "-o", "json")
    if len(nodes.get("items", [])) != 6:
        raise RuntimeError("blind matrix requires all six registered nodes")
    for node in nodes["items"]:
        conditions = {item["type"]: item["status"] for item in node["status"]["conditions"]}
        bad_taints = {
            item.get("key") for item in node.get("spec", {}).get("taints", [])
        } & {
            "node.kubernetes.io/disk-pressure",
            "node.kubernetes.io/memory-pressure",
            "node.kubernetes.io/pid-pressure",
            "node.kubernetes.io/not-ready",
            "node.kubernetes.io/unreachable",
        }
        if conditions.get("Ready") != "True" or any(
            conditions.get(name) != "False"
            for name in ("DiskPressure", "MemoryPressure", "PIDPressure")
        ) or bad_taints:
            raise RuntimeError(f"unhealthy node before blind trial: {node['metadata']['name']}")
    pods = runtime.kubectl_json("get", "pods", "-n", "production", "-o", "json")
    bad = []
    for pod in pods.get("items", []):
        phase = pod.get("status", {}).get("phase")
        if phase == "Succeeded":
            continue
        statuses = pod.get("status", {}).get("containerStatuses", [])
        if phase != "Running" or not statuses or not all(
            item.get("ready") is True for item in statuses
        ):
            bad.append(pod["metadata"]["name"])
    if bad:
        raise RuntimeError(f"unhealthy production pods before blind trial: {bad}")
    sensors = runtime.kubectl_json(
        "get", "pods", "-n", "kube-system", "-l",
        "app.kubernetes.io/name=tetragon", "-o", "json",
    )
    ready_sensors = {
        item.get("spec", {}).get("nodeName")
        for item in sensors.get("items", [])
        if item.get("status", {}).get("phase") == "Running"
        and item.get("status", {}).get("containerStatuses")
        and all(
            status.get("ready") is True
            for status in item["status"]["containerStatuses"]
        )
    }
    if ready_sensors != {item["metadata"]["name"] for item in nodes["items"]}:
        raise RuntimeError("Tetragon is not Ready on every cluster node")
    volumes = runtime.kubectl_json(
        "get", "volumes.longhorn.io", "-n", "longhorn-system", "-o", "json"
    )
    if any(item.get("status", {}).get("robustness") != "healthy" for item in volumes.get("items", [])):
        raise RuntimeError("Longhorn has a degraded volume before blind trial")
    clusters = runtime.kubectl_json(
        "get", "clusters.postgresql.cnpg.io", "-n", "production", "-o", "json"
    )
    for cluster in clusters.get("items", []):
        status, spec = cluster.get("status", {}), cluster.get("spec", {})
        expected = status.get("instances", spec.get("instances", 0))
        if status.get("phase") != "Cluster in healthy state" or status.get("readyInstances", 0) != expected:
            raise RuntimeError("CloudNativePG is not fully healthy before blind trial")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument("--model-dir", type=Path, required=True)
    parser.add_argument("--attack-contract", type=Path, required=True)
    parser.add_argument("--implementation-contract", type=Path, required=True)
    parser.add_argument("--exec-provenance-policy", type=Path, required=True)
    parser.add_argument("--namespace", default="production")
    parser.add_argument("--ssh-user", default="dat")
    parser.add_argument("--post-trial-seconds", type=float, default=2.0)
    parser.add_argument("--copy-timeout-seconds", type=int, default=120)
    parser.add_argument("--pilot-plan", type=Path)
    args = parser.parse_args()
    password = os.environ.get("SSHPASS")
    if not password:
        raise ValueError("SSHPASS is required")
    if not 30 <= args.copy_timeout_seconds <= 300:
        raise ValueError("copy timeout must be between 30 and 300 seconds")
    root = args.evidence_root.resolve()
    marker_path = root / "BLIND_START.json"
    active = root / "ACTIVE"
    if not marker_path.is_file() or not active.is_file() or (root / "INFRA_FAILURE.json").exists():
        raise ValueError("blind run is not active or was already invalidated")
    start = json.loads(marker_path.read_text(encoding="utf-8"))
    contract = load_contract(args.attack_contract)
    implementation = json.loads(args.implementation_contract.read_text(encoding="utf-8"))
    manifest_path = args.model_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    binary = root / "runtime_attack_blind"
    bindings = {
        "model_manifest_sha256": sha256_file(manifest_path),
        "blind_attack_contract_sha256": sha256_file(args.attack_contract),
        "attack_implementation_contract_sha256": sha256_file(args.implementation_contract),
        "exec_provenance_policy_sha256": sha256_file(args.exec_provenance_policy),
        "runtime_binary_sha256": sha256_file(binary),
    }
    for name, value in bindings.items():
        if start.get(name) != value:
            raise ValueError(f"blind start binding changed: {name}")
    if contract.get("schema") == "sentinel-pulse-blind-attack-contract-v2":
        candidate_binding = contract["candidate_binding"]
        if (
            candidate_binding["model_manifest_sha256"]
            != bindings["model_manifest_sha256"]
            or candidate_binding["decision_policy_sha256"]
            != start.get("decision_policy_sha256")
        ):
            raise ValueError("successor blind contract belongs to another candidate")
    if implementation.get("binary", {}).get("sha256") != bindings["runtime_binary_sha256"]:
        raise ValueError("runtime binary differs from frozen implementation contract")
    if set(implementation.get("scenarios", [])) != set(contract["matrix"]["scenarios"]):
        raise ValueError("implementation scenarios differ from Pulse contract")
    duration = int(implementation["attack_seconds"])
    pilot_mode = args.pilot_plan is not None
    schedule = (
        load_pilot_schedule(args.pilot_plan, contract, start)
        if pilot_mode
        else build_schedule(contract, int(start["schedule_seed"]))
    )
    if len(schedule) != int(start["expected_injections"]):
        raise ValueError("blind schedule size differs from start marker")
    for row in schedule:
        row["workload_key"] = controller_model_workload(
            manifest, row["workload_controller"]
        )
    plan = {
        "schema": "sentinel-pulse-blind-plan-v1",
        "start_sha256": sha256_file(marker_path),
        "bindings": bindings,
        "duration_seconds": duration,
        "post_trial_seconds": args.post_trial_seconds,
        "schedule": schedule,
    }
    plan_path = root / "PLAN.json"
    if plan_path.exists() and json.loads(plan_path.read_text(encoding="utf-8")) != plan:
        raise ValueError("existing blind plan differs from frozen schedule")
    if not plan_path.exists():
        atomic_json(plan_path, plan)

    workers = {}
    for line in (root / "workers.txt").read_text(encoding="utf-8").splitlines():
        host, node, feature, injections = line.split()
        workers[node] = {"host": host, "feature": feature, "injections": injections}
    if len(workers) != 3:
        raise ValueError("blind run must bind all three workers")
    runtime = Runtime(password, args.ssh_user)
    desired_policy = json.loads(runtime.run(
        ["kubectl", "apply", "--dry-run=client", "-f",
         str(args.exec_provenance_policy), "-o", "json"],
        timeout=30,
    ).stdout)
    desired_metadata = desired_policy.get("metadata", {})
    if (
        desired_policy.get("kind") != "TracingPolicyNamespaced"
        or desired_metadata.get("namespace") != args.namespace
        or desired_metadata.get("name") != EXEC_PROVENANCE_POLICY
    ):
        raise ValueError("exec provenance manifest has the wrong identity")
    active_policy = runtime.kubectl_json(
        "get", "tracingpoliciesnamespaced.cilium.io", EXEC_PROVENANCE_POLICY,
        "-n", args.namespace, "-o", "json",
    )
    if active_policy.get("spec") != desired_policy.get("spec"):
        raise RuntimeError("active exec provenance policy differs from frozen manifest")
    partial_path = root / "REPORT.partial.json"
    report = json.loads(partial_path.read_text()) if partial_path.exists() else {
        "schema": (
            "sentinel-pulse-attack-latency-pilot-run-v1"
            if pilot_mode else "sentinel-pulse-blind-run-v1"
        ),
        "plan_sha256": sha256_file(plan_path),
        "trials": [],
        "evidence_class": (
            "nonformal_attack_latency_pilot" if pilot_mode else "formal_blind_matrix"
        ),
        "accuracy_claim_allowed": False,
        "automatic_promotion": False,
    }
    if report.get("plan_sha256") != sha256_file(plan_path):
        raise ValueError("partial report belongs to another blind plan")
    completed = {tuple(item[part] for part in ("workload_controller", "scenario", "seed", "rate_per_second")) for item in report["trials"]}
    injections_path = root / "injections.jsonl"
    kernel_path = root / "kernel-events.jsonl"
    existing_markers = []
    if injections_path.exists():
        existing_markers = [json.loads(line) for line in injections_path.read_text().splitlines()]
    marker_keys = {marker_matrix_key(item) for item in existing_markers}
    if marker_keys != completed:
        raise ValueError("marker/report mismatch indicates an interrupted infrastructure trial")

    active_target = None
    active_capture = None
    try:
        for index, row in enumerate(schedule, 1):
            key = tuple(row[part] for part in ("workload_controller", "scenario", "seed", "rate_per_second"))
            if key in completed:
                continue
            cluster_gate(runtime)
            pods_payload = runtime.kubectl_json("get", "pods", "-n", args.namespace, "-o", "json")
            pods = ready_pods(pods_payload, row["workload_controller"])
            if not pods:
                raise RuntimeError(f"no ready target for {row['workload_controller']}")
            pod = pods[(index - 1) % len(pods)]
            worker = workers.get(pod["node_name"])
            if worker is None:
                raise RuntimeError(f"target scheduled outside Pulse workers: {pod['node_name']}")
            model_container = row["workload_key"].split(":", 1)[1]
            target_container = pod["containers"][0] if model_container == "pod-slice" else model_container
            if target_container not in pod["containers"]:
                raise RuntimeError(f"container {target_container} absent from {pod['name']}")
            metadata_raw = runtime.remote_sudo(worker["host"], "cat /run/sentinel-pulse/cgroups.json")
            cgroup_id, _cgroup = select_cgroup(
                json.loads(metadata_raw.stdout), str(pod["uid"]), model_container
            )
            binary_in_container = binary_path_for_controller(row["workload_controller"])
            active_target = (pod["name"], target_container, binary_in_container)
            runtime.run(
                ["kubectl", "exec", "-i", "-n", args.namespace, pod["name"],
                 "-c", target_container, "--", "sh", "-c",
                 'cat > "$1" && chmod 0755 "$1"', "pulse-copy", binary_in_container],
                input_bytes=binary.read_bytes(), timeout=args.copy_timeout_seconds,
            )
            runtime.run(
                ["kubectl", "exec", "-n", args.namespace, pod["name"],
                 "-c", target_container, "--", "sh", "-c",
                 'test "$(wc -c < "$1")" -eq "$2"', "pulse-size",
                 binary_in_container, str(binary.stat().st_size)],
                timeout=30,
            )
            tetragon_pods = runtime.kubectl_json(
                "get", "pods", "-n", "kube-system", "-l",
                "app.kubernetes.io/name=tetragon", "-o", "json",
            )
            sensor = next(
                (item["metadata"]["name"] for item in tetragon_pods["items"]
                 if item["spec"].get("nodeName") == pod["node_name"]), None
            )
            if sensor is None:
                raise RuntimeError(f"no Tetragon pod on {pod['node_name']}")
            policy_status = runtime.run(
                ["kubectl", "exec", "-n", "kube-system", sensor, "-c", "tetragon",
                 "--", "tetra", "tracingpolicy", "list"],
                timeout=30,
            ).stdout.decode(errors="replace")
            if not any(
                EXEC_PROVENANCE_POLICY in line and "enabled" in line
                for line in policy_status.splitlines()
            ):
                raise RuntimeError(
                    f"{EXEC_PROVENANCE_POLICY} is not enabled on {pod['node_name']}"
                )
            capture_timeout = duration + 5
            active_capture = subprocess.Popen(
                ["timeout", f"{capture_timeout}s", "kubectl", "exec", "-n",
                 "kube-system", sensor, "-c", "tetragon", "--", "tetra",
                 "getevents", "-o", "json", "--policy-names",
                 EXEC_PROVENANCE_POLICY],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=runtime.environment,
            )
            time.sleep(0.5)
            injected_at = time.time()
            injection_id = f"{start['run_id']}:{index:04d}"
            injection = {
                "schema": "sentinel-pulse-injection-v1",
                "injection_id": injection_id,
                "injected_at": injected_at,
                "duration_seconds": duration,
                "workload_controller": row["workload_controller"],
                "workload_key": row["workload_key"],
                "cgroup_id": cgroup_id,
                "pod_name": pod["name"],
                "pod_uid": pod["uid"],
                "node_name": pod["node_name"],
                "scenario": row["scenario"],
                "seed": row["seed"],
                "rate_per_second": row["rate_per_second"],
                "binary_path": binary_in_container,
            }
            encoded = (json.dumps(injection, sort_keys=True, separators=(",", ":")) + "\n").encode()
            runtime.remote_sudo(
                worker["host"], f"tee -a -- {worker['injections']}", payload=encoded
            )
            append_jsonl(injections_path, injection)
            attack = runtime.run(
                ["kubectl", "exec", "-n", args.namespace, pod["name"],
                 "-c", target_container, "--", binary_in_container,
                 row["scenario"], str(duration), str(row["rate_per_second"]), str(row["seed"])],
                timeout=duration + 30,
            )
            stderr = attack.stderr.decode(errors="replace")
            if (
                "sentinel-runtime-attack start" not in stderr
                or "sentinel-runtime-attack done" not in stderr
            ):
                raise RuntimeError("frozen attack binary did not emit start/done acknowledgements")
            capture_stdout, capture_stderr = active_capture.communicate(timeout=15)
            active_capture = None
            kernel = find_execve_kprobe_event(
                capture_stdout.decode(errors="replace").splitlines(), injection,
                expected_binary=binary_in_container,
                maximum_delay_seconds=10.0,
            )
            append_jsonl(kernel_path, kernel)
            detector_dir = str(Path(worker["injections"]).parent)
            decisions = runtime.remote_sudo(
                worker["host"], f"grep -F -- '\"injection_id\":\"{injection_id}\"' {detector_dir}/decisions.jsonl || true"
            ).stdout.decode(errors="replace").splitlines()
            cleanup = runtime.run(
                ["kubectl", "exec", "-n", args.namespace, pod["name"],
                 "-c", target_container, "--", "rm", "-f", "--", binary_in_container],
                timeout=30,
            )
            if cleanup.returncode != 0:
                raise RuntimeError("could not remove temporary blind binary")
            active_target = None
            report["trials"].append({
                **row,
                "injection_id": injection_id,
                "pod_name": pod["name"],
                "pod_uid": pod["uid"],
                "node_name": pod["node_name"],
                "cgroup_id": cgroup_id,
                "kernel_exec_id": kernel["exec_id"],
                "detected": bool(decisions),
            })
            report["completed_injections"] = len(report["trials"])
            report["detected_injections"] = sum(bool(item["detected"]) for item in report["trials"])
            atomic_json(partial_path, report)
            time.sleep(args.post_trial_seconds)
    except Exception as error:
        if active_capture is not None:
            active_capture.terminate()
            try:
                active_capture.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                active_capture.kill()
                active_capture.communicate()
            active_capture = None
        cleanup_returncode = None
        if active_target is not None:
            pod_name, container_name, binary_in_container = active_target
            cleanup = runtime.run(
                ["kubectl", "exec", "-n", args.namespace, pod_name,
                 "-c", container_name, "--", "rm", "-f", "--", binary_in_container],
                timeout=30,
                check=False,
            )
            cleanup_returncode = cleanup.returncode
        failure = {
            "schema": "sentinel-pulse-blind-infrastructure-failure-v1",
            "failed_at": datetime.now(timezone.utc).isoformat(),
            "error_type": type(error).__name__,
            "error": str(error),
            "completed_injections": len(report["trials"]),
            "automatic_rerun": False,
            "temporary_binary_cleanup_returncode": cleanup_returncode,
        }
        if isinstance(error, (subprocess.CalledProcessError, subprocess.TimeoutExpired)):
            for name in ("stdout", "stderr"):
                value = getattr(error, name, None)
                if isinstance(value, bytes):
                    value = value.decode(errors="replace")
                if value:
                    failure[f"command_{name}_tail"] = str(value)[-4096:]
        atomic_json(root / "INFRA_FAILURE.json", failure)
        raise

    report["completed_at"] = datetime.now(timezone.utc).isoformat()
    report["expected_injections"] = len(schedule)
    report["schedule_complete"] = len(report["trials"]) == len(schedule)
    report["matrix_complete"] = (
        report["schedule_complete"] and not pilot_mode
    )
    report["formal_blind_evidence"] = not pilot_mode
    report["recall"] = report["detected_injections"] / len(schedule)
    atomic_json(root / "REPORT.json", report)
    completion_marker = root / ("PILOT_COMPLETE" if pilot_mode else "MATRIX_COMPLETE")
    completion_marker.write_text(
        f"completed_at={report['completed_at']}\nreport_sha256={sha256_file(root / 'REPORT.json')}\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
