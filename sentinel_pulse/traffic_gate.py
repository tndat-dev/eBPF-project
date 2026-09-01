"""Fail-closed production traffic gate for a Sentinel Pulse lifecycle."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any


MICROSERVICES = (
    "api-gateway",
    "auth-service",
    "cart-service",
    "catalog-service",
    "inventory-service",
    "notification-service",
    "order-service",
    "payment-service",
    "security-telemetry-service",
)
INGRESS_PATHS = ("/", "/api/health/", "/api/products/")
NATIVE_RUNTIME_REQUIRED = ("notification-service", "payment-service")


def run(command: list[str], timeout: int = 180) -> str:
    completed = subprocess.run(
        command,
        check=True,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    return completed.stdout


def ready_pod(payload: dict[str, Any]) -> dict[str, Any]:
    candidates = []
    for pod in payload.get("items", []):
        conditions = {
            item.get("type"): item.get("status")
            for item in pod.get("status", {}).get("conditions", [])
        }
        if (
            pod.get("metadata", {}).get("deletionTimestamp") is None
            and pod.get("status", {}).get("phase") == "Running"
            and conditions.get("Ready") == "True"
        ):
            candidates.append(pod)
    if not candidates:
        raise ValueError("selector has no running Ready pod")
    return min(candidates, key=lambda item: item["metadata"]["name"])


def rollout_summary(payload: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    observed = {}
    errors = []
    by_name = {item["metadata"]["name"]: item for item in payload.get("items", [])}
    for name in MICROSERVICES:
        item = by_name.get(name)
        if item is None:
            errors.append(f"missing Rollout: {name}")
            continue
        spec = item.get("spec", {})
        status = item.get("status", {})
        desired = int(spec.get("replicas", 0))
        ready = int(status.get("readyReplicas", 0))
        phase = str(status.get("phase", ""))
        runtime = spec.get("template", {}).get("spec", {}).get("runtimeClassName")
        observed[name] = {
            "desired": desired,
            "ready": ready,
            "phase": phase,
            "runtime_class": runtime,
            "resource_version": item["metadata"].get("resourceVersion"),
        }
        if desired <= 0 or ready != desired or phase != "Healthy":
            errors.append(
                f"Rollout {name} is not Healthy at full readiness: "
                f"desired={desired} ready={ready} phase={phase}"
            )
        if name in NATIVE_RUNTIME_REQUIRED and runtime is not None:
            errors.append(
                f"Rollout {name} must use native runtime for ambient HBONE and "
                f"host eBPF visibility; observed={runtime}"
            )
    return observed, errors


def east_west_errors(result: dict[str, Any], samples: int) -> list[str]:
    errors = []
    for name in MICROSERVICES:
        counts = result.get(name, {}).get("status_counts", {})
        if counts != {"200": samples}:
            errors.append(f"east-west {name}: expected 200x{samples}, observed={counts}")
    return errors


def ingress_errors(result: dict[str, Any], samples: int) -> list[str]:
    errors = []
    for path in INGRESS_PATHS:
        row = result.get(path, {})
        if row.get("success") != samples or row.get("failure") != 0:
            errors.append(
                f"north-south {path}: expected success={samples} failure=0, "
                f"observed={row}"
            )
    return errors


def get_pod(namespace: str, selector: str) -> dict[str, Any]:
    payload = json.loads(
        run([
            "kubectl", "-n", namespace, "get", "pods", "-l", selector,
            "-o", "json",
        ])
    )
    return ready_pod(payload)


def run_east_west(namespace: str, pod: str, samples: int) -> dict[str, Any]:
    program = r'''
import collections, json, sys, time, urllib.error, urllib.request
samples = int(sys.argv[1])
services = sys.argv[2:]
result = {}
for service in services:
    counts = collections.Counter()
    latency = []
    for _ in range(samples):
        started = time.perf_counter()
        try:
            response = urllib.request.urlopen(
                f"http://{service}:8000/api/health/", timeout=1
            )
            counts[str(response.status)] += 1
            response.read()
        except urllib.error.HTTPError as error:
            counts[str(error.code)] += 1
            error.read()
        except Exception as error:
            counts[type(error).__name__] += 1
        latency.append((time.perf_counter() - started) * 1000)
    latency.sort()
    result[service] = {
        "status_counts": dict(counts),
        "p50_ms": latency[int((len(latency) - 1) * 0.50)],
        "p95_ms": latency[int((len(latency) - 1) * 0.95)],
        "p99_ms": latency[int((len(latency) - 1) * 0.99)],
        "max_ms": latency[-1],
    }
print(json.dumps(result, sort_keys=True))
'''
    output = run([
        "kubectl", "-n", namespace, "exec", pod, "--", "python", "-c",
        program, str(samples), *MICROSERVICES,
    ])
    return json.loads(output)


def run_ingress(namespace: str, pod: str, samples: int) -> dict[str, Any]:
    script = r'''
set -eu
samples=$1
base=http://aims-ingress-istio.istio-ingress.svc.cluster.local
first=true
printf '{'
for path in / /api/health/ /api/products/; do
  ok=0
  bad=0
  i=0
  while [ "$i" -lt "$samples" ]; do
    if wget -q -O /dev/null -T 2 "$base$path"; then
      ok=$((ok + 1))
    else
      bad=$((bad + 1))
    fi
    i=$((i + 1))
  done
  if [ "$first" = true ]; then first=false; else printf ','; fi
  printf '"%s":{"success":%s,"failure":%s}' "$path" "$ok" "$bad"
done
printf '}\n'
'''
    output = run([
        "kubectl", "-n", namespace, "exec", pod, "--", "sh", "-c",
        script, "traffic-gate", str(samples),
    ])
    return json.loads(output)


def write_report(path: Path, report: dict[str, Any]) -> None:
    if path.exists():
        raise FileExistsError(f"refusing to overwrite traffic gate evidence: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    os.replace(temporary, path)
    path.chmod(0o444)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--namespace", default="production")
    parser.add_argument("--samples", type=int, default=20)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.samples < 10:
        parser.error("samples must be at least 10")
    if args.output.exists():
        parser.error(f"output already exists: {args.output}")

    source_path = Path(__file__).resolve()
    source_root = source_path.parents[1]
    try:
        source_commit = run(["git", "-C", str(source_root), "rev-parse", "HEAD"]).strip()
    except Exception:
        source_commit = os.environ.get("SOURCE_GIT_COMMIT")
    report: dict[str, Any] = {
        "schema": "sentinel-pulse-production-traffic-gate-v1",
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        "namespace": args.namespace,
        "samples_per_target": args.samples,
        "source_git_commit": source_commit,
        "source_sha256": hashlib.sha256(source_path.read_bytes()).hexdigest(),
        "errors": [],
    }
    errors: list[str] = report["errors"]
    try:
        rollouts = json.loads(run([
            "kubectl", "-n", args.namespace, "get", "rollouts", "-o", "json",
        ]))
        report["rollouts"], rollout_errors = rollout_summary(rollouts)
        errors.extend(rollout_errors)

        source = get_pod(args.namespace, "app.kubernetes.io/name=api-gateway")
        ingress = get_pod(
            args.namespace,
            "app.kubernetes.io/name=aims-sentinel-ingress-loadgen",
        )
        report["source_pods"] = {
            "east_west": {
                "name": source["metadata"]["name"],
                "uid": source["metadata"]["uid"],
                "node": source["spec"]["nodeName"],
            },
            "north_south": {
                "name": ingress["metadata"]["name"],
                "uid": ingress["metadata"]["uid"],
                "node": ingress["spec"]["nodeName"],
                "dataplane_mode": ingress["metadata"].get("labels", {}).get(
                    "istio.io/dataplane-mode"
                ),
            },
        }
        if report["source_pods"]["north_south"]["dataplane_mode"] != "none":
            errors.append("north-south loadgen must opt out of ambient mode")

        report["east_west"] = run_east_west(
            args.namespace, source["metadata"]["name"], args.samples
        )
        errors.extend(east_west_errors(report["east_west"], args.samples))
        report["north_south"] = run_ingress(
            args.namespace, ingress["metadata"]["name"], args.samples
        )
        errors.extend(ingress_errors(report["north_south"], args.samples))
    except Exception as error:  # preserve a fail-closed receipt
        errors.append(f"traffic gate execution failed: {type(error).__name__}: {error}")

    report["passed"] = not errors
    write_report(args.output, report)
    print(json.dumps(report, indent=2, sort_keys=True))
    raise SystemExit(0 if report["passed"] else 1)


if __name__ == "__main__":
    main()
