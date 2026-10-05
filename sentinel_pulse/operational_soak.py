"""Opt-in dependency-scoped operational soak. Legacy strict gates stay intact."""
from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
import json
import math
from pathlib import Path
import subprocess
import time

from .cgroup_resolver import infer_workload_name
from .cluster_health import unhealthy_nodes
from .storage_health import duplicate_disk_uuids, colocated_running_replicas


SCHEMA = "sentinel-pulse-operational-soak-contract-v1"


def digest(value: dict) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def validate_profile(profile: dict) -> dict:
    if profile.get("schema") != SCHEMA:
        raise ValueError("unsupported operational contract")
    for name in ("maximum_alerts_per_workload_hour", "maximum_alerts_per_hour_per_workload"):
        value = float(profile[name])
        if not math.isfinite(value) or not 0 <= value <= 1:
            raise ValueError(f"invalid {name}")
    for name, lower, upper in (
        ("maximum_recovery_seconds", 60, 600),
        ("maximum_excluded_seconds", 60, 1800),
        ("recovery_exclusion_seconds", 30, 120),
        ("maximum_health_observation_gap_seconds", 60, 180),
    ):
        value = profile[name]
        if type(value) is not int or not lower <= value <= upper:
            raise ValueError(f"invalid {name}")
    if profile["maximum_excluded_seconds"] < profile["maximum_recovery_seconds"]:
        raise ValueError("excluded budget is smaller than recovery budget")
    if profile.get("automatic_promotion") is not False or profile.get("automatic_blind_evaluation") is not False:
        raise ValueError("operational contract must not open promotion/blind interlocks")
    extra = profile.get("additional_workloads")
    if not isinstance(extra, list) or len(extra) != len(set(extra)) or any(
        not isinstance(key, str) or not key.startswith("production/") or ":" in key for key in extra
    ):
        raise ValueError("invalid additional dependency workloads")
    return profile


def items(payload: dict) -> list:
    if not isinstance(payload.get("items"), list):
        raise ValueError("resource snapshot has no items list")
    return payload["items"]


def controller(pod: dict) -> str:
    meta = pod["metadata"]
    return f'{meta["namespace"]}/{infer_workload_name(meta["name"])}'


def ready(pod: dict) -> bool:
    return (not pod["metadata"].get("deletionTimestamp")
            and pod.get("status", {}).get("phase") == "Running"
            and any(c.get("type") == "Ready" and c.get("status") == "True"
                    for c in pod.get("status", {}).get("conditions", [])))


def bind(profile: dict, manifest: dict, pods: dict, pvs: dict, worker_nodes: list[str]) -> dict:
    validate_profile(profile)
    expected = sorted(manifest["workloads"])
    if not expected or any(not key.startswith("production/") or ":" not in key for key in expected):
        raise ValueError("unsupported or empty model workload mapping")
    required = set(key.split(":", 1)[0] for key in expected) | set(profile["additional_workloads"])
    selected = [p for p in items(pods) if controller(p) in required and ready(p)]
    registered_counts = {key: sum(controller(p) == key for p in selected) for key in sorted(required)}
    if any(count == 0 for count in registered_counts.values()):
        raise ValueError("dependency workload missing or unready at registration")
    # Ordinary HPA changes must not turn 4->3 healthy stateless replicas into
    # a storage/telemetry incident. Stateful replica reductions remain scoped.
    stateful = {controller(p) for p in selected if
                any(o.get("kind") in {"StatefulSet", "StrimziPodSet", "Cluster"}
                    for o in p["metadata"].get("ownerReferences", []))
                or p["metadata"].get("labels", {}).get("cnpg.io/cluster")}
    counts = {key: count if key in stateful else 1 for key, count in registered_counts.items()}
    volumes, cnpg = set(), set()
    claims = {(p["metadata"]["namespace"], v["persistentVolumeClaim"]["claimName"])
              for p in selected for v in p.get("spec", {}).get("volumes", [])
              if "persistentVolumeClaim" in v}
    pv_by_claim = {(p.get("spec", {}).get("claimRef", {}).get("namespace"),
                    p.get("spec", {}).get("claimRef", {}).get("name")): p for p in items(pvs)}
    for claim in claims:
        pv = pv_by_claim.get(claim)
        if pv is None or pv.get("status", {}).get("phase") != "Bound":
            raise ValueError(f"dependency PVC has no Bound PV: {claim}")
        csi = pv["spec"].get("csi", {})
        if csi.get("driver") == "driver.longhorn.io":
            handle = csi.get("volumeHandle")
            if not handle:
                raise ValueError("Longhorn dependency has no volume handle")
            volumes.add(handle)
    for pod in selected:
        cluster = pod["metadata"].get("labels", {}).get("cnpg.io/cluster")
        if cluster:
            cnpg.add(cluster)
    if len(worker_nodes) != 3 or len(set(worker_nodes)) != 3:
        raise ValueError("three distinct worker nodes required")
    return {"profile": profile, "profile_sha256": digest(profile),
            "expected_workloads": expected, "minimum_ready_pods": counts,
            "ready_pods_at_registration": registered_counts,
            "longhorn_volumes": sorted(volumes), "cnpg_clusters": sorted(cnpg),
            "worker_nodes": sorted(worker_nodes)}


def validate_binding(binding: dict) -> dict:
    validate_profile(binding["profile"])
    if digest(binding["profile"]) != binding["profile_sha256"]:
        raise ValueError("operational profile hash mismatch")
    if not binding.get("minimum_ready_pods") or not binding.get("expected_workloads"):
        raise ValueError("empty operational dependency scope")
    if set(k.split(":", 1)[0] for k in binding["expected_workloads"]) - set(binding["minimum_ready_pods"]):
        raise ValueError("model workload omitted from dependency scope")
    return binding


def classify_health(binding: dict, nodes: dict, pods: dict, volumes: dict, cnpg: dict) -> dict:
    validate_binding(binding)
    items(nodes)  # Fail closed on unavailable/malformed API data.
    fatal, transient, warnings = [], [], []
    worker_nodes = set(binding["worker_nodes"])
    observed_nodes = {n["metadata"]["name"] for n in items(nodes)}
    fatal += [{"reason": "missing_worker_node", "name": n} for n in sorted(worker_nodes - observed_nodes)]
    for issue in unhealthy_nodes(nodes):
        (fatal if issue["node"] in worker_nodes else warnings).append(issue)
    present = items(pods)
    for key, minimum in binding["minimum_ready_pods"].items():
        count = sum(controller(p) == key and ready(p) for p in present)
        if count < minimum:
            transient.append({"reason": "dependency_pod_unready", "workload": key,
                              "ready": count, "minimum": minimum})
        elif count != binding.get("ready_pods_at_registration", {}).get(key, count):
            warnings.append({"reason": "ready_replica_count_changed", "workload": key, "ready": count})
    scoped = set(binding["longhorn_volumes"])
    observed = {v["metadata"]["name"]: v for v in items(volumes)}
    fatal += [{"reason": "missing_dependency_volume", "name": n} for n in sorted(scoped - set(observed))]
    for name, volume in observed.items():
        status = volume.get("status", {})
        robustness, state = status.get("robustness"), status.get("state")
        if robustness == "healthy" and state == "attached":
            continue
        issue = {"reason": "longhorn_volume_unhealthy", "name": name,
                 "robustness": robustness, "state": state}
        if name not in scoped:
            warnings.append(issue)
        elif robustness in {"healthy", "degraded"} and state in {"attached", "attaching"}:
            transient.append(issue)
        else:
            fatal.append(issue)
    clusters = {c["metadata"]["name"]: c for c in items(cnpg)}
    for name in binding["cnpg_clusters"]:
        cluster = clusters.get(name)
        if cluster is None:
            fatal.append({"reason": "missing_dependency_cnpg_cluster", "name": name})
            continue
        status = cluster.get("status", {})
        if (status.get("phase") != "Cluster in healthy state"
                or status.get("readyInstances", 0) != status.get("instances", cluster.get("spec", {}).get("instances"))):
            transient.append({"reason": "cnpg_degraded", "name": name})
    return {"fatal": fatal, "transient": transient, "warnings": warnings}


def merge_intervals(intervals: list) -> list[list[float]]:
    merged = []
    for start, end in sorted(intervals):
        if not all(math.isfinite(x) for x in (start, end)) or end < start:
            raise ValueError("invalid degraded interval")
        if merged and start <= merged[-1][1]:
            merged[-1][1] = max(end, merged[-1][1])
        else:
            merged.append([start, end])
    return merged


def observe(binding: dict, previous: list[dict], health: dict, now: float, started: float) -> dict:
    profile = validate_binding(binding)["profile"]
    if not math.isfinite(now) or now < started:
        raise ValueError("invalid health observation timestamp")
    last = previous[-1] if previous else None
    before = last["checked_at_unix"] if last else started
    if now <= before or now - before > profile["maximum_health_observation_gap_seconds"]:
        raise ValueError("health observation gap or non-monotonic clock")
    row = {"schema": "sentinel-pulse-operational-health-v1", "checked_at_unix": now,
           "binding_sha256": digest(binding),
           **{key: list(health[key]) for key in ("fatal", "transient", "warnings")},
           "degraded": bool(health["transient"]),
           "outage_started_at": None, "excluded_interval": None}
    if row["degraded"]:
        row["outage_started_at"] = (last["outage_started_at"] if last and last["degraded"] else before)
        row["excluded_interval"] = [row["outage_started_at"], now + profile["recovery_exclusion_seconds"]]
        if now - row["outage_started_at"] > profile["maximum_recovery_seconds"]:
            row["fatal"].append({"reason": "recovery_budget_exceeded"})
    elif last and last["degraded"]:
        row["excluded_interval"] = [last["outage_started_at"], now + profile["recovery_exclusion_seconds"]]
    intervals = merge_intervals([r["excluded_interval"] for r in previous + [row] if r.get("excluded_interval")])
    row["excluded_seconds"] = sum(end - begin for begin, end in intervals)
    if row["excluded_seconds"] > profile["maximum_excluded_seconds"]:
        row["fatal"].append({"reason": "total_degraded_budget_exceeded"})
    return row


def kubectl(*arguments: str) -> dict:
    result = subprocess.run(["kubectl", *arguments, "-o", "json"], capture_output=True,
                            text=True, check=True, timeout=20)
    payload = json.loads(result.stdout)
    items(payload)
    return payload


def live_health(binding: dict) -> dict:
    result = classify_health(binding, kubectl("get", "nodes"),
        kubectl("-n", "production", "get", "pods"),
        kubectl("-n", "longhorn-system", "get", "volumes.longhorn.io"),
        kubectl("-n", "production", "get", "clusters.postgresql.cnpg.io"))
    result["fatal"].extend(duplicate_disk_uuids(kubectl("-n", "longhorn-system", "get", "nodes.longhorn.io")))
    result["fatal"].extend(colocated_running_replicas(kubectl("-n", "longhorn-system", "get", "replicas.longhorn.io")))
    return result


def load_binding(marker_path: Path) -> tuple[dict, dict]:
    marker = json.loads(marker_path.read_text())
    binding = validate_binding(marker["operational_evaluation_contract"])
    telemetry = marker["telemetry_availability_contract"]
    minimum = float(telemetry["minimum_availability"])
    gap = float(telemetry["maximum_single_gap_seconds"])
    if not math.isfinite(minimum) or not math.isfinite(gap) or not 0.999 <= minimum <= 1 or not 0.8 <= gap <= 10:
        raise ValueError("operational profile must not weaken telemetry contract")
    return marker, binding


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    register = sub.add_parser("bind")
    register.add_argument("--contract", type=Path, required=True)
    register.add_argument("--model-manifest", type=Path, required=True)
    register.add_argument("--worker-nodes", nargs=3, required=True)
    snapshot = sub.add_parser("snapshot")
    snapshot.add_argument("--binding", required=True)
    step = sub.add_parser("observe")
    step.add_argument("--marker", type=Path, required=True)
    step.add_argument("--log", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "bind":
        result = bind(json.loads(args.contract.read_text()), json.loads(args.model_manifest.read_text()),
                      kubectl("-n", "production", "get", "pods"), kubectl("get", "pv"), args.worker_nodes)
        result["source_contract_sha256"] = hashlib.sha256(args.contract.read_bytes()).hexdigest()
    elif args.command == "snapshot":
        binding = validate_binding(json.loads(args.binding))
        result = live_health(binding)
    else:
        marker, binding = load_binding(args.marker)
        previous = [json.loads(line) for line in args.log.read_text().splitlines()] if args.log.exists() else []
        if any(r.get("binding_sha256") != digest(binding) for r in previous):
            raise ValueError("health log binding mismatch")
        started = datetime.fromisoformat(marker["started_not_before"]).timestamp()
        result = observe(binding, previous, live_health(binding), time.time(), started)
        with args.log.open("a") as stream:
            stream.write(json.dumps(result, sort_keys=True, allow_nan=False) + "\n")
    print(json.dumps(result, sort_keys=True, allow_nan=False))
    if args.command != "bind":
        raise SystemExit(1 if result["fatal"] or (args.command == "snapshot" and result["transient"]) else 0)


if __name__ == "__main__":
    main()
