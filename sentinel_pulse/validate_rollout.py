"""Validate all-worker smoke evidence and production workload union."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


DEFAULT_NODES = {
    "k8s-worker1.local",
    "k8s-worker3.local",
    "k8s-worker4.local",
}

DEFAULT_WORKLOADS = {
    "aims-frontend",
    "api-gateway",
    "auth-service",
    "cart-service",
    "catalog-service",
    "inventory-service",
    "notification-service",
    "order-service",
    "payment-service",
    "security-telemetry-service",
    "aims-postgres-cnpg",
    "aims-kafka-dual-role",
    "aims-kafka-entity-operator",
    "aims-rabbitmq-server",
    "aims-redis",
    "aims-redis-sentinel-sentinel",
    "aims-minio-pool-0",
    "aims-waypoint",
}


def stable_workload(key: str) -> str:
    scoped = key.split("/", 1)[-1]
    return scoped.split(":", 1)[0]


def validate(
    report_paths: list[Path],
    expected_nodes: set[str] | None = None,
    required_workloads: set[str] | None = None,
) -> dict:
    expected = DEFAULT_NODES if expected_nodes is None else expected_nodes
    required = DEFAULT_WORKLOADS if required_workloads is None else required_workloads
    errors: list[str] = []
    observed_nodes: list[str] = []
    observed_workloads: set[str] = set()
    summaries = []
    for path in report_paths:
        try:
            report = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            errors.append(f"{path}: unreadable report: {error}")
            continue
        nodes = report.get("node_names", [])
        if report.get("schema") != "sentinel-pulse-collect-smoke-v1":
            errors.append(f"{path}: unsupported smoke schema")
        if report.get("valid") is not True:
            errors.append(f"{path}: node smoke is not valid")
        if not isinstance(nodes, list) or len(nodes) != 1 or not nodes[0]:
            errors.append(f"{path}: expected one node identity")
            node = "unknown"
        else:
            node = str(nodes[0])
            observed_nodes.append(node)
        workloads = {
            stable_workload(str(key)) for key in report.get("workloads", {})
        }
        observed_workloads.update(workloads)
        summaries.append(
            {
                "path": str(path),
                "node": node,
                "rows": int(report.get("rows", 0)),
                "workloads": sorted(workloads),
            }
        )
    node_set = set(observed_nodes)
    if len(node_set) != len(observed_nodes):
        errors.append("duplicate worker identity in smoke reports")
    if node_set != expected:
        errors.append(
            f"worker coverage mismatch: expected={sorted(expected)} observed={sorted(node_set)}"
        )
    missing = required - observed_workloads
    if missing:
        errors.append(f"missing production workloads: {sorted(missing)}")
    return {
        "schema": "sentinel-pulse-rollout-validation-v1",
        "valid": not errors,
        "nodes": sorted(node_set),
        "required_workloads": sorted(required),
        "observed_workloads": sorted(observed_workloads),
        "reports": summaries,
        "errors": errors,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", action="append", type=Path, required=True)
    parser.add_argument("--expected-node", action="append")
    parser.add_argument("--required-workload", action="append")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = validate(
        args.report,
        set(args.expected_node) if args.expected_node else None,
        set(args.required_workload) if args.required_workload else None,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    raise SystemExit(0 if result["valid"] else 1)


if __name__ == "__main__":
    main()
