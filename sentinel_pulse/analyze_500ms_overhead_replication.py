"""Exploratory cross-day/worker synthesis of frozen Pulse 500 ms A/B runs."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from sentinel_pulse.analyze_500ms_overhead_pilot import (
    analyze,
    exact_sign_flip_pvalue,
    sha256,
    summary,
)


def verify_frozen_index(root: Path) -> int:
    if not (root / "COMPLETE").is_file() or (root / "FAILED.txt").exists():
        raise ValueError(f"campaign is not terminal-success: {root}")
    lines = (root / "SHA256SUMS").read_text(encoding="utf-8").splitlines()
    if not lines:
        raise ValueError(f"empty frozen index: {root}")
    marker = f"{root.name}/"
    checked = 0
    for line in lines:
        digest, separator, listed = line.partition("  ")
        if not separator or len(digest) != 64 or marker not in listed:
            raise ValueError(f"invalid frozen index entry: {line}")
        relative = listed.split(marker, 1)[1]
        candidate = (root / relative).resolve()
        if not candidate.is_relative_to(root.resolve()) or not candidate.is_file():
            raise ValueError(f"unsafe or missing frozen artifact: {listed}")
        actual = hashlib.sha256(candidate.read_bytes()).hexdigest()
        if actual != digest:
            raise ValueError(f"checksum mismatch: {listed}")
        checked += 1
    return checked


def analyze_replications(roots: list[Path]) -> dict:
    if len(roots) < 2:
        raise ValueError("at least two frozen campaigns are required")

    campaigns = []
    throughput_effects: list[float] = []
    latency_effects: list[float] = []
    telemetry = {
        "rows": [],
        "interval_p99_seconds": [],
        "ingest_lag_p99_seconds": [],
        "collector_cpu_cores": [],
        "collector_memory_peak_bytes": [],
    }
    campaign_ids, dates, nodes, endpoint_uids = set(), set(), set(), set()

    for root in roots:
        frozen_index_files = verify_frozen_index(root)
        pilot = analyze(root)
        protocol_path = root / "PROTOCOL.json"
        result_path = root / "RESULT.json"
        protocol = json.loads(protocol_path.read_text(encoding="utf-8"))
        result = json.loads(result_path.read_text(encoding="utf-8"))
        endpoint = protocol.get("endpoint", {})
        campaign_id = str(protocol.get("campaign_id", ""))
        registered_at = str(protocol.get("registered_at", ""))
        node = str(endpoint.get("node", ""))
        endpoint_uid = str(endpoint.get("pod_uid", ""))
        if (
            protocol.get("schema") != "sentinel-pulse-500ms-overhead-protocol-v1"
            or protocol.get("mode") != "full"
            or result.get("campaign_id") != campaign_id
            or not campaign_id
            or len(registered_at) < 10
            or not node
            or not endpoint_uid
        ):
            raise ValueError(f"invalid replication provenance: {root}")
        if campaign_id in campaign_ids:
            raise ValueError(f"duplicate campaign: {campaign_id}")
        campaign_ids.add(campaign_id)
        dates.add(registered_at[:10])
        nodes.add(node)
        endpoint_uids.add(endpoint_uid)

        throughput_effects.extend(
            float(item["throughput_loss_percent"]) for item in result["pairs"]
        )
        latency_effects.extend(
            float(item["p99_latency_increase_percent"]) for item in result["pairs"]
        )
        finalizers = []
        for path in sorted(root.glob("p*-on-finalize.json")):
            report = json.loads(path.read_text(encoding="utf-8"))
            if report.get("valid") is not True:
                raise ValueError(f"invalid treatment telemetry: {path}")
            finalizers.append(report)
            telemetry["rows"].append(float(report["rows"]))
            telemetry["interval_p99_seconds"].append(
                float(report["interval_seconds"]["p99"])
            )
            telemetry["ingest_lag_p99_seconds"].append(
                float(report["ingest_lag_seconds"]["p99"])
            )
            telemetry["collector_cpu_cores"].append(
                float(report["experiment_average_cpu_cores"])
            )
            telemetry["collector_memory_peak_bytes"].append(
                float(report["experiment_memory_peak_bytes"])
            )
            if any(int(value) for value in report["collector_max_drops"].values()):
                raise ValueError(f"telemetry loss in {path}")
        if len(finalizers) != 4:
            raise ValueError(f"expected four treatment phases: {root}")

        campaigns.append({
            "campaign_id": campaign_id,
            "registered_date": registered_at[:10],
            "git_commit": protocol.get("git_commit"),
            "node": node,
            "endpoint_pod_uid": endpoint_uid,
            "protocol_sha256": sha256(protocol_path),
            "result_sha256": sha256(result_path),
            "frozen_index_sha256": pilot["frozen_sha256sums_sha256"],
            "frozen_index_files": frozen_index_files,
            "paired_effects": pilot["paired_effects"],
        })

    if len(dates) < 2 or len(nodes) < 2 or len(endpoint_uids) < 2:
        raise ValueError("replications must span two dates, nodes and endpoint pod UIDs")

    throughput_p = exact_sign_flip_pvalue(throughput_effects)
    latency_p = exact_sign_flip_pvalue(latency_effects)
    return {
        "schema": "sentinel-pulse-500ms-overhead-replication-analysis-v1",
        "exploratory_posthoc": True,
        "campaigns": campaigns,
        "independence": {
            "campaigns": len(campaigns),
            "dates": sorted(dates),
            "nodes": sorted(nodes),
            "endpoint_pod_uids": sorted(endpoint_uids),
            "cross_day": True,
            "cross_worker": True,
            "cross_endpoint_pod": True,
        },
        "paired_effects": {
            "throughput_loss_percent": {
                **summary(throughput_effects),
                "exact_two_sided_sign_flip_pvalue": throughput_p,
            },
            "p99_latency_increase_percent": {
                **summary(latency_effects),
                "exact_two_sided_sign_flip_pvalue": latency_p,
            },
        },
        "treatment_telemetry": {
            "runs": len(telemetry["rows"]),
            **{name: summary(values) for name, values in telemetry.items()},
            "all_integrity_gates_passed": True,
        },
        "interpretation": {
            "alpha": 0.05,
            "throughput_difference_significant": throughput_p < 0.05,
            "p99_latency_difference_significant": latency_p < 0.05,
            "equivalence_established": False,
            "reason": (
                "Cross-day/worker replication improves external validity, but no "
                "equivalence margin or power calculation was preregistered."
            ),
        },
        "limitations": [
            "The synthesis code was finalized while the second campaign was running.",
            "Both campaigns still use one cluster and one application endpoint class.",
            "Failure to reject zero effect is not evidence of equivalence.",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", action="append", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = analyze_replications(args.root)
    args.output.parent.mkdir(parents=True, exist_ok=False)
    args.output.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    main()
