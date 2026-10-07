"""Audit syscall source mappings and summarize existing independent evidence.

Read-only: no capture, model fitting, threshold selection, or promotion. The
normal-only evidence cannot establish security recall or an optimal syscall set.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import math
from pathlib import Path
import re
from urllib.request import urlopen

from .features import SENSITIVE_IDS, TRACKED_SYSCALLS


ABI_URL = (
    "https://raw.githubusercontent.com/torvalds/linux/v6.8/"
    "arch/x86/entry/syscalls/syscall_64.tbl"
)
VARIANTS = (
    "full", "log_count", "ratio", "rolling_mean", "rolling_std",
    "security", "syscall_bin", "transition_bin", "volume",
)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def integer(value, name):
    if type(value) is not int or value < 0:
        raise ValueError(f"invalid {name}")
    return value


def finite(value, name):
    if isinstance(value, bool) or not isinstance(value, (float, int)):
        raise ValueError(f"invalid {name}")
    if not math.isfinite(value):
        raise ValueError(f"invalid {name}")
    return value


def abi_mapping(data):
    mapping = {}
    for line in data.decode("utf-8").splitlines():
        fields = line.split()
        if len(fields) < 3 or not fields[0].isdigit() or fields[1] not in ("common", "64"):
            continue
        syscall_id = int(fields[0])
        if syscall_id in mapping:
            raise ValueError("duplicate native syscall ID in ABI table")
        mapping[syscall_id] = fields[2]
    return mapping


def summarize(analysis_bytes, ablation_bytes, abi_bytes, header_bytes):
    abi = abi_mapping(abi_bytes)
    for syscall_id, name in TRACKED_SYSCALLS.items():
        if abi.get(syscall_id) != name:
            raise ValueError(f"Linux ABI mismatch: {syscall_id}/{name}")
    header_rows = [
        (int(syscall_id), int(slot))
        for syscall_id, slot in re.findall(
            r"\bX\(\s*(\d+)\s*,\s*(\d+)\s*\)", header_bytes.decode("utf-8")
        )
    ]
    expected = [(syscall_id, slot) for slot, syscall_id in enumerate(TRACKED_SYSCALLS)]
    if header_rows != expected:
        raise ValueError("collector IDs/order differ from Python features")

    analysis = json.loads(analysis_bytes)
    ablation = json.loads(ablation_bytes)
    if analysis.get("schema") != "sentinel-pulse-syscall-analysis-v1":
        raise ValueError("unsupported analysis schema")
    if ablation.get("schema") != "sentinel-pulse-retrained-normal-ablation-v1":
        raise ValueError("unsupported ablation schema")
    if analysis.get("independent_capture_hash_and_post_training_time") is not True:
        raise ValueError("independent post-training capture required")
    if ablation.get("heldout_analysis_sha256") != digest(analysis_bytes):
        raise ValueError("ablation refers to a different analysis")
    if ablation.get("heldout_capture_sha256") != analysis.get("capture_sha256"):
        raise ValueError("ablation refers to a different capture")
    if not analysis["workloads"] or set(analysis["workloads"]) != set(ablation["workloads"]):
        raise ValueError("analysis/ablation workload mismatch")

    counts = Counter()
    prevalence = Counter()
    regimes = Counter()
    seconds = 0.0
    total = rows = 0
    importance = {}
    summaries = {variant: {"anomalous_contexts": 0, "normal_contexts": 0} for variant in VARIANTS}
    names = set(TRACKED_SYSCALLS.values()) | {"other"}
    for key, workload in analysis["workloads"].items():
        duration = finite(workload["container_seconds"], "container seconds")
        if duration <= 0 or set(workload["frequency"]) != names:
            raise ValueError("incomplete exact frequency evidence")
        count = integer(workload["exact_total"], "exact total")
        local = {}
        for name, frequency in workload["frequency"].items():
            value = integer(frequency["count"], "syscall count")
            share = finite(frequency["share"], "frequency share")
            rate = finite(frequency["per_container_second"], "frequency rate")
            if not math.isclose(share, value / count if count else 0, abs_tol=1e-12):
                raise ValueError("frequency share mismatch")
            if not math.isclose(rate, value / duration, abs_tol=1e-12):
                raise ValueError("frequency rate mismatch")
            local[name] = value
            prevalence[name] += int(value > 0)
        if sum(local.values()) != count:
            raise ValueError("exact counter sum mismatch")
        counts.update(local)
        seconds += duration
        total += count
        rows += integer(workload["rows"], "feature rows")
        for regime, regime_rows in workload["regimes"].items():
            regimes[regime] += integer(regime_rows, "regime rows")
        if sum(workload["regimes"].values()) != workload["rows"]:
            raise ValueError("regime row sum mismatch")
        importance[key] = workload["impurity_importance_descriptive"][:5]

        variants = ablation["workloads"][key]
        if set(variants) != set(VARIANTS):
            raise ValueError("incomplete ablation matrix")
        context_n = integer(workload["normal_contexts"], "heldout contexts")
        for variant, result in variants.items():
            n = integer(result["normal_contexts"], "ablation contexts")
            fp = integer(result["FP_raw_model"], "raw anomalous contexts")
            tn = integer(result["TN_raw_model"], "raw nonanomalous contexts")
            if n != context_n or n <= 0 or fp + tn != n:
                raise ValueError("ablation counts mismatch")
            rate = finite(result["raw_model_fpr"], "raw anomaly rate")
            if not math.isclose(rate, fp / n, abs_tol=1e-12):
                raise ValueError("ablation rate mismatch")
            summaries[variant]["normal_contexts"] += n
            summaries[variant]["anomalous_contexts"] += fp
    if total <= 0:
        raise ValueError("no syscall exposure")
    for result in summaries.values():
        result["descriptive_raw_anomaly_rate"] = result["anomalous_contexts"] / result["normal_contexts"]

    syscall_rows = []
    for syscall_id, name in TRACKED_SYSCALLS.items():
        syscall_rows.append({
            "syscall_id": syscall_id,
            "name": name,
            "sensitive_design_flag": syscall_id in SENSITIVE_IDS,
            "count": counts[name],
            "share_of_all_syscalls": counts[name] / total,
            "calls_per_container_second": counts[name] / seconds,
            "workloads_with_nonzero_count": prevalence[name],
        })
    return {
        "schema": "sentinel-pulse-syscall-selection-evidence-v1",
        "linux_abi_source": ABI_URL,
        "abi_table_sha256": digest(abi_bytes),
        "native_x86_64_abi_matches": True,
        "collector_header_sha256": digest(header_bytes),
        "collector_python_order_matches": True,
        "analysis_sha256": digest(analysis_bytes),
        "ablation_sha256": digest(ablation_bytes),
        "capture_sha256": analysis["capture_sha256"],
        "model_manifest_sha256": analysis["model_manifest_sha256"],
        "feature_rows": rows,
        "workloads": len(analysis["workloads"]),
        "regime_rows": dict(regimes),
        "container_seconds": seconds,
        "exact_total": total,
        "tracked_share": (total - counts["other"]) / total,
        "other_count": counts["other"],
        "other_share": counts["other"] / total,
        "tracked_syscalls": syscall_rows,
        "syscalls_not_observed_in_this_capture": [row["name"] for row in syscall_rows if not row["count"]],
        "top5_impurity_features_by_workload_descriptive": importance,
        "group_ablation_normal_only": summaries,
        "proof_scope": "ABI correctness, exact observed frequency, descriptive frozen-model importance, retrained group sensitivity",
        "capture_raw_seals_reverified_by_this_tool": False,
        "individual_untracked_frequency_available": False,
        "optimal_syscall_selection_proven": False,
        "per_syscall_security_utility_proven": False,
        "precision": None,
        "attack_recall": None,
        "kernel_to_alert_seconds": None,
        "automatic_promotion": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--analysis", type=Path, required=True)
    parser.add_argument("--ablation", type=Path, required=True)
    parser.add_argument("--abi-table", type=Path, help="Offline copy; otherwise fetch the fixed Linux v6.8 source URL")
    parser.add_argument("--collector-header", type=Path, default=Path(__file__).parent / "ebpf/pulse_counter_ids.h")
    args = parser.parse_args()
    if args.abi_table:
        abi = args.abi_table.read_bytes()
    else:
        with urlopen(ABI_URL, timeout=20) as response:
            abi = response.read(1_000_001)
        if len(abi) > 1_000_000:
            raise ValueError("ABI table exceeds size limit")
    result = summarize(args.analysis.read_bytes(), args.ablation.read_bytes(), abi, args.collector_header.read_bytes())
    print(json.dumps(result, indent=2, sort_keys=True, allow_nan=False))


if __name__ == "__main__":
    main()
