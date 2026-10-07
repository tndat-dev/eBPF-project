import copy
import json

import pytest

from sentinel_pulse.features import TRACKED_SYSCALLS
from sentinel_pulse.verify_syscall_selection import (
    VARIANTS, abi_mapping, digest, summarize,
)


def fixture():
    abi = "\n".join(f"{n}\tcommon\t{name}\tsys_{name}" for n, name in TRACKED_SYSCALLS.items()).encode()
    header = " ".join(f"X({n}, {slot})" for slot, n in enumerate(TRACKED_SYSCALLS)).encode()
    frequency = {}
    for name in (*TRACKED_SYSCALLS.values(), "other"):
        count = 2 if name == "read" else 8 if name == "other" else 0
        frequency[name] = {"count": count, "share": count / 10, "per_container_second": count / 2}
    analysis = {
        "schema": "sentinel-pulse-syscall-analysis-v1",
        "independent_capture_hash_and_post_training_time": True,
        "capture_sha256": "capture", "model_manifest_sha256": "model",
        "workloads": {"web": {
            "frequency": frequency, "exact_total": 10, "container_seconds": 2,
            "rows": 4, "regimes": {"unlabelled": 4}, "normal_contexts": 2,
            "impurity_importance_descriptive": [{"feature": "log_count:read", "weight": .1}],
        }},
    }
    ablation = {
        "schema": "sentinel-pulse-retrained-normal-ablation-v1",
        "heldout_capture_sha256": "capture",
        "workloads": {"web": {name: {
            "normal_contexts": 2, "FP_raw_model": 1, "TN_raw_model": 1, "raw_model_fpr": .5,
        } for name in VARIANTS}},
    }
    return analysis, ablation, abi, header


def inputs(analysis, ablation, abi, header):
    raw = json.dumps(analysis).encode()
    bound = copy.deepcopy(ablation)
    bound["heldout_analysis_sha256"] = digest(raw)
    return raw, json.dumps(bound).encode(), abi, header


def test_source_and_frequency_evidence_does_not_prove_optimal_security_features():
    report = summarize(*inputs(*fixture()))
    assert report["native_x86_64_abi_matches"]
    assert report["collector_python_order_matches"]
    assert report["feature_rows"] == 4 and report["exact_total"] == 10
    assert report["tracked_share"] == .2 and report["other_share"] == .8
    read = next(row for row in report["tracked_syscalls"] if row["name"] == "read")
    assert read["calls_per_container_second"] == 1
    assert read["workloads_with_nonzero_count"] == 1
    assert "ptrace" in report["syscalls_not_observed_in_this_capture"]
    assert report["group_ablation_normal_only"]["full"]["anomalous_contexts"] == 1
    assert report["attack_recall"] is None and report["precision"] is None
    assert not report["optimal_syscall_selection_proven"]
    assert not report["automatic_promotion"]


def test_x32_entry_does_not_replace_native_mapping():
    assert abi_mapping(b"0 common read sys_read\n512 x32 read compat_read")[0] == "read"
    assert 512 not in abi_mapping(b"512 x32 read compat_read")


@pytest.mark.parametrize("change", [
    "abi", "header_order", "header_extra", "duplicate_abi", "negative_count",
    "sum", "share", "rate", "missing_name", "nan_duration", "regime_rows",
    "ablation_counts", "ablation_rate", "ablation_incomplete", "capture_hash",
    "independence", "workload_set",
])
def test_inconsistent_evidence_is_rejected(change):
    analysis, ablation, abi, header = fixture()
    workload = analysis["workloads"]["web"]
    if change == "abi":
        abi = abi.replace(b"common\tread", b"common\tnot_read")
    elif change == "header_order":
        header = header.replace(b"X(0, 0)", b"X(0, 1)")
    elif change == "header_extra":
        header += b" X(999, 29)"
    elif change == "duplicate_abi":
        abi += b"\n0 64 read sys_read"
    elif change == "negative_count":
        workload["frequency"]["read"]["count"] = -1
    elif change == "sum":
        workload["exact_total"] = 11
    elif change == "share":
        workload["frequency"]["read"]["share"] = .1
    elif change == "rate":
        workload["frequency"]["read"]["per_container_second"] = 7
    elif change == "missing_name":
        del workload["frequency"]["ptrace"]
    elif change == "nan_duration":
        workload["container_seconds"] = float("nan")
    elif change == "regime_rows":
        workload["regimes"]["unlabelled"] = 3
    elif change == "ablation_counts":
        ablation["workloads"]["web"]["full"]["TN_raw_model"] = 0
    elif change == "ablation_rate":
        ablation["workloads"]["web"]["full"]["raw_model_fpr"] = 0
    elif change == "ablation_incomplete":
        del ablation["workloads"]["web"]["security"]
    elif change == "capture_hash":
        ablation["heldout_capture_sha256"] = "changed"
    elif change == "independence":
        analysis["independent_capture_hash_and_post_training_time"] = False
    elif change == "workload_set":
        ablation["workloads"]["other"] = copy.deepcopy(ablation["workloads"]["web"])
    with pytest.raises(ValueError):
        summarize(*inputs(analysis, ablation, abi, header))


def test_changed_analysis_hash_is_rejected():
    raw, ablation, abi, header = inputs(*fixture())
    with pytest.raises(ValueError, match="different analysis"):
        summarize(raw + b" ", ablation, abi, header)
