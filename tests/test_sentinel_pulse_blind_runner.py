import json
from pathlib import Path

import pytest

from sentinel_pulse.blind_contract import load_contract
from sentinel_pulse.run_500ms_blind_matrix import (
    build_schedule,
    controller_model_workload,
    ready_pods,
    select_cgroup,
)


ROOT = Path(__file__).resolve().parents[1]


def test_schedule_is_complete_unique_and_reproducible():
    contract = load_contract(
        ROOT / "sentinel_pulse" / "protocol" / "blind-attack-contract.json"
    )
    first = build_schedule(contract, 20260820)
    second = build_schedule(contract, 20260820)
    keys = {
        (row["workload_controller"], row["scenario"], row["seed"], row["rate_per_second"])
        for row in first
    }
    assert first == second
    assert len(first) == len(keys) == 450


def test_multi_container_controller_uses_preregistered_primary_preference():
    manifest = {
        "workloads": {
            "production/aims-minio-pool-0:sidecar": {"status": "candidate"},
            "production/aims-minio-pool-0:minio": {"status": "candidate"},
            "production/aims-kafka-entity-operator:user-operator": {"status": "candidate"},
            "production/aims-kafka-entity-operator:topic-operator": {"status": "candidate"},
        }
    }
    assert controller_model_workload(manifest, "aims-minio-pool-0").endswith(":minio")
    assert controller_model_workload(manifest, "aims-kafka-entity-operator").endswith(
        ":topic-operator"
    )


def test_target_resolution_requires_ready_pod_and_exact_cgroup():
    payload = {
        "items": [
            {
                "metadata": {"name": "catalog-service-a", "uid": "uid"},
                "spec": {"nodeName": "worker", "containers": [{"name": "app"}]},
                "status": {
                    "phase": "Running",
                    "conditions": [{"type": "Ready", "status": "True"}],
                    "containerStatuses": [{"name": "app", "ready": True}],
                },
            }
        ]
    }
    assert ready_pods(payload, "catalog-service")[0]["uid"] == "uid"
    cgroup_id, item = select_cgroup(
        {"cgroups": {"42": {"pod_uid": "uid", "container_name": "app"}}},
        "uid",
        "app",
    )
    assert cgroup_id == 42
    assert item["container_name"] == "app"
    with pytest.raises(ValueError, match="observed 0"):
        select_cgroup({"cgroups": {}}, "uid", "app")


def test_gvisor_pod_slice_resolves_deepest_sentry_scope_without_attack_labels():
    cgroup_id, _item = select_cgroup(
        {
            "cgroups": {
                "9989": {
                    "pod_uid": "uid",
                    "container_name": "pod-slice",
                    "cgroup_path": "/sys/fs/cgroup/kubepods/pod.slice",
                },
                "16788": {
                    "pod_uid": "uid",
                    "container_name": "pod-slice",
                    "cgroup_path": "/sys/fs/cgroup/kubepods/pod.slice/sentry.scope",
                },
            }
        },
        "uid",
        "pod-slice",
    )
    assert cgroup_id == 16788


def test_blind_lifecycle_is_interlocked_and_has_no_promotion_path():
    starter = (ROOT / "sentinel_pulse" / "start_500ms_blind_matrix.sh").read_text()
    runner = (ROOT / "sentinel_pulse" / "run_500ms_blind_matrix.py").read_text()
    finalizer = (ROOT / "sentinel_pulse" / "finalize_500ms_blind_matrix.sh").read_text()
    lifecycle = (ROOT / "sentinel_pulse" / "run_500ms_blind_campaign.sh").read_text()
    waiter = (ROOT / "sentinel_pulse" / "wait_and_run_500ms_blind_campaign.sh").read_text()
    assert 'test -f "$NORMAL_EVIDENCE_ROOT/NORMAL_PASS"' in starter
    assert ".normal_gate == true and .expected_workload_gate == true" in starter
    assert "ENABLE_INJECTION_TRACKING=true" in starter
    assert 'MODEL_STAGED="$EVIDENCE_ROOT/model"' in starter
    assert 'PROTOCOL_STAGED="$EVIDENCE_ROOT/protocol"' in starter
    assert "protocol/decision-policy.json" in starter
    assert "protocol/runtime_attack_blind.c" in starter
    assert "sha256sum -c manifest.sha256" in starter
    assert "sha256sum -c START_SHA256SUMS" in starter
    assert "runtime_attack_blind" in starter
    assert "automatic_promotion" in runner
    assert "automatic_rerun" in runner
    assert "CloudNativePG is not fully healthy" in runner
    assert "Tetragon is not Ready on every cluster node" in runner
    assert '"rm", "-f", "--", BINARY_IN_CONTAINER' in runner
    assert "promote" not in runner.lower().replace("promotion", "")
    assert "MATRIX_COMPLETE" in runner
    assert "sentinel_pulse.evaluate_latency" in finalizer
    assert "--kernel-events" in finalizer
    assert "verify_distributed_injections" in finalizer
    assert 'EVIDENCE_ROOT/protocol/decision-policy.json' in finalizer
    assert "sha256sum -c START_SHA256SUMS" in finalizer
    assert "sentinel_pulse.finalize_candidate" in finalizer
    assert "CANDIDATE_DECISION.json" in finalizer
    assert "FINALIZE_FAILED" in finalizer
    assert "automatic_promotion" in finalizer
    assert "start_500ms_blind_matrix.sh" in lifecycle
    assert "finalize_500ms_blind_matrix.sh" in lifecycle
    assert 'EVIDENCE_ROOT/protocol/blind-attack-contract.json' in lifecycle
    assert "LIFECYCLE_FAILED" in lifecycle
    assert 'NORMAL_EVIDENCE_ROOT/NORMAL_PASS' in waiter
    assert 'NORMAL_EVIDENCE_ROOT/FINALIZE_FAILED' in waiter
    assert "run_500ms_blind_campaign.sh" in waiter
