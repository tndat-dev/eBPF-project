import hashlib
import json
from pathlib import Path

import pytest

from sentinel_pulse.blind_contract import load_contract
from sentinel_pulse.run_500ms_blind_matrix import (
    build_schedule,
    binary_path_for_controller,
    controller_model_workload,
    ready_pods,
    select_cgroup,
    load_pilot_schedule,
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


def test_pilot_schedule_must_be_frozen_nonformal_subset(tmp_path):
    contract = load_contract(
        ROOT / "sentinel_pulse" / "protocol" / "blind-attack-contract.json"
    )
    row = build_schedule(contract, 20260820)[0]
    plan = tmp_path / "pilot.json"
    plan.write_text(json.dumps({
        "schema": "sentinel-pulse-attack-latency-pilot-plan-v1",
        "schedule": [row],
    }))
    import hashlib
    start = {
        "evidence_class": "nonformal_attack_latency_pilot",
        "accuracy_claim_allowed": False,
        "automatic_promotion": False,
        "pilot_plan_sha256": hashlib.sha256(plan.read_bytes()).hexdigest(),
        "expected_injections": 1,
        "schedule_seed": 20260820,
    }
    assert load_pilot_schedule(plan, contract, start) == [row]
    start["accuracy_claim_allowed"] = True
    with pytest.raises(ValueError, match="forbid accuracy claims"):
        load_pilot_schedule(plan, contract, start)


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
    assert "tetragon-exec-provenance.yaml" in starter
    assert "sha256sum -c manifest.sha256" in starter
    assert "sha256sum -c START_SHA256SUMS" in starter
    assert "runtime_attack_blind" in starter
    assert "automatic_promotion" in runner
    assert "automatic_rerun" in runner
    assert "CloudNativePG is not fully healthy" in runner
    assert "Tetragon is not Ready on every cluster node" in runner
    assert '"rm", "-f", "--", binary_in_container' in runner
    assert "promote" not in runner.lower().replace("promotion", "")
    assert "MATRIX_COMPLETE" in runner
    assert "sentinel_pulse.evaluate_latency" in finalizer
    assert "--kernel-events" in finalizer
    assert "verify_distributed_injections" in finalizer
    assert 'EVIDENCE_ROOT/protocol/decision-policy.json' in finalizer
    assert "sha256sum -c START_SHA256SUMS" in finalizer
    assert "sentinel_pulse.finalize_candidate" in finalizer
    assert "CANDIDATE_DECISION.json" in finalizer
    assert "BLIND_RESULT.json" in finalizer
    assert "sha256sum -c FINAL_SHA256SUMS" in finalizer
    assert "*-pre-finalize.txt" in finalizer
    assert "FINALIZE_FAILED" in finalizer
    assert "automatic_promotion" in finalizer
    assert "start_500ms_blind_matrix.sh" in lifecycle
    assert "finalize_500ms_blind_matrix.sh" in lifecycle
    assert 'EVIDENCE_ROOT/protocol/blind-attack-contract.json' in lifecycle
    assert "LIFECYCLE_FAILED" in lifecycle
    assert 'NORMAL_EVIDENCE_ROOT/NORMAL_PASS' in waiter
    assert 'NORMAL_EVIDENCE_ROOT/FINALIZE_FAILED' in waiter
    assert "run_500ms_blind_campaign.sh" in waiter


def test_attack_latency_pilot_is_explicitly_nonformal_and_never_promotes():
    starter = (ROOT / "sentinel_pulse" / "start_attack_latency_pilot.sh").read_text()
    runner = (ROOT / "sentinel_pulse" / "run_500ms_blind_matrix.py").read_text()
    finalizer = (
        ROOT / "sentinel_pulse" / "finalize_attack_latency_pilot.sh"
    ).read_text()
    failure_archiver = (
        ROOT / "sentinel_pulse" / "archive_failed_attack_latency_pilot.sh"
    ).read_text()
    assert "nonformal_attack_latency_pilot" in starter
    assert '"accuracy_claim_allowed": False' in starter
    assert '"automatic_promotion": False' in starter
    assert "NORMAL_CANARY_AGGREGATE" in starter
    assert "PILOT_PLAN.json" in starter
    assert "PREVIOUS_PILOT_EVIDENCE" in starter
    assert "previous_completed_trials_excluded_without_rerun" in starter
    assert "continuation_of_failure_index_sha256" in starter
    assert "exec_provenance_policy_sha256" in starter
    assert "--pilot-plan" in runner
    assert "PILOT_COMPLETE" in runner
    assert "matrix_complete" in runner
    assert "formal_blind_evidence" in finalizer
    assert "pilot_engineering_pass" in finalizer
    assert "lineage_recall_descriptive_only" in finalizer
    assert 'test -f "$remote_injections"' in finalizer
    assert "finalize_candidate" not in finalizer
    assert "promote" not in finalizer.lower().replace("promotion", "")
    assert "FAILURE_TERMINAL.json" in failure_archiver
    assert "FAILURE_RAW_SHA256SUMS" in failure_archiver
    assert 'test -f "$destination/${detector_dir#/}/injections.jsonl"' in failure_archiver
    assert '"accuracy_claim_allowed": False' in failure_archiver
    assert "promote" not in failure_archiver.lower().replace("promotion", "")


def test_runner_acknowledgements_match_frozen_binary_protocol():
    runner = (ROOT / "sentinel_pulse" / "run_500ms_blind_matrix.py").read_text()
    binary = (ROOT / "sentinel" / "benchmarks" / "runtime_attack_blind.c").read_text()
    assert '"sentinel-runtime-attack start"' in runner
    assert '"sentinel-runtime-attack done"' in runner
    assert '"sentinel-runtime-attack start mode=' in binary
    assert '"sentinel-runtime-attack done mode=' in binary
    assert "--copy-timeout-seconds" in runner
    assert '"getevents", "-o", "json"' in runner
    assert "find_execve_kprobe_event" in runner
    assert "active exec provenance policy differs from frozen manifest" in runner
    assert "active_target = (pod[\"name\"], target_container, binary_in_container)" in runner
    assert 'wc -c < "$1"' in runner
    assert '"aims-postgres-cnpg": "/run/' in runner
    assert 'DEFAULT_BINARY_IN_CONTAINER = "/tmp/' in runner
    assert 'failure[f"command_{name}_tail"]' in runner


def test_b1_successor_binary_is_checksum_bound_and_excludes_a2_scenarios():
    source_path = ROOT / "sentinel" / "benchmarks" / "runtime_attack_blind_b1.c"
    source = source_path.read_text()
    implementation = json.loads(
        (
            ROOT
            / "sentinel_pulse"
            / "protocol"
            / "attack-implementation-contract-b1.json"
        ).read_text()
    )
    contract = load_contract(
        ROOT / "sentinel_pulse" / "protocol" / "blind-attack-contract-b1.json"
    )
    assert hashlib.sha256(source_path.read_bytes()).hexdigest() == implementation["source"]["sha256"]
    assert set(implementation["scenarios"]) == set(contract["matrix"]["scenarios"])
    assert not set(contract["matrix"]["scenarios"]) & set(
        contract["independence"]["excluded_predecessor_scenarios"]
    )
    for scenario in contract["matrix"]["scenarios"]:
        assert f'"{scenario}"' in source
    for scenario in contract["independence"]["excluded_predecessor_scenarios"]:
        assert f'"{scenario}"' not in source


def test_successor_lifecycle_binds_frozen_candidate_directly():
    starter = (ROOT / "sentinel_pulse" / "start_500ms_blind_matrix.sh").read_text()
    pilot = (ROOT / "sentinel_pulse" / "start_attack_latency_pilot.sh").read_text()
    runner = (ROOT / "sentinel_pulse" / "run_500ms_blind_matrix.py").read_text()
    finalizer = (ROOT / "sentinel_pulse" / "finalize_500ms_blind_matrix.sh").read_text()
    for lifecycle in (starter, pilot):
        assert "sentinel-pulse-blind-attack-contract-v2" in lifecycle
        assert ".candidate_binding.model_manifest_sha256 == $model" in lifecycle
        assert ".candidate_binding.decision_policy_sha256 == $policy" in lifecycle
        assert "successor blind contract belongs to another runtime commit" in lifecycle
    assert "successor blind contract belongs to another candidate" in runner
    assert "successor blind contract belongs to another runtime commit" in runner
    assert '--attack-contract "$ATTACK_CONTRACT"' in finalizer
    assert '--expected-injections "$expected_injections"' in finalizer


def test_b3_blind_opener_requires_terminal_normal_pass_and_exact_runtime_commit():
    opener = (ROOT / "sentinel_pulse" / "open_b3_blind_after_normal.sh").read_text()
    assert 'test -f "$NORMAL_EVIDENCE_ROOT/NORMAL_PASS"' in opener
    assert 'test ! -e "$NORMAL_EVIDENCE_ROOT/ACTIVE"' in opener
    assert 'test ! -e "$NORMAL_EVIDENCE_ROOT/INFRA_FAILURE.json"' in opener
    assert ".candidate_binding.runtime_source_git_commit" in opener
    assert 'git -C "$RUNTIME_ROOT" status --porcelain --untracked-files=no' in opener
    assert "^\\.runtime-artifacts\\/" in opener
    assert "blind-attack-contract-b3.json" in opener


def test_binary_staging_path_preserves_tetragon_visibility_for_cnpg():
    assert binary_path_for_controller("aims-postgres-cnpg").startswith("/run/")
    assert binary_path_for_controller("api-gateway").startswith("/tmp/")
