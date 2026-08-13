import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
SERVICE_ROOT = ROOT / "ml-service" if (ROOT / "ml-service").is_dir() else ROOT
sys.path.insert(0, str(SERVICE_ROOT))

from evaluate_tetragon_rule_replay import evaluate_rule_replay, publish


def feature(start, run_id, phase_id, sequence, pod="production/api-pod"):
    counts = {name: sequence.count(name) for name in sorted(set(sequence))}
    return {
        "kind": "feature_window", "ts": start + 10,
        "schema": "sentinel-feature-window/v2",
        "pod_key": pod, "model_key": "production/api", "node_name": "worker",
        "window_start": start, "window_end": start + 10,
        "event_count": len(sequence), "vector_size": 2,
        "sparse_vector": [[0, 1.0]], "syscall_counts": counts,
        "contains_arguments_or_payloads": False, "capture_mode": "sequence",
        "syscall_sequence": sequence, "release_id": "v8-test",
        "run_id": run_id, "phase_id": phase_id, "traffic_regime": "steady",
    }


def injection(kind, timestamp, injection_id, pod="production/api-pod"):
    row = {
        "kind": kind, "ts": timestamp,
        "schema": "sentinel-injection-interval/v2",
        "injection_id": injection_id, "pod_key": pod,
        "attack_type": "escape", "release_id": "v8-test",
        "run_id": "attack-run", "phase_id": injection_id,
        "traffic_regime": "controlled_attack",
    }
    if kind == "injection":
        row.update(rate=6, seed=1901)
    else:
        row["attack_exit_code"] = 0
    return row


def write_rows(path, rows):
    path.write_text("".join(json.dumps(row) + "\n" for row in rows))


def protocol():
    return {
        "schema": "sentinel-syscall-evaluation-protocol/v1",
        "release_id": "v8-test",
        "shared_replay": {
            "normal_run_ids": [f"normal-run-{index:02d}" for index in range(2, 7)]
        },
        "methods": {
            "tetragon_rule_only": {
                "sensitive_syscalls": ["capset", "mount", "ptrace", "setuid", "unshare"]
            }
        },
    }


def test_rule_replay_counts_normal_alerts_and_attack_trial_recall(tmp_path):
    normal_rows = []
    start = 10.0
    for run in range(2, 7):
        for phase in range(4):
            sequence = ["read", "setuid"] if run == 2 and phase == 0 else ["read"]
            normal_rows.append(feature(
                start, f"normal-run-{run:02d}", f"phase-{phase}", sequence,
            ))
            start += 10
    normal = tmp_path / "normal.jsonl"
    write_rows(normal, normal_rows)

    attack = tmp_path / "attack.jsonl"
    write_rows(attack, [
        injection("injection", 1002, "trial-1"),
        feature(1000, "attack-run", "trial-1", ["execve", "unshare"]),
        injection("injection_end", 1008, "trial-1"),
        injection("injection", 1022, "trial-2"),
        feature(1020, "attack-run", "trial-2", ["read", "write"]),
        injection("injection_end", 1028, "trial-2"),
    ])
    report, alerts = evaluate_rule_replay(
        normal, attack, protocol(), expected_trials=2,
    )
    assert report["normal"]["independent_runs"] == 5
    assert report["normal"]["phases"] == 20
    assert report["normal"]["false_alerts"] == 1
    assert len(report["normal"]["phase_outcomes"]) == 20
    assert sum(
        item["false_alerts"] for item in report["normal"]["phase_outcomes"]
    ) == 1
    assert report["attack"]["trials"] == 2
    assert report["attack"]["detected"] == 1
    assert report["attack"]["recall"]["estimate"] == .5
    assert report["latency_seconds"]["count"] == 1
    assert len(alerts) == 2


def test_rule_replay_publishes_idempotent_hash_checked_bundle(tmp_path):
    report = {"schema": "test", "evaluation_protocol_sha256": None}
    protocol_path = tmp_path / "protocol.json"
    protocol_path.write_text("{}")
    output = tmp_path / "output"
    publish(output, report, [], protocol_path)
    assert (output / "SHA256SUMS").is_file()
    publish(output, report, [], protocol_path)
    (output / "tetragon-rule-replay.report.json").write_text("tampered")
    try:
        publish(output, report, [], protocol_path)
    except ValueError as exc:
        assert "checksum mismatch" in str(exc)
    else:
        raise AssertionError("tampered output was accepted")


def test_rule_replay_does_not_cross_attribute_next_phase_window(tmp_path):
    normal_rows = []
    start = 10.0
    for run in range(2, 7):
        for phase in range(4):
            normal_rows.append(feature(
                start, f"normal-run-{run:02d}", f"phase-{phase}", ["read"],
            ))
            start += 10
    normal = tmp_path / "normal.jsonl"
    write_rows(normal, normal_rows)
    attack = tmp_path / "attack.jsonl"
    write_rows(attack, [
        injection("injection", 1002, "trial-1"),
        feature(1000, "attack-run", "trial-1", ["read"]),
        injection("injection_end", 1008, "trial-1"),
        injection("injection", 1019.99, "trial-2"),
        feature(1010, "attack-run", "trial-2", ["unshare", "read"]),
        injection("injection_end", 1028, "trial-2"),
    ])
    report, _ = evaluate_rule_replay(
        normal, attack, protocol(), expected_trials=2,
    )
    assert report["attack"]["detected"] == 0
