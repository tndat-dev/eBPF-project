import hashlib
import json
import sys
from pathlib import Path

import pytest


SERVICE_ROOT = Path(__file__).resolve().parents[1] / "ml-service"
sys.path.insert(0, str(SERVICE_ROOT))

from audit_attack_observability import build_audit


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_capture(path: Path, *, injection_id: str, scenario: str,
                  syscall_counts: dict[str, int]) -> dict:
    pod = "production/security-telemetry-abc"
    context = {
        "release_id": "v8", "run_id": "blind:trial-01",
        "phase_id": scenario, "traffic_regime": "attack",
    }
    rows = [
        {
            "kind": "injection", "injection_id": injection_id,
            "attack_type": scenario, "pod_key": pod, "ts": 100.0,
            **context,
        },
        {
            "kind": "feature_window", "pod_key": pod,
            "window_start": 95.0, "window_end": 105.0,
            "event_count": sum(syscall_counts.values()),
            "syscall_counts": syscall_counts, **context,
        },
        {
            "kind": "injection_end", "injection_id": injection_id,
            "attack_type": scenario, "pod_key": pod, "ts": 145.0,
            "attack_exit_code": 0, **context,
        },
    ]
    path.write_text("".join(json.dumps(row) + "\n" for row in rows))
    return {
        "path": str(path), "sha256": digest(path),
        "validation": {
            "valid": True,
            "privacy_contract": {
                "arguments": False, "file_contents": False,
                "network_contents": False, "payloads": False,
            },
        },
    }


def campaign(tmp_path: Path) -> tuple[Path, Path]:
    child_dir = tmp_path / "security-telemetry-trial-01" / "run"
    child_dir.mkdir(parents=True)
    namespace = write_capture(
        child_dir / "namespace.jsonl", injection_id="namespace-01",
        scenario="namespace_probe", syscall_counts={"execve": 1},
    )
    beacon = write_capture(
        child_dir / "beacon.jsonl", injection_id="beacon-01",
        scenario="local_socket_beacon", syscall_counts={"connect": 8},
    )
    child = child_dir / "report.json"
    child.write_text(json.dumps({
        "scenarios": {
            "namespace_probe": {
                "detected": False, "fast_path_expected": True,
                "feature_capture": namespace,
            },
            "local_socket_beacon": {
                "detected": True, "fast_path_expected": False,
                "feature_capture": beacon,
            },
        },
    }))
    top = tmp_path / "report.json"
    top.write_text(json.dumps({
        "completed_trials": 1, "expected_scenario_trials": 2,
        "total": 2,
        "trials": [{
            "target": "production/security-telemetry-service",
            "trial": 1, "seed": 1901, "rate": 6,
            "report_path": str(child), "report_sha256": digest(child),
        }],
    }))
    return tmp_path, child


def test_observability_audit_preserves_primary_miss_and_marks_missing_signal(tmp_path):
    root, _ = campaign(tmp_path)
    report = build_audit(root, 2)
    assert report["valid"] is True
    assert report["primary_outcomes_redefined"] is False
    assert report["summary"] == {
        "primary_detected": 1,
        "primary_misses": 1,
        "semantic_signal_observable": 1,
        "semantic_signal_unobservable": 1,
        "observable_primary_misses": 0,
        "unobservable_primary_misses": 1,
    }
    namespace = next(
        row for row in report["outcomes"]
        if row["scenario"] == "namespace_probe"
    )
    assert namespace["primary_detected"] is False
    assert namespace["semantic_signal_observed"] is False
    assert namespace["semantic_families"][0]["observed_counts"] == {}
    assert report["methodology"]["labels_used_for_training_or_threshold_tuning"] is False


def test_observability_audit_rejects_child_report_tamper(tmp_path):
    root, child = campaign(tmp_path)
    child.write_text("{}")
    with pytest.raises(ValueError, match="child report digest mismatch"):
        build_audit(root, 2)


def test_observability_audit_requires_terminal_trial_count(tmp_path):
    root, _ = campaign(tmp_path)
    top = root / "report.json"
    value = json.loads(top.read_text())
    value["completed_trials"] = 0
    top.write_text(json.dumps(value))
    with pytest.raises(ValueError, match="not terminal"):
        build_audit(root, 2)
