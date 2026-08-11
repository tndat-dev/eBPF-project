import hashlib
import json
from pathlib import Path
import stat


ROOT = Path(__file__).resolve().parents[1]
SERVICE_ROOT = ROOT / "ml-service" if (ROOT / "ml-service").is_dir() else ROOT
SYSTEMD_ROOT = ROOT / "sentinel" / "systemd"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_v8_attack_contract_derives_seeds_from_pre_capture_contract():
    attack = json.loads((SERVICE_ROOT / "v8_blind_attack_contract.json").read_text())
    evaluation_path = SERVICE_ROOT / "evaluation_matrix_contract.json"
    split_path = SERVICE_ROOT / "v8_capture_split_contract.json"
    evaluation = json.loads(evaluation_path.read_text())
    assert attack["schema"] == "sentinel-v8-blind-attack-contract/v1"
    assert attack["release_id"] == evaluation["release_id"]
    assert attack["trial_seeds"] == evaluation["trial_seeds"]
    assert attack["seed_pre_registration"]["source_sha256"] == digest(evaluation_path)
    assert attack["split_contract_sha256"] == digest(split_path)
    assert attack["seed_pre_registration"]["frozen_before_v8_capture"] is True
    assert attack["frozen_before_candidate_training"] is True
    assert attack["use_for_training_or_threshold_tuning"] is False
    assert attack["automatic_promotion"] is False
    assert attack["capture_mode"] == "sequence"


def test_v8_attack_binary_source_is_hash_bound():
    attack = json.loads((SERVICE_ROOT / "v8_blind_attack_contract.json").read_text())
    source = ROOT / attack["source"]["path"]
    assert source.is_file()
    assert attack["source"]["sha256"] == digest(source)
    assert len(attack["binary"]["sha256"]) == 64


def test_v8_attack_wrapper_is_gated_and_has_no_train_or_promotion_path():
    path = SERVICE_ROOT / "run_v8_blind_attack.sh"
    script = path.read_text()
    assert path.stat().st_mode & stat.S_IXUSR
    assert "POST_CAPTURE_COMPLETE" in script
    assert "independent_evaluation" in script
    assert "aims-v8-falco-evidence" in script
    assert "Falco paired evidence collector is inactive" in script
    assert 'falco.get("stream_failures") == 0' in script
    assert 'falco.get("release_id") == "v8-paired-replay-20260811"' in script
    assert ").total_seconds() > 120" in script
    assert "--feature-capture-mode sequence" in script
    assert "--evaluation-contract" in script
    assert "v8_blind_attack_contract.json" in script
    assert "syscall_evaluation_protocol.json" in script
    assert "falco_attack_evidence_finalizer.py" in script
    assert "FALCO_ATTACK_EVIDENCE_COMPLETE" in script
    assert "train_candidate.py" not in script
    assert "promote_candidate.py" not in script


def test_v8_attack_service_is_bounded_delayed_and_non_promoting():
    service = (SYSTEMD_ROOT / "aims-v8-blind-attack.service").read_text()
    timer = (SYSTEMD_ROOT / "aims-v8-blind-attack.timer").read_text()
    assert "ConditionPathExists=" in service and "POST_CAPTURE_COMPLETE" in service
    assert "FALCO_ATTACK_EVIDENCE_COMPLETE" in service
    assert "User=dat" in service
    assert "NoNewPrivileges=true" in service
    assert "CPUQuota=150%" in service
    assert "MemoryMax=8G" in service
    assert "TimeoutStartSec=72h" in service
    assert "SuccessExitStatus=75 8" in service
    assert "Conflicts=aims-v8-capture.service" not in service
    assert "OnUnitInactiveSec=30min" in timer
    assert "Persistent=true" in timer
    assert "promote" not in service.lower()


def test_blind_matrix_canonicalizes_complete_capture_without_promotion():
    source = (SERVICE_ROOT / "run_aims_blind_matrix.py").read_text()
    assert "freeze_paired_attack_evidence" in source
    assert "frozen-attack-feature-capture.jsonl" in source
    assert "frozen-attack-replay.jsonl" in source
    assert "labels_used_for_training" in source
    assert "promote_candidate" not in source
