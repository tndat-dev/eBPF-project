import json
from pathlib import Path

import pytest

from sentinel_pulse.build_prior_confirmation_policy import build_policy
from sentinel_pulse.build_semantic_policy import write_policy
from sentinel_pulse.decision_policy import load_decision_policy
from sentinel_pulse.integrity import sha256_file


ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = (
    ROOT / "sentinel_pulse" / "protocol" / "decision-policy-temporal-b7.json"
)


def _base(path: Path) -> Path:
    policy = json.loads(TEMPLATE.read_text(encoding="utf-8"))
    policy["schema"] = "sentinel-pulse-decision-policy-v2"
    policy["name"] = "target-r9-same-window"
    policy["evidence_class"] = "formal_candidate_normal_calibrated"
    policy.pop("bounded_event_time_corroboration")
    policy.pop("temporal_confirmation")
    policy["development_normal_evidence"]["model_manifest_sha256"] = "9" * 64
    path.write_text(json.dumps(policy) + "\n", encoding="utf-8")
    return path


def test_transfers_only_temporal_controls_and_binds_prior(tmp_path):
    base_path = _base(tmp_path / "base.json")
    base, base_sha = load_decision_policy(base_path)
    template, template_sha = load_decision_policy(TEMPLATE)
    policy = build_policy(
        base_path,
        TEMPLATE,
        "sentinel-pulse-r9-c2",
        source={
            "source_git_commit": "a" * 40,
            "source_clean": True,
            "source_git_diff_sha256": "b" * 64,
        },
    )
    output = tmp_path / "policy.json"
    write_policy(output, policy)
    loaded, digest = load_decision_policy(output)

    assert len(digest) == 64
    assert loaded["same_window_corroboration"] == base[
        "same_window_corroboration"
    ]
    assert loaded["score_corroboration"] == base["score_corroboration"]
    assert loaded["temporal_confirmation"] == template["temporal_confirmation"]
    assert loaded["bounded_event_time_corroboration"] == template[
        "bounded_event_time_corroboration"
    ]
    transfer = loaded["confirmation_transfer"]
    assert transfer["source_policy_sha256"] == template_sha
    assert transfer["target_base_policy_sha256"] == base_sha
    assert transfer["target_model_manifest_sha256"] == "9" * 64
    assert transfer["source_model_manifest_sha256"] != "9" * 64
    development = loaded["development_normal_evidence"]
    assert development["confirmation_template_sha256"] == template_sha
    assert development["model_manifest_sha256"] == "9" * 64


def test_rejects_template_with_attack_outcome(tmp_path):
    base_path = _base(tmp_path / "base.json")
    template = json.loads(TEMPLATE.read_text(encoding="utf-8"))
    template["blind_outcome_used"] = True
    template_path = tmp_path / "template.json"
    template_path.write_text(json.dumps(template) + "\n", encoding="utf-8")
    with pytest.raises(ValueError):
        build_policy(base_path, template_path, "invalid")


def test_loader_rejects_transfer_target_identity_mismatch(tmp_path):
    base_path = _base(tmp_path / "base.json")
    policy = build_policy(
        base_path,
        TEMPLATE,
        "sentinel-pulse-r9-c2",
        source={
            "source_git_commit": "a" * 40,
            "source_clean": True,
            "source_git_diff_sha256": "b" * 64,
        },
    )
    policy["confirmation_transfer"]["target_model_manifest_sha256"] = "8" * 64
    path = tmp_path / "invalid.json"
    path.write_text(json.dumps(policy) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="transfer provenance"):
        load_decision_policy(path)


def test_template_checksum_is_stable():
    _policy, digest = load_decision_policy(TEMPLATE)
    assert digest == sha256_file(TEMPLATE)
