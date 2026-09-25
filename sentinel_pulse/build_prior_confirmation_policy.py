"""Transfer a preregistered temporal gate onto a new normal-only model.

Only the decision-control structure is transferred.  The target model,
semantic envelope, score calibration, and training provenance remain those of
the target base policy.  This is useful when an operational pattern was
documented before the target model existed; target-model evaluation is still
mandatory and no target holdout outcome may be consumed by this builder.
"""

from __future__ import annotations

import argparse
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path

from .build_semantic_policy import write_policy
from .decision_policy import load_decision_policy
from .integrity import sha256_file
from .train import source_git_provenance


def _signal_groups(policy: dict) -> list[dict]:
    return policy["same_window_corroboration"]["workload_normal_envelope"][
        "signal_groups"
    ]


def build_policy(
    base_policy_path: Path,
    confirmation_template_path: Path,
    policy_name: str,
    source: dict | None = None,
) -> dict:
    if not policy_name.strip():
        raise ValueError("policy_name must be non-empty")
    base, base_sha256 = load_decision_policy(base_policy_path)
    template, template_sha256 = load_decision_policy(confirmation_template_path)
    if base.get("schema") != "sentinel-pulse-decision-policy-v2":
        raise ValueError("confirmation transfer requires a target v2 base policy")
    if (
        template.get("schema") != "sentinel-pulse-decision-policy-v3"
        or template.get("blind_outcome_used") is not False
        or template.get("automatic_promotion") is not False
        or template.get("evidence_class")
        != "normal_only_consecutive_confirmation_candidate"
        or not isinstance(template.get("temporal_confirmation"), dict)
        or not isinstance(template.get("bounded_event_time_corroboration"), dict)
    ):
        raise ValueError("confirmation template is not eligible normal-only evidence")
    base_confirmation = base["same_window_corroboration"]
    template_confirmation = template["same_window_corroboration"]
    if (
        base_confirmation["security_activity_fields"]
        != template_confirmation["security_activity_fields"]
        or _signal_groups(base) != _signal_groups(template)
    ):
        raise ValueError("confirmation template semantic groups differ from target")

    target_model = base["development_normal_evidence"]["model_manifest_sha256"]
    prior_development = template["development_normal_evidence"]
    prior_model = prior_development["model_manifest_sha256"]
    required_prior_hashes = (
        "temporal_calibration_sha256",
        "temporal_calibration_source_checksums_sha256",
        "temporal_confirmation_calibration_sha256",
        "temporal_confirmation_source_checksums_sha256",
    )
    if any(
        not isinstance(prior_development.get(field), str)
        or len(prior_development[field]) != 64
        for field in required_prior_hashes
    ):
        raise ValueError("confirmation template prior evidence is incomplete")

    provenance = source or source_git_provenance()
    policy = deepcopy(base)
    policy.update(
        {
            "schema": "sentinel-pulse-decision-policy-v3",
            "name": policy_name,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "evidence_class": "prior_normal_confirmation_transfer_candidate",
            "frozen_before_blind_evaluation": True,
            "blind_outcome_used": False,
            "automatic_promotion": False,
            "source_git_commit": provenance["source_git_commit"],
            "source_clean": provenance["source_clean"],
            "source_git_diff_sha256": provenance["source_git_diff_sha256"],
            "bounded_event_time_corroboration": deepcopy(
                template["bounded_event_time_corroboration"]
            ),
            "temporal_confirmation": deepcopy(template["temporal_confirmation"]),
            "confirmation_transfer": {
                "schema": "sentinel-pulse-confirmation-transfer-v1",
                "scope": "temporal_control_structure_only",
                "source_policy_name": template["name"],
                "source_policy_sha256": template_sha256,
                "source_model_manifest_sha256": prior_model,
                "target_base_policy_sha256": base_sha256,
                "target_model_manifest_sha256": target_model,
                "normal_only_prior": True,
                "attack_outcomes_used": False,
                "independent_target_evaluation_required": True,
            },
            "claim_scope": (
                "Temporal decision controls transferred from checksum-bound prior "
                "normal-only evidence onto the target model; target model and "
                "semantic envelope are unchanged, no target holdout or attack "
                "outcome is used, and independent target evaluation is required"
            ),
        }
    )
    development = policy["development_normal_evidence"]
    development["base_policy_sha256"] = base_sha256
    development["confirmation_template_sha256"] = template_sha256
    for field in required_prior_hashes:
        development[field] = prior_development[field]
    development["additional_temporal_confirmation_calibrations"] = deepcopy(
        prior_development.get(
            "additional_temporal_confirmation_calibrations", []
        )
    )
    return policy


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-policy", type=Path, required=True)
    parser.add_argument("--confirmation-template", type=Path, required=True)
    parser.add_argument("--policy-name", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    policy = build_policy(
        args.base_policy,
        args.confirmation_template,
        args.policy_name,
    )
    write_policy(args.output, policy)
    load_decision_policy(args.output)


if __name__ == "__main__":
    main()
