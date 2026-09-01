"""Build a frozen bounded-join policy exclusively from normal calibration."""

from __future__ import annotations

import argparse
from copy import deepcopy
from datetime import datetime, timezone
import json
from pathlib import Path

from .build_semantic_policy import write_policy
from .decision_policy import load_decision_policy
from .integrity import sha256_file
from .train import source_git_provenance


def build_policy(
    base_policy_path: Path,
    calibration_path: Path,
    maximum_evidence_age_seconds: float,
    policy_name: str,
    source: dict | None = None,
    eligible_semantic_signal_groups: list[str] | None = None,
) -> dict:
    base, base_sha256 = load_decision_policy(base_policy_path)
    calibration = json.loads(calibration_path.read_text(encoding="utf-8"))
    if base.get("schema") not in {
        "sentinel-pulse-decision-policy-v2",
        "sentinel-pulse-decision-policy-v3",
    }:
        raise ValueError("temporal policy requires a frozen v2/v3 normal-only base")
    if (
        calibration.get("schema") != "sentinel-pulse-temporal-calibration-v1"
        or calibration.get("normal_only") is not True
        or calibration.get("blind_outcome_used") is not False
        or calibration.get("automatic_promotion") is not False
        or calibration.get("model_manifest_sha256")
        != base["development_normal_evidence"]["model_manifest_sha256"]
        or calibration.get("decision_policy_sha256") != base_sha256
    ):
        raise ValueError("temporal calibration is not compatible normal-only evidence")
    eligible_groups = (
        sorted(set(eligible_semantic_signal_groups))
        if eligible_semantic_signal_groups is not None
        else None
    )
    if (
        eligible_groups != calibration.get("eligible_semantic_signal_groups")
        or (
            eligible_groups is not None
            and len(eligible_groups) != len(eligible_semantic_signal_groups)
        )
    ):
        raise ValueError("temporal policy eligible groups differ from calibration")
    selected = [
        item for item in calibration.get("horizons", [])
        if float(item.get("maximum_evidence_age_seconds", -1.0))
        == float(maximum_evidence_age_seconds)
    ]
    if len(selected) != 1 or int(selected[0].get("projected_alerts", -1)) != 0:
        raise ValueError("selected temporal horizon does not pass normal calibration")
    provenance = source or source_git_provenance()
    policy = deepcopy(base)
    policy.update({
        "schema": "sentinel-pulse-decision-policy-v3",
        "name": policy_name,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "evidence_class": "normal_only_bounded_event_time_candidate",
        "blind_outcome_used": False,
        "automatic_promotion": False,
        "source_git_commit": provenance["source_git_commit"],
        "source_clean": provenance["source_clean"],
        "source_git_diff_sha256": provenance["source_git_diff_sha256"],
        "bounded_event_time_corroboration": {
            "mode": "bounded_model_semantic_join",
            "maximum_evidence_age_seconds": float(maximum_evidence_age_seconds),
            "requires_raw_model_anomaly": True,
            "requires_score_corroboration": True,
            "requires_semantic_corroboration": True,
            "consume_on_alert": True,
            "normal_only_calibration": True,
            **(
                {"eligible_semantic_signal_groups": eligible_groups}
                if eligible_groups is not None else {}
            ),
        },
        "claim_scope": (
            "Bounded event-time candidate calibrated only on checksum-bound "
            "normal decisions; no attack outcome used and no auto-promotion"
        ),
    })
    policy["development_normal_evidence"]["base_policy_sha256"] = base_sha256
    policy["development_normal_evidence"]["temporal_calibration_sha256"] = (
        sha256_file(calibration_path)
    )
    if calibration.get("evidence_checksums_sha256") is not None:
        policy["development_normal_evidence"][
            "temporal_calibration_source_checksums_sha256"
        ] = calibration["evidence_checksums_sha256"]
    return policy


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-policy", type=Path, required=True)
    parser.add_argument("--calibration", type=Path, required=True)
    parser.add_argument("--maximum-evidence-age-seconds", type=float, required=True)
    parser.add_argument("--policy-name", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--eligible-semantic-group", action="append")
    args = parser.parse_args()
    policy = build_policy(
        args.base_policy,
        args.calibration,
        args.maximum_evidence_age_seconds,
        args.policy_name,
        eligible_semantic_signal_groups=args.eligible_semantic_group,
    )
    write_policy(args.output, policy)
    load_decision_policy(args.output)


if __name__ == "__main__":
    main()
