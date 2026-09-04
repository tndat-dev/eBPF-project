"""Build a frozen consecutive-window policy from normal-only replay evidence."""

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
    policy_name: str,
    source: dict | None = None,
    bounded_join_groups: list[str] | None = None,
    additional_calibration_paths: list[Path] | None = None,
) -> dict:
    base, base_sha256 = load_decision_policy(base_policy_path)
    calibration = json.loads(calibration_path.read_text(encoding="utf-8"))
    if (
        base.get("schema") != "sentinel-pulse-decision-policy-v3"
        or calibration.get("schema")
        != "sentinel-pulse-temporal-confirmation-development-replay-v1"
        or calibration.get("normal_only_development_evidence") is not True
        or calibration.get("attack_outcomes_used") is not False
        or calibration.get("automatic_promotion") is not False
        or int(calibration.get("projected_alerts", -1)) != 0
        or not calibration.get("evidence_checksums_sha256")
        or calibration.get("decision_policy_sha256") != base_sha256
        or calibration.get("model_manifest_sha256")
        != base["development_normal_evidence"]["model_manifest_sha256"]
    ):
        raise ValueError("confirmation calibration is not compatible normal-only evidence")
    required_windows = calibration.get("required_consecutive_windows")
    maximum_gap = calibration.get("maximum_gap_seconds")
    bypass_groups = calibration.get("bypass_groups")
    per_group_windows = calibration.get("required_consecutive_windows_by_group", {})
    calibrated_bounded_groups = calibration.get("bounded_event_time_groups")
    if (
        isinstance(required_windows, bool)
        or not isinstance(required_windows, int)
        or required_windows < 2
        or not isinstance(maximum_gap, (int, float))
        or not isinstance(bypass_groups, list)
        or not bypass_groups
        or not isinstance(per_group_windows, dict)
        or (
            calibrated_bounded_groups is not None
            and not isinstance(calibrated_bounded_groups, list)
        )
    ):
        raise ValueError("confirmation calibration parameters are incomplete")
    if bounded_join_groups is None:
        selected_bounded_groups = (
            None
            if calibrated_bounded_groups is None
            else sorted(calibrated_bounded_groups)
        )
    else:
        selected_bounded_groups = sorted(bounded_join_groups)
    if (
        calibrated_bounded_groups is not None
        and selected_bounded_groups != sorted(calibrated_bounded_groups)
    ):
        raise ValueError("bounded join groups differ from normal-only calibration")

    replay_settings = {
        "required_consecutive_windows": required_windows,
        "required_consecutive_windows_by_group": per_group_windows,
        "maximum_gap_seconds": maximum_gap,
        "bypass_groups": sorted(bypass_groups),
        "bounded_event_time_groups": selected_bounded_groups,
        "maximum_evidence_age_seconds": calibration.get(
            "maximum_evidence_age_seconds"
        ),
    }
    additional_calibrations = []
    for path in additional_calibration_paths or []:
        extra = json.loads(path.read_text(encoding="utf-8"))
        extra_settings = {
            "required_consecutive_windows": extra.get(
                "required_consecutive_windows"
            ),
            "required_consecutive_windows_by_group": extra.get(
                "required_consecutive_windows_by_group", {}
            ),
            "maximum_gap_seconds": extra.get("maximum_gap_seconds"),
            "bypass_groups": sorted(extra.get("bypass_groups", [])),
            "bounded_event_time_groups": extra.get("bounded_event_time_groups"),
            "maximum_evidence_age_seconds": extra.get(
                "maximum_evidence_age_seconds"
            ),
        }
        if (
            extra.get("schema")
            != "sentinel-pulse-temporal-confirmation-development-replay-v1"
            or extra.get("normal_only_development_evidence") is not True
            or extra.get("attack_outcomes_used") is not False
            or extra.get("automatic_promotion") is not False
            or int(extra.get("projected_alerts", -1)) != 0
            or not extra.get("evidence_checksums_sha256")
            or extra.get("model_manifest_sha256")
            != base["development_normal_evidence"]["model_manifest_sha256"]
            or extra_settings != replay_settings
        ):
            raise ValueError("additional confirmation calibration is incompatible")
        additional_calibrations.append(
            {
                "report_sha256": sha256_file(path),
                "evidence_checksums_sha256": extra[
                    "evidence_checksums_sha256"
                ],
                "decision_policy_sha256": extra.get("decision_policy_sha256"),
                "run_id": extra.get("run_id"),
                "scored_rows": int(extra.get("scored_rows", 0)),
                "projected_alerts": 0,
            }
        )

    provenance = source or source_git_provenance()
    policy = deepcopy(base)
    if selected_bounded_groups is not None:
        policy["bounded_event_time_corroboration"][
            "eligible_semantic_signal_groups"
        ] = selected_bounded_groups
    policy.update(
        {
            "name": policy_name,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "evidence_class": "normal_only_consecutive_confirmation_candidate",
            "blind_outcome_used": False,
            "automatic_promotion": False,
            "source_git_commit": provenance["source_git_commit"],
            "source_clean": provenance["source_clean"],
            "source_git_diff_sha256": provenance["source_git_diff_sha256"],
            "temporal_confirmation": {
                "mode": "consecutive_same_group",
                "required_consecutive_windows": required_windows,
                "required_consecutive_windows_by_group": dict(
                    sorted(per_group_windows.items())
                ),
                "maximum_gap_seconds": float(maximum_gap),
                "immediate_bypass_signal_groups": sorted(bypass_groups),
                "normal_only_calibration": True,
                "consume_on_alert": True,
            },
            "claim_scope": (
                "Consecutive-window candidate calibrated only on checksum-bound "
                "normal decisions; no attack outcome used and no auto-promotion"
            ),
        }
    )
    development = policy["development_normal_evidence"]
    development["base_policy_sha256"] = base_sha256
    development["temporal_confirmation_calibration_sha256"] = sha256_file(
        calibration_path
    )
    development["temporal_confirmation_source_checksums_sha256"] = calibration[
        "evidence_checksums_sha256"
    ]
    development["additional_temporal_confirmation_calibrations"] = (
        additional_calibrations
    )
    return policy


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-policy", type=Path, required=True)
    parser.add_argument("--calibration", type=Path, required=True)
    parser.add_argument("--policy-name", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--bounded-join-group", action="append")
    parser.add_argument(
        "--additional-calibration", type=Path, action="append", default=[]
    )
    args = parser.parse_args()
    policy = build_policy(
        args.base_policy,
        args.calibration,
        args.policy_name,
        bounded_join_groups=args.bounded_join_group,
        additional_calibration_paths=args.additional_calibration,
    )
    write_policy(args.output, policy)
    load_decision_policy(args.output)


if __name__ == "__main__":
    main()
