"""Bind opt-in recovery deployments without weakening legacy lifecycle gates."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re

from .telemetry_recovery import digest, load_profile

CONTRACT_SCHEMA = "sentinel-pulse-recovery-deployment-v1"


def contract(path: Path, nominal: float, availability: float, maximum_gap: float) -> dict:
    profile = load_profile(path)
    if (nominal != profile["nominal_interval_seconds"]
            or availability != profile["minimum_telemetry_availability"]
            or maximum_gap != profile["maximum_recoverable_gap_seconds"]):
        raise ValueError("telemetry deployment differs from recovery profile")
    return {"schema": CONTRACT_SCHEMA, "profile": profile,
            "profile_sha256": digest(profile),
            "profile_file_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "formal_lifecycle_enabled": False, "automatic_promotion": False,
            "automatic_blind_evaluation": False}


def bind_detector(feature: Path, supplied_profile: Path | None) -> dict | None:
    """Require a collector START receipt, not an operator's unaudited flag."""
    start_path = feature.parent / "START.json"
    start = json.loads(start_path.read_text()) if start_path.exists() else {}
    recorded = start.get("telemetry_recovery_contract")
    if recorded is None:
        if supplied_profile is not None:
            raise ValueError("recovery detector needs a recovery collector START binding")
        return None
    if supplied_profile is None:
        raise ValueError("recovery collector requires explicit recovery detector profile")
    telemetry = start["telemetry_availability_contract"]
    expected = contract(supplied_profile, telemetry["nominal_interval_seconds"],
                        telemetry["minimum_availability"], telemetry["maximum_single_gap_seconds"])
    if recorded != expected:
        raise ValueError("collector/detector recovery contract mismatch")
    installed = feature.parent / "telemetry-recovery-profile.json"
    if hashlib.sha256(installed.read_bytes()).hexdigest() != expected["profile_file_sha256"]:
        raise ValueError("collector installed recovery profile checksum mismatch")
    # The detector will independently replay EVERY journal record from start.
    return expected


def bind_freshness_preregistration(feature: Path, preregistration_root: Path = Path(
        "/var/lib/sentinel-pulse-recovery-smoke"), formal_preregistration_root: Path = Path(
        "/var/lib/sentinel-pulse-recovery-formal"), attack_preregistration_root: Path = Path(
        "/var/lib/sentinel-pulse-attack-registration")) -> dict:
    """Refuse retroactive freshness opt-in on an already frozen/legacy run."""
    from .detector_freshness import CONTRACT, CONTRACT_SHA256
    run_id = feature.parent.name
    if not re.fullmatch(r"[A-Za-z0-9._-]+", run_id):
        raise ValueError("unsafe freshness preregistration run ID")
    smoke = preregistration_root / run_id / "START.json"
    formal = formal_preregistration_root / run_id / "START.json"
    attack = attack_preregistration_root / run_id / "START.json"
    if attack.exists():
        if smoke.exists() or formal.exists():
            raise ValueError('ambiguous attack freshness preregistration')
        marker = json.loads(attack.read_text())
        collector = json.loads((feature.parent / 'START.json').read_text())
        if (marker.get('schema') != 'sentinel-pulse-attack-worker-start-v1'
                or marker.get('run_id') != run_id
                or marker.get('automatic_promotion') is not False
                or marker.get('detector_freshness_contract') != CONTRACT
                or marker.get('detector_freshness_contract_sha256') != CONTRACT_SHA256
                or collector.get('telemetry_recovery_contract', {}).get('profile_file_sha256')
                != marker.get('recovery_profile_sha256')
                or not marker.get('campaign_start_sha256')):
            raise ValueError('changed attack freshness preregistration')
        return CONTRACT
    if smoke.exists() and formal.exists():
        raise ValueError("ambiguous smoke/formal freshness preregistration")
    if formal.exists():
        from .recovery_formal import validate_marker, validate_worker_start
        marker = validate_marker(json.loads(formal.read_text()))
        receipt = json.loads((feature.parent / "FORMAL_WORKER_START.json").read_text())
        if marker["run_id"] != run_id:
            raise ValueError("formal freshness preregistration run mismatch")
        validate_worker_start(feature.parent, formal, receipt["worker_ip"])
        return CONTRACT
    registered = json.loads(smoke.read_text())
    if (registered.get("schema") != "sentinel-pulse-recovery-runtime-smoke-start-v1"
            or registered.get("run_id") != run_id
            or registered.get("detector_freshness_contract") != CONTRACT
            or registered.get("detector_freshness_contract_sha256") != CONTRACT_SHA256):
        raise ValueError("missing or changed detector freshness preregistration")
    return CONTRACT


def render_unit(source: str, kind: str, profile_path: str, live_freshness: bool = False) -> str:
    """Only render approved immutable paths; never interpolate shell input."""
    approved = (r"/var/lib/sentinel-pulse-500ms/runs/[A-Za-z0-9._-]+/telemetry-recovery-profile\.json"
                if kind == "collector" else
                r"/opt/sentinel-pulse/policies/recovery-[0-9a-f]{64}\.json")
    if kind not in {"collector", "detector"} or not re.fullmatch(approved, profile_path):
        raise ValueError("unsafe recovery unit profile path or kind")
    if type(live_freshness) is not bool or (live_freshness and kind != "detector"):
        raise ValueError("live freshness flag is detector-only")
    lines = source.splitlines(keepends=True)
    if sum(line.startswith("ExecStart=") for line in lines) != 1 or "--recovery-profile" in source:
        raise ValueError("unsupported or already rendered recovery unit")
    result = []
    for line in lines:
        if line.startswith("ExecStart="):
            if kind == "collector":
                suffix = '--output "${PULSE_500MS_OUTPUT}"\'\n'
                if not line.endswith(suffix) or "-m sentinel_pulse.capture " not in line:
                    raise ValueError("unsupported capture unit command")
                line = line[:-len(suffix)] + '--output "${PULSE_500MS_OUTPUT}" --recovery-profile "' + profile_path + '"\'\n'
            else:
                if "-m sentinel_pulse.detect " not in line or "--from-start" in line:
                    raise ValueError("unsupported detector unit command")
                line = line.rstrip("\n") + " --recovery-profile " + profile_path + " --from-start\n"
                if live_freshness:
                    line = line.rstrip("\n") + " --live-freshness\n"
        result.append(line)
    return "".join(result)
