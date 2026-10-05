"""Bind collector provenance on launch, resume and every operational poll."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re

from .integrity import sha256_file

WORKERS = {"10.1.16.237", "10.1.16.238", "10.1.16.239"}


def bind(variant: str, plan: Path | None, model_sha: str, policy_sha: str) -> dict:
    if variant not in {"legacy", "projected"}:
        raise ValueError("invalid collector variant")
    if variant == "legacy":
        if plan is not None:
            raise ValueError("legacy collector cannot accept a projected plan")
        return {"variant": "legacy"}
    if plan is None:
        raise ValueError("projected collector requires a safety plan")
    data = json.loads(plan.read_text())
    if (data.get("schema") != "sentinel-pulse-projected-ml-canary-plan-v1" or
            data.get("model_manifest_sha256") != model_sha or
            data.get("decision_policy_sha256") != policy_sha):
        raise ValueError("collector plan model/policy identity mismatch")
    workers = data.get("workers")
    if not isinstance(workers, dict) or set(workers) != WORKERS:
        raise ValueError("collector plan requires exactly three worker addresses")
    for value in workers.values():
        if not isinstance(value, str) or not re.fullmatch(
                r"/var/lib/sentinel-pulse-projection-canary/[A-Za-z0-9._-]+", value) or Path(value).name in {".", ".."}:
            raise ValueError("unsafe collector safety path")
    return {"variant": "projected", "plan_sha256": sha256_file(plan),
            "safety_runs": workers}


def check_resume(marker: dict, supplied: dict) -> None:
    registered = marker.get("collector_contract", {"variant": "legacy"})
    for name in ("variant", "plan_sha256", "safety_runs"):
        if registered.get(name) != supplied.get(name):
            raise ValueError("resume collector contract differs from registered marker")


def check_runtime(marker: dict, host: str, start: dict, env: dict,
                  unit: Path) -> dict:
    contract = marker["collector_contract"]
    if contract["variant"] != "projected":
        raise ValueError("runtime provenance check requires projected contract")
    run = marker["run_id"]
    if not re.fullmatch(r"[A-Za-z0-9._-]+", run):
        raise ValueError("invalid run ID")
    expected = contract["artifacts"][host]
    prefix = f"/opt/sentinel-pulse/experiments/{run}"
    paths = {"loader": prefix + "/pulse_counter_projected_loader",
             "bpf_object": prefix + "/pulse_counter_projected.bpf.o"}
    if (start.get("collector_variant") != "projected" or
            env.get("PULSE_500MS_COLLECTOR_VARIANT") != "projected" or
            env.get("PULSE_500MS_RUN_ID") != run):
        raise ValueError("collector variant/run identity drift")
    for field, env_key in (("loader", "PULSE_500MS_LOADER"),
                           ("bpf_object", "PULSE_500MS_BPF_OBJECT")):
        path = paths[field]
        if start.get("collector_" + field) != path or env.get(env_key) != path:
            raise ValueError("collector runtime path drift")
        digest = sha256_file(Path(path))
        if digest != expected[field + "_sha256"] or start["sha256"][field] != digest:
            raise ValueError("collector artifact checksum drift")
    digest = sha256_file(unit)
    if digest != contract["unit_sha256"] or start["sha256"]["unit"] != digest:
        raise ValueError("collector unit checksum drift")
    return {"valid": True, "variant": "projected", "host": host, "run_id": run}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--variant", default="legacy")
    parser.add_argument("--plan", type=Path)
    parser.add_argument("--model-sha")
    parser.add_argument("--policy-sha")
    parser.add_argument("--marker", type=Path)
    parser.add_argument("--marker-sha")
    parser.add_argument("--runtime-host")
    args = parser.parse_args()
    if args.runtime_host:
        if not args.marker or not args.marker_sha or sha256_file(args.marker) != args.marker_sha:
            raise ValueError("worker marker checksum differs from control-plane marker")
    marker = json.loads(args.marker.read_text()) if args.marker else None
    if args.runtime_host:
        run_dir = Path("/var/lib/sentinel-pulse-500ms/runs") / marker["run_id"]
        start = json.loads((run_dir / "START.json").read_text())
        env = dict(line.split("=", 1) for line in
                   Path("/etc/sentinel-pulse/500ms-experiment.env").read_text().splitlines()
                   if line and not line.startswith("#"))
        result = check_runtime(marker, args.runtime_host, start, env,
                              Path("/etc/systemd/system/sentinel-pulse-collector-500ms-experiment.service"))
    else:
        result = bind(args.variant, args.plan, args.model_sha, args.policy_sha)
        if marker is not None:
            check_resume(marker, result)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
