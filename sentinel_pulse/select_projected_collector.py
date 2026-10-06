"""Select only a checksum-verified collector from a completed safety canary."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from .evaluate_projected_counter_canary import evaluate
from .integrity import sha256_file, verify_sha256


def key(metadata: dict) -> str:
    return (metadata.get("namespace", "unknown") + "/" +
            (metadata.get("workload_name") or metadata.get("role", "unknown")) +
            ":" + metadata.get("container_name", "unknown"))


def select(run_dir: Path, manifest_path: Path, current_metadata: Path, allow_scope_changes=False) -> dict:
    fields = manifest_path.with_name("manifest.sha256").read_text().split()
    if len(fields) != 2 or fields[1] != "manifest.json":
        raise ValueError("invalid detached model manifest checksum")
    verify_sha256(manifest_path, fields[0])
    manifest = json.loads(manifest_path.read_text())
    if (manifest.get("schema") != "sentinel-pulse-model-manifest-v2" or
            manifest.get("window_seconds") != 0.5):
        raise ValueError("projected ML canary requires frozen 500 ms model manifest")
    approved = manifest["approved_workload_revisions"]
    metadata = json.loads((run_dir / "start-cgroups.json").read_text())["cgroups"]
    expected = sorted({key(v) for v in metadata.values()} & set(manifest["workloads"]))
    review = evaluate(run_dir, expected)
    if not review["valid"]:
        raise ValueError("collector safety review rejected: " + "; ".join(review["errors"]))
    live = json.loads(current_metadata.read_text())["cgroups"]
    live_keys = set()
    for value in live.values():
        workload = key(value)
        if workload in manifest["workloads"]:
            live_keys.add(workload)
            if value.get("workload_revision") not in approved.get(workload, []) and not allow_scope_changes:
                raise ValueError("unapproved live workload revision: " + workload)
    if live_keys != set(expected) and not allow_scope_changes:
        raise ValueError("live node model coverage differs from registered collector canary")
    start = json.loads((run_dir / "START.json").read_text())
    root = Path(start["source_root"])
    loader = root / "sentinel_pulse/ebpf/pulse_counter_projected_loader"
    obj = root / "sentinel_pulse/ebpf/pulse_counter_projected.bpf.o"
    if not os.access(loader, os.X_OK):
        raise ValueError("verified projected loader is not executable")
    return {
        "schema": "sentinel-pulse-projected-collector-selection-v1",
        "variant": "projected", "loader": str(loader), "bpf_object": str(obj),
        "loader_sha256": sha256_file(loader), "bpf_object_sha256": sha256_file(obj),
        "model_manifest_sha256": fields[0], "safety_review": review,
        "observational_scope_changes": bool(allow_scope_changes),
        "live_workloads": sorted(live_keys),
        "automatic_promotion": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--canary-run-dir", type=Path, required=True)
    parser.add_argument("--model-manifest", type=Path, required=True)
    parser.add_argument("--current-metadata", type=Path, default=Path("/run/sentinel-pulse/cgroups.json"))
    parser.add_argument("--allow-scope-changes", action="store_true",
                        help="observational capture only; detector still rejects unapproved revisions")
    args = parser.parse_args()
    print(json.dumps(select(args.canary_run_dir, args.model_manifest, args.current_metadata,args.allow_scope_changes)))


if __name__ == "__main__":
    main()
