"""Verify and freeze the completed R4 matched syscall model set.

This audits fit coverage and artifact integrity only. It does not evaluate a
normal holdout, an attack, a confusion matrix, or promote any feature arm.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import time

from .integrity import contained_artifact, sha256_file, verify_sha256


def audit(root: Path, source_root: Path | None = None) -> dict:
    root = root.resolve(strict=True)
    config_path = root / "CONFIG.json"
    start_path = root / "START.json"
    index_path = root / "INDEX.json"
    inputs_path = root / "INPUTS.json"
    terminal_path = root / "TERMINAL.json"
    config, start, index, terminal = [
        json.loads(path.read_text(encoding="utf-8"))
        for path in (config_path, start_path, index_path, terminal_path)
    ]
    source_root = Path(source_root or Path(__file__).resolve().parents[1])
    matched_source = source_root / "sentinel_pulse" / "matched_study.py"

    if terminal.get("state") != "completed_matched_fits":
        raise ValueError("R4 terminal is not a successful complete fit")
    workloads = set(config.get("workload_keys", ()))
    arms = index.get("arms", {})
    seeds = start.get("seeds", ())
    if not workloads or len(workloads) != 21 or not arms or len(arms) != 11 or len(seeds) != 3:
        raise ValueError("registered R4 scope differs from 21 workloads x 11 arms x 3 seeds")
    if set(index.get("workloads", {})) != workloads or index.get("missing_workloads"):
        raise ValueError("workload coverage is incomplete")
    if set(terminal.get("unknown", {})):
        raise ValueError("R4 contains fit/coverage unknowns")

    config_hash = sha256_file(config_path)
    index_hash = sha256_file(index_path)
    if start.get("config_sha256") != config_hash:
        raise ValueError("R4 START does not bind the current config")
    if start.get("source_sha256") != sha256_file(matched_source):
        raise ValueError("R4 matched-study source differs from the fitted source")
    if terminal.get("index_sha256") != index_hash:
        raise ValueError("R4 terminal does not bind the current arm index")
    if index.get("input_manifest_sha256") != sha256_file(inputs_path):
        raise ValueError("R4 index does not bind the input manifest")
    if terminal.get("completed_models") != 693 or terminal.get("expected_models") != 693:
        raise ValueError("R4 terminal does not report 693/693 models")
    if len(terminal.get("completed", {})) != 693:
        raise ValueError("R4 completion ledger does not contain 693 entries")
    if terminal.get("fresh_blind_complete") is not False or terminal.get("precision") is not None or terminal.get("recall") is not None:
        raise ValueError("R4 fit terminal unexpectedly claims blind evaluation metrics")

    expected_tags = {
        f"{workload}|{arm}|{seed}"
        for workload in workloads for arm in arms for seed in seeds
    }
    completed = terminal["completed"]
    if set(completed) != expected_tags:
        raise ValueError("R4 model ledger differs from registered workload/arm/seed grid")

    artifacts = []
    dimensions = {}
    for tag in sorted(expected_tags):
        workload, arm, seed_text = tag.rsplit("|", 2)
        record = completed[tag]
        if record.get("workload") != workload or record.get("seed") != int(seed_text):
            raise ValueError(f"R4 model identity mismatch: {tag}")
        spec = arms[arm]
        if record.get("arm") != spec:
            raise ValueError(f"R4 arm binding mismatch: {tag}")
        expected_dim = 249 - 4 * len(spec["drop"]) + 4 * len(spec["add"])
        if record.get("feature_dim") != expected_dim:
            raise ValueError(f"R4 feature dimension mismatch: {tag}")
        artifact_name = record.get("artifact", "")
        if not re.fullmatch(r"[0-9a-f]{64}\.pkl", artifact_name):
            raise ValueError(f"unsafe R4 artifact name: {tag}")
        artifact_path = contained_artifact(root, artifact_name)
        digest = sha256_file(artifact_path)
        verify_sha256(artifact_path, record.get("sha256", ""))
        if record.get("support", {}).get("fitted_from_attack_data") is not False:
            raise ValueError(f"attack data was used or not excluded in fit: {tag}")
        fit = record.get("fit", {})
        if fit.get("feature_dim") != expected_dim or fit.get("train_examples", 0) < 1200 or fit.get("calibration_examples", 0) < 1200:
            raise ValueError(f"R4 fit metadata invalid: {tag}")
        artifacts.append({"tag": tag, "path": artifact_name, "sha256": digest,
                          "bytes": artifact_path.stat().st_size, "feature_dim": expected_dim})
        dimensions[str(expected_dim)] = dimensions.get(str(expected_dim), 0) + 1

    terminal_hash = sha256_file(terminal_path)
    result = {
        "schema": "sentinel-pulse-r4-matched-fit-audit-v1",
        "state": "fit_set_verified_blind_evaluation_pending",
        "checked_at_unix": time.time(),
        "scope": {"workloads": len(workloads), "arms": len(arms), "seeds": len(seeds),
                  "expected_models": 693, "verified_models": len(artifacts),
                  "feature_dimensions": dimensions},
        "binding": {"config_sha256": config_hash, "start_sha256": sha256_file(start_path),
                    "inputs_sha256": sha256_file(inputs_path), "index_sha256": index_hash,
                    "terminal_sha256": terminal_hash,
                    "matched_study_source_sha256": sha256_file(matched_source)},
        "fit_artifacts": artifacts,
        "normal_holdout_complete": False,
        "fresh_blind_complete": False,
        "precision": None,
        "recall": None,
        "confusion_matrix": {"TP": None, "FP": None, "TN": None, "FN": None,
                             "uncertain": None, "missing_telemetry": None},
        "automatic_promotion": False,
    }
    return result


def write_new(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
    with path.open("xb") as stream:
        stream.write(payload)
        stream.flush()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--study-root", type=Path, required=True)
    parser.add_argument("--source-root", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    output = args.output or args.study_root / "R4_FIT_AUDIT.json"
    result = audit(args.study_root, args.source_root)
    write_new(output, result)
    print(json.dumps({"state": result["state"], **result["scope"],
                      "output": str(output), "terminal_sha256": result["binding"]["terminal_sha256"]}))


if __name__ == "__main__":
    main()
