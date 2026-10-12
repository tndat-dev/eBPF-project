"""Freeze eligible idle-aware reference artifacts for later independent evaluation.

This creates a model-only artifact manifest. It does not define an alert policy,
admit data as normal, make the model serving-compatible, or promote anything.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import tempfile
import time

from .integrity import sha256_file


def _read_json(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path.name}")
    return value


def _atomic_create(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(value, stream, sort_keys=True, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        # Do not replace a previous freeze: a changed experiment needs a new path.
        os.link(temporary, path)
        os.unlink(temporary)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def freeze(experiment: Path, output: Path) -> dict:
    experiment = experiment.resolve(strict=True)
    if output.exists():
        raise ValueError("candidate manifest already exists; refusing to overwrite")

    start_path = experiment / "START.json"
    index_path = experiment / "INDEX.json"
    inputs_path = experiment / "INPUTS.json"
    results_path = experiment / "RESULTS.json"
    terminal_path = experiment / "TERMINAL.json"
    start = _read_json(start_path)
    index = _read_json(index_path)
    inputs = _read_json(inputs_path)
    results = _read_json(results_path)
    terminal = _read_json(terminal_path)

    if start.get("include_idle_windows") is not True:
        raise ValueError("expected the idle-aware feature contract")
    if start.get("feature_dimensions") != 249:
        raise ValueError("unexpected feature dimension")
    if start.get("attack_data_used_for_fit") is not False:
        raise ValueError("reference fit is not normal-only")
    if start.get("normal_training_admission") is not False:
        raise ValueError("reference data has not been admitted as normal")
    if terminal.get("state") != "completed_reference_experiment":
        raise ValueError("reference fit is not complete")
    if results.get("start_sha256") != sha256_file(start_path):
        raise ValueError("results are not bound to START")
    if sha256_file(inputs_path) != start.get("input_manifest_sha256"):
        raise ValueError("reference input manifest differs from START")

    for item in inputs.get("reference_files", []):
        reference = Path(item["path"]).resolve(strict=True)
        if experiment not in reference.parents or sha256_file(reference) != item.get("sha256"):
            raise ValueError("frozen raw reference input checksum differs")

    indexed = index.get("workloads")
    fitted = results.get("workloads")
    if not isinstance(indexed, dict) or not isinstance(fitted, dict) or set(indexed) != set(fitted):
        raise ValueError("reference index/results key sets differ")
    expected = len(indexed)
    artifact_count = sum("artifact" in row for row in fitted.values())
    if terminal.get("completed") != expected or terminal.get("fitted") != artifact_count:
        raise ValueError("terminal counts do not match reference results")

    eligible: dict[str, dict] = {}
    excluded: dict[str, dict] = {}
    for key in sorted(indexed):
        data_path = (experiment / indexed[key]["file"]).resolve(strict=True)
        if experiment not in data_path.parents or sha256_file(data_path) != indexed[key].get("sha256"):
            raise ValueError(f"indexed training data checksum differs for {key}")
        row = fitted[key]
        if row.get("state") != "fitted_exploratory_reference" or "artifact" not in row:
            raise ValueError(f"model is not fitted for {key}")
        fit = row.get("fit", {})
        support = row.get("support", {})
        dimension = fit.get("feature_dim")
        if dimension != 249:
            raise ValueError(f"feature dimension mismatch for {key}")
        constant = support.get("constant_training_coordinates")
        artifact = (experiment / row["artifact"]).resolve(strict=True)
        if experiment not in artifact.parents:
            raise ValueError(f"artifact escapes experiment root for {key}")
        digest = sha256_file(artifact)
        if digest != row.get("artifact_sha256"):
            raise ValueError(f"artifact checksum mismatch for {key}")
        calibration = fit.get("calibration_examples", 0)
        support_calibration = support.get("calibration_rows", 0)
        required_support = support.get("minimum_calibration_examples_per_branch", 0)
        if calibration < fit.get("minimum_calibration_examples", 1):
            raise ValueError(f"tree calibration support is insufficient for {key}")
        if support_calibration < required_support or required_support <= 0:
            raise ValueError(f"support calibration is insufficient for {key}")

        entry = {
            "artifact": row["artifact"],
            "artifact_sha256": digest,
            "feature_dim": dimension,
            "tree_alpha": 0.001,
            "support_alpha_per_window_combined": support.get("alpha_per_window_combined"),
            "train_examples": fit.get("train_examples"),
            "tree_calibration_examples": calibration,
            "support_calibration_examples": support_calibration,
            "constant_training_coordinates": constant,
        }
        if constant == dimension:
            excluded[key] = dict(entry, reason="all model input coordinates were constant during normal fit")
        else:
            eligible[key] = entry

    if not eligible:
        raise ValueError("no non-degenerate model artifacts are eligible")

    return {
        "schema": "sentinel-pulse-model-only-candidate-v1",
        "candidate_name": "sentinel-pulse-idle-aware-model-only-20261012",
        "created_at_unix": time.time(),
        "status": "offline_frozen_candidate_for_independent_evaluation",
        "feature_contract": start.get("feature_contract", "pulse-entered-plus-seccomp-skip-idle-v2"),
        "feature_dimensions": 249,
        "history_windows": start.get("history_windows"),
        "reference_root": str(experiment),
        "source_commit": start.get("source_commit"),
        "software": start.get("software"),
        "bindings": {
            "manifest_generator_sha256": sha256_file(Path(__file__)),
            "start_sha256": sha256_file(start_path),
            "index_sha256": sha256_file(index_path),
            "results_sha256": sha256_file(results_path),
            "terminal_sha256": sha256_file(terminal_path),
        },
        "fit_protocol": {
            "label": start.get("reference_label"),
            "attack_data_used": False,
            "normal_training_admission": False,
            "automatic_promotion": False,
        },
        "decision_policy": None,
        "serving_compatible": False,
        "automatic_promotion": False,
        "eligible_workload_count": len(eligible),
        "excluded_degenerate_workload_count": len(excluded),
        "workloads": eligible,
        "excluded_degenerate_workloads": excluded,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--experiment", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    value = freeze(args.experiment, args.output)
    _atomic_create(args.output, value)
    print(json.dumps({"status": value["status"], "eligible": value["eligible_workload_count"],
                      "excluded_degenerate": value["excluded_degenerate_workload_count"],
                      "manifest": str(args.output)}, sort_keys=True))


if __name__ == "__main__":
    main()
