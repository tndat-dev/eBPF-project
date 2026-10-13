"""Create a verified, non-destructive sidecar manifest for a sealed C2 run."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from .integrity import sha256_file


def _load(path: Path):
    return json.loads(path.read_text())


def _safe_model_path(root: Path, relative: str) -> Path:
    candidate = Path(relative)
    if candidate.parts != ("models", candidate.name) or candidate.name in ("", ".", ".."):
        raise ValueError(f"invalid model artifact path: {relative!r}")
    resolved_root = root.resolve()
    resolved = (root / candidate).resolve(strict=True)
    if resolved.parent != (resolved_root / "models").resolve(strict=True):
        raise ValueError("model artifact escapes sealed models directory")
    return resolved


def derive_manifest(run_dir: Path, output_path: Path | None = None) -> dict:
    """Verify sealed run evidence and write a corrected manifest sidecar.

    The original manifest and all run evidence remain byte-for-byte unchanged.
    The sidecar is created exclusively; an existing output is never replaced.
    """
    run_dir = Path(run_dir)
    start_path = run_dir / "START.json"
    results_path = run_dir / "RESULTS.json"
    terminal_path = run_dir / "TERMINAL.json"
    original_path = run_dir / "VARIANT_MODEL_MANIFEST.json"
    start, results, terminal, original = map(
        _load, (start_path, results_path, terminal_path, original_path)
    )

    if terminal.get("state") != "completed" or terminal.get("errors"):
        raise ValueError("run is not a clean completed terminal")
    if terminal.get("start_sha256") != sha256_file(start_path):
        raise ValueError("terminal START checksum mismatch")
    start_hash = sha256_file(start_path)
    results_hash = sha256_file(results_path)
    if results.get("start_sha256") != start_hash:
        raise ValueError("RESULTS START checksum mismatch")
    if original.get("schema") != "sentinel-pulse-syscall-variant-models-v1":
        raise ValueError("unexpected original manifest schema")
    if original.get("start_sha256") != start_hash or original.get("results_sha256") != results_hash:
        raise ValueError("original manifest is not bound to this START/RESULTS")

    workload_results = results.get("workloads", {})
    workload_manifest = original.get("workloads", {})
    expected_workloads = set(start.get("workloads", []))
    if set(workload_results) != expected_workloads or set(workload_manifest) != expected_workloads:
        raise ValueError("workload coverage differs across sealed inputs")

    verified = {}
    fitted_count = 0
    for workload in sorted(expected_workloads):
        result_variants = workload_results[workload].get("variants", {})
        manifest_variants = workload_manifest[workload]
        if set(result_variants) != set(manifest_variants):
            raise ValueError(f"variant coverage mismatch for {workload}")
        verified[workload] = {}
        for variant, record in sorted(result_variants.items()):
            sealed = manifest_variants[variant]
            model_rel = record.get("model_artifact")
            if record.get("status") != "measured" or not model_rel:
                raise ValueError(f"missing fitted model for {workload}/{variant}")
            model_path = _safe_model_path(run_dir, model_rel)
            digest = sha256_file(model_path)
            size = model_path.stat().st_size
            if digest != record.get("model_sha256") or size != record.get("model_bytes"):
                raise ValueError(f"RESULTS model integrity mismatch for {workload}/{variant}")
            # This sidecar specifically repairs the historical duplicate-prefix
            # bug; refuse unrelated or manually edited manifest discrepancies.
            if sealed.get("artifact") != f"models/{model_rel}":
                raise ValueError(f"unexpected original artifact path for {workload}/{variant}")
            if sealed.get("sha256") != digest or sealed.get("bytes") != size:
                raise ValueError(f"original manifest integrity mismatch for {workload}/{variant}")
            if sealed.get("masked_columns") != record.get("masked_columns"):
                raise ValueError(f"feature-mask mismatch for {workload}/{variant}")
            fitted_count += 1
            verified[workload][variant] = {**sealed, "artifact": model_rel}

    expected_fits = int(start.get("expected_fits", fitted_count))
    if fitted_count != expected_fits or terminal.get("completed_fits") != expected_fits:
        raise ValueError("fit count does not match the registered run")

    derived = {
        **original,
        "workloads": verified,
        "derived_manifest": True,
        "derivation": {
            "method": "verify sealed START/RESULTS/TERMINAL and all model SHA-256/size; correct duplicate models/ prefix only",
            "source_manifest_sha256": sha256_file(original_path),
            "start_sha256": start_hash,
            "results_sha256": results_hash,
            "terminal_sha256": sha256_file(terminal_path),
            "verified_model_count": fitted_count,
            "original_evidence_modified": False,
        },
    }
    output_path = Path(output_path) if output_path else run_dir / "VARIANT_MODEL_MANIFEST.derived.json"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    payload = (json.dumps(derived, indent=2, sort_keys=True) + "\n").encode()
    with output_path.open("xb") as handle:
        handle.write(payload)
        handle.flush()
    checksum_path = output_path.with_suffix(output_path.suffix + ".sha256")
    with checksum_path.open("xb") as handle:
        handle.write(f"{hashlib.sha256(payload).hexdigest()}  {output_path.name}\n".encode())
        handle.flush()
    return derived


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    manifest = derive_manifest(args.run_dir, args.output)
    print(json.dumps(manifest["derivation"], sort_keys=True))


if __name__ == "__main__":
    main()
