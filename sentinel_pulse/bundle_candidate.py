"""Stage a frozen candidate manifest and its checksum-verified artifacts."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile

from .idle_candidate import SCHEMA
from .integrity import contained_artifact, verify_sha256


def bundle_candidate(manifest_path: Path, artifact_root: Path, output_dir: Path) -> int:
    """Copy a frozen model bundle without changing the manifest or its hashes.

    The destination must not exist. Artifacts are verified before and after
    copying, and the completed directory is atomically published.
    """
    manifest_path = manifest_path.resolve(strict=True)
    artifact_root = artifact_root.resolve(strict=True)
    output_dir = output_dir.absolute()
    if output_dir.exists():
        raise ValueError("output directory already exists; refusing to overwrite")
    if not artifact_root.is_dir() or not output_dir.parent.is_dir():
        raise ValueError("artifact root and output parent must already exist")

    raw_manifest = manifest_path.read_bytes()
    manifest = json.loads(raw_manifest)
    if (not isinstance(manifest, dict) or manifest.get("schema") != SCHEMA
            or manifest.get("serving_compatible") is not False):
        raise ValueError("input is not a frozen non-serving model-only candidate")
    workloads = manifest.get("workloads")
    if not isinstance(workloads, dict) or not workloads:
        raise ValueError("candidate manifest contains no workload artifacts")

    # Validate the whole source set before allocating/copying the output.
    for entry in workloads.values():
        if not isinstance(entry, dict):
            raise ValueError("candidate workload artifact entry is malformed")
        source = contained_artifact(artifact_root, entry.get("artifact", ""))
        verify_sha256(source, entry.get("artifact_sha256", ""))

    stage = Path(tempfile.mkdtemp(prefix=f".{output_dir.name}.stage-",
                                  dir=output_dir.parent))
    try:
        for entry in workloads.values():
            name = entry["artifact"]
            source = contained_artifact(artifact_root, name)
            target = stage / name
            digest = hashlib.sha256()
            with source.open("rb") as src, target.open("xb") as dst:
                for chunk in iter(lambda: src.read(1024 * 1024), b""):
                    digest.update(chunk)
                    dst.write(chunk)
            if digest.hexdigest() != entry["artifact_sha256"]:
                raise ValueError(f"artifact changed while staging: {name}")
            target.chmod(0o440)
        (stage / "CANDIDATE_MANIFEST.json").write_bytes(raw_manifest)
        (stage / "CANDIDATE_MANIFEST.json").chmod(0o440)
        # Re-verify from the exact directory the runtime will load.
        for entry in workloads.values():
            verify_sha256(contained_artifact(stage, entry["artifact"]),
                          entry["artifact_sha256"])
        os.rename(stage, output_dir)
    except BaseException:
        shutil.rmtree(stage, ignore_errors=True)
        raise
    return len(workloads)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--artifact-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        count = bundle_candidate(args.manifest, args.artifact_root, args.output)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        parser.error(f"candidate bundle refused: {type(exc).__name__}: {exc}")
    print(f"verified and staged {count} frozen workload artifacts")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
