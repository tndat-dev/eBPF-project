"""Merge chronological baseline rounds with checksums and provenance."""

import argparse
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path

import numpy as np


TARGETS = ("default/postgres", "production/nginx", "production/redis")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("inputs", nargs="+")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    inputs = [Path(item).resolve() for item in args.inputs]
    output = Path(args.output).resolve()
    if output.exists():
        raise FileExistsError(f"refusing to overwrite {output}")
    staging = output.with_name(f".{output.name}.staging-{os.getpid()}")
    staging.mkdir(parents=True, exist_ok=False)
    manifest = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "ordering": "input directories then row order; no shuffle",
        "targets": {},
    }

    for pod_key in TARGETS:
        filename = f"{pod_key.replace('/', '__')}.npy"
        arrays = []
        sources = []
        width = None
        for directory in inputs:
            path = directory / filename
            if not path.is_file():
                raise FileNotFoundError(path)
            array = np.load(path, allow_pickle=False)
            if array.ndim != 2 or not np.isfinite(array).all():
                raise ValueError(f"invalid baseline {path}: {array.shape}")
            width = width or array.shape[1]
            if array.shape[1] != width:
                raise ValueError(f"vocabulary width mismatch in {path}")
            arrays.append(array.astype(np.float32, copy=False))
            sources.append({
                "path": str(path),
                "shape": list(array.shape),
                "sha256": sha256(path),
            })

        merged = np.concatenate(arrays, axis=0)
        target_path = staging / filename
        np.save(target_path, merged)
        manifest["targets"][pod_key] = {
            "shape": list(merged.shape),
            "sources": sources,
            "unique_rows": int(np.unique(merged, axis=0).shape[0]),
            "sha256": sha256(target_path),
        }

    (staging / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    )
    os.replace(staging, output)
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
