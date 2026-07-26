"""Add a new normal phase without destroying an existing stratified holdout."""

import argparse
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path

import numpy as np


TARGETS = ("default/postgres", "production/nginx", "production/redis")


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", required=True)
    parser.add_argument("--addition", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--target", default="production/nginx", choices=TARGETS)
    parser.add_argument("--base-validation-count", type=int, default=14)
    parser.add_argument("--validation-fraction", type=float, default=0.20)
    args = parser.parse_args()

    base, addition, output = map(Path, (args.base, args.addition, args.output))
    if output.exists():
        raise FileExistsError(output)
    staging = output.with_name(f".{output.name}.staging-{os.getpid()}")
    staging.mkdir(parents=True)
    manifest = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "base": str(base.resolve()),
        "addition": str(addition.resolve()),
        "augmented_target": args.target,
        "targets": {},
    }
    try:
        for pod_key in TARGETS:
            name = f"{pod_key.replace('/', '__')}.npy"
            base_array = np.load(base / name, allow_pickle=False)
            if pod_key == args.target:
                extra = np.load(addition / name, allow_pickle=False)
                if extra.shape[1:] != base_array.shape[1:]:
                    raise ValueError("addition vocabulary width mismatch")
                old_val = args.base_validation_count
                if not 1 <= old_val < len(base_array):
                    raise ValueError("invalid base validation count")
                new_val = max(1, int(round(len(extra) * args.validation_fraction)))
                split = len(extra) - new_val
                merged = np.concatenate((
                    base_array[:-old_val], extra[:split],
                    base_array[-old_val:], extra[split:],
                ))
                ordering = {
                    "base_train": len(base_array) - old_val,
                    "addition_train": split,
                    "base_validation": old_val,
                    "addition_validation": new_val,
                }
            else:
                merged = base_array
                ordering = {"unchanged": len(base_array)}
            target_path = staging / name
            np.save(target_path, merged.astype(np.float32, copy=False))
            manifest["targets"][pod_key] = {
                "shape": list(merged.shape),
                "sha256": sha256(target_path),
                "ordering": ordering,
            }
        (staging / "augmentation_manifest.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n"
        )
        os.replace(staging, output)
    except Exception:
        import shutil
        shutil.rmtree(staging, ignore_errors=True)
        raise
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
