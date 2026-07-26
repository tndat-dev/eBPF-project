"""Immutable fingerprints shared by validation and promotion gates."""

import hashlib
from pathlib import Path


TARGET_STEMS = (
    "default__postgres", "production__nginx", "production__redis",
)
RELEASE_FILES = (
    "vocab.pkl", "dataset_manifest.json", "training_report.json",
    *(f"{stem}_bundle.pkl" for stem in TARGET_STEMS),
    *(f"{stem}_lstm.pt" for stem in TARGET_STEMS),
)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def model_release_hashes(model_dir) -> dict:
    """Hash the exact candidate inputs used by a validation run."""
    root = Path(model_dir).resolve()
    missing = [name for name in RELEASE_FILES if not (root / name).is_file()]
    if missing:
        raise FileNotFoundError(
            f"incomplete model release {root}: missing {missing}"
        )
    return {name: sha256(root / name) for name in sorted(RELEASE_FILES)}
