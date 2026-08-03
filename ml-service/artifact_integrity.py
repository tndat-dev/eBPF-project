"""Immutable fingerprints shared by validation and promotion gates."""

import hashlib
import json
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


def artifact_provenance(path) -> dict | None:
    """Return the canonical path and digest of an experiment input."""
    if not path:
        return None
    absolute = Path(path).resolve()
    return {"path": str(absolute), "sha256": sha256(absolute)}


def release_files(root: Path) -> tuple[str, ...]:
    """Resolve model files from the candidate's explicit training targets."""
    report_path = root / "training_report.json"
    if report_path.is_file():
        try:
            targets = json.loads(report_path.read_text()).get("models")
        except (OSError, ValueError, TypeError):
            targets = None
        if isinstance(targets, dict) and targets:
            stems = sorted(str(target).replace("/", "__") for target in targets)
            return (
                "vocab.pkl", "dataset_manifest.json", "training_report.json",
                *(f"{stem}_bundle.pkl" for stem in stems),
                *(f"{stem}_lstm.pt" for stem in stems),
            )
    return RELEASE_FILES


def model_release_hashes(model_dir) -> dict:
    """Hash the exact candidate inputs used by a validation run."""
    root = Path(model_dir).resolve()
    files = release_files(root)
    missing = [name for name in files if not (root / name).is_file()]
    if missing:
        raise FileNotFoundError(
            f"incomplete model release {root}: missing {missing}"
        )
    return {name: sha256(root / name) for name in sorted(files)}
