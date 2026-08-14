"""Fail-closed integrity helpers for Sentinel Pulse datasets and artifacts."""

from __future__ import annotations

import hashlib
import hmac
from pathlib import Path


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_sha256(path: Path, expected: str) -> None:
    if len(expected) != 64 or any(character not in "0123456789abcdef" for character in expected):
        raise ValueError(f"invalid SHA-256 metadata for {path.name}")
    observed = sha256_file(path)
    if not hmac.compare_digest(observed, expected):
        raise ValueError(f"SHA-256 mismatch for {path.name}")


def contained_artifact(model_dir: Path, artifact_name: str) -> Path:
    """Resolve one plain artifact filename without allowing manifest traversal."""
    if not artifact_name or Path(artifact_name).name != artifact_name:
        raise ValueError("model manifest contains an unsafe artifact path")
    root = model_dir.resolve()
    artifact = (root / artifact_name).resolve()
    if artifact.parent != root:
        raise ValueError("model artifact escapes model directory")
    if not artifact.is_file():
        raise ValueError(f"missing model artifact: {artifact_name}")
    return artifact
