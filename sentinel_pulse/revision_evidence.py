"""Validate a completed workload-revision observer before data collection."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys


REQUIRED_START_FILES = (
    "START",
    "APPROVED_FINGERPRINT.json",
    "SOURCE_SHA256SUMS",
)
REQUIRED_FINAL_FILES = (
    "APPROVED_FINGERPRINT.json",
    "final-fingerprint.json",
    "OBSERVATIONS.log",
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_fingerprint(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"invalid workload fingerprint: {path}") from error
    if value.get("schema") != "sentinel-pulse-workload-fingerprint-v1":
        raise ValueError(f"unsupported workload fingerprint: {path}")
    workloads = value.get("workloads")
    if not isinstance(workloads, dict) or not workloads:
        raise ValueError(f"empty workload fingerprint: {path}")
    return value


def _resolve_recorded_artifact(root: Path, recorded_path: str) -> Path:
    basename = Path(recorded_path.lstrip("*")).name
    direct = root / basename
    if direct.is_file():
        return direct
    matches = [path for path in root.rglob(basename) if path.is_file()]
    if len(matches) != 1:
        raise ValueError(f"cannot resolve observer checksum artifact: {basename}")
    return matches[0]


def _checksum_index(
    root: Path,
    name: str,
    required: tuple[str, ...],
    *,
    verify_all: bool = False,
) -> dict[str, str]:
    path = root / name
    if not path.is_file():
        raise ValueError(f"missing observer checksum index: {name}")
    entries: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        fields = line.split(maxsplit=1)
        if len(fields) != 2:
            raise ValueError(f"malformed observer checksum line in {name}")
        checksum, recorded_path = fields
        basename = Path(recorded_path.lstrip("*")).name
        if basename in entries:
            raise ValueError(f"duplicate observer checksum entry: {basename}")
        entries[basename] = checksum
        if verify_all:
            artifact = _resolve_recorded_artifact(root, recorded_path)
            if checksum != _sha256(artifact):
                raise ValueError(f"observer checksum mismatch: {basename}")
    for filename in required:
        artifact = root / filename
        if not artifact.is_file():
            raise ValueError(f"missing observer artifact: {filename}")
        expected = entries.get(filename)
        if expected is None or expected != _sha256(artifact):
            raise ValueError(f"observer checksum mismatch: {filename}")
    return entries


def compare_fingerprints(approved: dict, current: dict) -> None:
    """Reject any controller revision change, independent of JSON formatting."""
    if approved.get("sha256") != current.get("sha256"):
        raise ValueError("live workload fingerprint hash differs from approved observer")
    if approved.get("workloads") != current.get("workloads"):
        raise ValueError("live workload revisions differ from approved observer")


def validate_completed_observer(root: Path, current_fingerprint: Path | None = None) -> dict:
    root = root.resolve()
    if not root.is_dir():
        raise ValueError(f"observer evidence directory does not exist: {root}")
    if (root / "ACTIVE").exists():
        raise ValueError("workload revision observer is still active")
    if (root / "FAILED").exists() or (root / "REJECTED").exists():
        raise ValueError("workload revision observer did not complete successfully")
    if not (root / "COMPLETE").is_file():
        raise ValueError("workload revision observer is not complete")

    _checksum_index(root, "START_SHA256SUMS", REQUIRED_START_FILES)
    _checksum_index(root, "FINAL_SHA256SUMS", REQUIRED_FINAL_FILES)
    _checksum_index(root, "SOURCE_SHA256SUMS", (), verify_all=True)
    approved_path = root / "APPROVED_FINGERPRINT.json"
    final_path = root / "final-fingerprint.json"
    approved = _load_fingerprint(approved_path)
    final = _load_fingerprint(final_path)
    compare_fingerprints(approved, final)

    if current_fingerprint is not None:
        compare_fingerprints(approved, _load_fingerprint(current_fingerprint))

    return {
        "schema": "sentinel-pulse-revision-evidence-validation-v1",
        "observer_root": str(root),
        "complete_sha256": _sha256(root / "COMPLETE"),
        "start_checksums_sha256": _sha256(root / "START_SHA256SUMS"),
        "final_checksums_sha256": _sha256(root / "FINAL_SHA256SUMS"),
        "approved_fingerprint_file_sha256": _sha256(approved_path),
        "approved_workload_fingerprint_sha256": approved.get("sha256"),
        "workload_count": len(approved["workloads"]),
        "live_fingerprint_verified": current_fingerprint is not None,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--observer-root", type=Path, required=True)
    parser.add_argument("--current-fingerprint", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        report = validate_completed_observer(args.observer_root, args.current_fingerprint)
    except ValueError as error:
        print(f"revision evidence invalid: {error}", file=sys.stderr)
        raise SystemExit(2) from error
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")


if __name__ == "__main__":
    main()
