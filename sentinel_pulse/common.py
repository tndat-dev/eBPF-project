"""Shared file, JSON and source-provenance helpers for Sentinel Pulse.

These used to be copied into several experiment modules; runtime code now
imports them from here so it no longer depends on retired experiment runners.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import pickle
import subprocess
import tempfile
import time

from .integrity import sha256_file

# Frozen artifacts were pickled before the 2026-10-18 package split and name
# classes by their flat module path; map those onto the current layout.
LEGACY_MODULES = {
    'sentinel_pulse.model': 'sentinel_pulse.detector.model',
    'sentinel_pulse.support_model': 'sentinel_pulse.detector.support_model',
    'sentinel_pulse.extended_reference_experiment': 'sentinel_pulse.detector.extended_reference_experiment',
    'sentinel_pulse.idle_candidate': 'sentinel_pulse.detector.idle_candidate',
    'sentinel_pulse.features': 'sentinel_pulse.collector.features',
    'sentinel_pulse.matched_study': 'sentinel_pulse.syscall_study.matched_study',
}


class _ArtifactUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        return super().find_class(LEGACY_MODULES.get(module, module), name)


def load_artifact(stream):
    """Unpickle a hash-verified model artifact written by any package layout.

    Pickle executes code: callers must verify the artifact digest first.
    """
    return _ArtifactUnpickler(stream).load()


def atomic_json(path: Path, value: dict) -> None:
    """Write JSON through a same-directory temporary file, fsync and rename."""
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, indent=2, sort_keys=True, allow_nan=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def append_jsonl(path: Path, value: dict) -> None:
    """Append one compact JSON line and fsync before returning."""
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")
        stream.flush()
        os.fsync(stream.fileno())


def clean_source(source: Path) -> tuple[str, dict[str, str]]:
    """Return (commit, {path: sha256}) for a clean checkout's sentinel_pulse tree."""
    args = ["git", "-c", "safe.directory=" + str(source), "-C", str(source)]
    if subprocess.check_output(args + ["status", "--porcelain", "--untracked-files=all"], text=True).strip():
        raise ValueError("worker source is dirty")
    commit = subprocess.check_output(args + ["rev-parse", "HEAD"], text=True).strip()
    names = subprocess.check_output(args + ["ls-files", "sentinel_pulse"], text=True).splitlines()
    return commit, {name: sha256_file(source / name) for name in names}


class RotatingJsonlFollower:
    """Follow an append-only JSONL path across atomic rotation/truncation."""

    def __init__(self, path: Path, from_start: bool = False, poll_seconds: float = 0.05):
        if poll_seconds < 0:
            raise ValueError("tail poll interval cannot be negative")
        self.path = path
        self.from_start = from_start
        self.poll_seconds = poll_seconds
        self.source = None
        self.identity = None
        self._initial_open = True

    def _open(self) -> bool:
        try:
            source = self.path.open(encoding="utf-8")
        except FileNotFoundError:
            return False
        if self._initial_open and not self.from_start:
            source.seek(0, os.SEEK_END)
        descriptor = os.fstat(source.fileno())
        self.source = source
        self.identity = (descriptor.st_dev, descriptor.st_ino)
        self._initial_open = False
        return True

    def _path_replaced_or_truncated(self) -> bool:
        if self.source is None:
            return False
        try:
            current = self.path.stat()
        except FileNotFoundError:
            return False
        except PermissionError:
            # A finite collector can restore root ownership while shutting
            # down after this process has already opened the stream. At EOF,
            # keep the valid descriptor and wait for an explicit detector stop
            # instead of entering a systemd restart storm on a path stat.
            return False
        return (
            (current.st_dev, current.st_ino) != self.identity
            or current.st_size < self.source.tell()
        )

    def readline(self) -> str:
        while True:
            if self.source is None:
                if not self._open():
                    time.sleep(self.poll_seconds)
                    continue
            line_start = self.source.tell()
            line = self.source.readline()
            if line.endswith("\n"):
                return line
            if line:
                # A reader can observe an append-only file between the writer's
                # data write and terminating newline.  Rewind and wait instead
                # of handing a torn JSON object to the decoder.  If rotation
                # replaced the file while a fragment was pending, discard only
                # that unterminated fragment and reopen the new inode.
                if self._path_replaced_or_truncated():
                    self.source.close()
                    self.source = None
                    self.identity = None
                    continue
                self.source.seek(line_start)
            if self._path_replaced_or_truncated():
                self.source.close()
                self.source = None
                self.identity = None
                continue
            time.sleep(self.poll_seconds)

    def close(self) -> None:
        if self.source is not None:
            self.source.close()
            self.source = None
            self.identity = None


# --- sealed segment files that may have been compressed (scripts/compress_raw_frames.py) ---
COMPRESSION_RECEIPTS = ('COMPRESSION.json', 'RAW_COMPRESSION.json')


def compression_receipt(path: Path) -> dict | None:
    """The receipt entry for ``path`` if it was replaced by ``path.gz`` (None otherwise)."""
    for name in COMPRESSION_RECEIPTS:
        receipt = path.parent/name
        if receipt.exists():
            doc = json.loads(receipt.read_text())
            entry = doc.get('files', {}).get(path.name) if 'files' in doc else (
                doc if doc.get('original') == path.name else None)
            if entry:
                return entry
    return None


def sealed_path(path: Path) -> Path:
    """``path`` if present, else its verified-compressed ``.gz`` sibling (else ``path``)."""
    if path.exists():
        return path
    gz = path.with_name(path.name + '.gz')
    return gz if gz.exists() else path


def open_sealed(path: Path, mode: str = 'r', encoding: str | None = 'utf-8'):
    """Open a sealed segment file transparently whether it is plain or gzip-compressed."""
    import gzip
    real = sealed_path(path)
    binary = 'b' in mode
    if real.suffix == '.gz' and path.suffix != '.gz':
        return gzip.open(real, 'rb' if binary else 'rt', encoding=None if binary else encoding)
    return real.open('rb' if binary else 'r', encoding=None if binary else encoding)


def sealed_sha256(path: Path) -> str:
    """SHA-256 of the original bytes: hashed directly, or proven via the compression receipt
    (the receipt's original hash was checked against the seal when the file was compressed,
    and the .gz must still match the receipt's gzip hash)."""
    if path.exists():
        return sha256_file(path)
    entry = compression_receipt(path)
    gz = path.with_name(path.name + '.gz')
    if entry is None or not gz.exists():
        raise FileNotFoundError(path)
    if sha256_file(gz) != entry['gzip_sha256']:
        raise ValueError('compressed file differs from its receipt: ' + str(gz))
    return entry['original_sha256']
