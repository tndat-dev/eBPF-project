#!/usr/bin/env python3
"""Losslessly compress sealed segment files of a finished matched run to free NFS space.

Each file is streamed once: SHA-256 of the original bytes is computed while writing
``<name>.gz``. The original is removed only if that hash equals the segment's TERMINAL.json
seal. Receipts:

- ``raw.jsonl`` (default, duplicates features.jsonl, read by no analysis): RAW_COMPRESSION.json;
- ``--files features.jsonl decisions.jsonl ...``: COMPRESSION.json ({"files": {name: entry}}),
  with first/last window bounds for features.jsonl so readers need not decompress to find them.

Readers open compressed files through ``sentinel_pulse.common.open_sealed`` / ``sealed_sha256``;
``gzip -dc <name>.gz | sha256sum`` re-proves the seal at any time. Only sealed segments (with
TERMINAL.json) are touched, so a running capture's open segment is never compressed.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import math
import os
from pathlib import Path
import time


def window_bounds(path: Path):
    """First window_start and last window_end of a plain features.jsonl (head + 1 MiB tail)."""
    first = last = None
    with path.open('rb') as stream:
        for line in stream:
            row = json.loads(line)
            if 'window_start' in row:
                first = float(row['window_start']); break
        stream.seek(max(0, path.stat().st_size - 1024**2))
        if stream.tell():
            stream.readline()
        for line in stream:
            if line.endswith(b'\n'):
                row = json.loads(line)
                if 'window_end' in row:
                    last = max(last or -math.inf, float(row['window_end']))
    return first, last


def compress_file(segment: Path, name: str, seal: str) -> dict:
    raw = segment/name
    target = segment/(name + '.gz.partial')
    digest = hashlib.sha256()
    with raw.open('rb') as src, gzip.open(target, 'wb', compresslevel=1) as dst:
        for block in iter(lambda: src.read(4 << 20), b''):
            digest.update(block)
            dst.write(block)
    if digest.hexdigest() != seal:
        target.unlink()
        return dict(status='seal_mismatch_kept_original', sha256=digest.hexdigest(), seal=seal)
    entry = dict(status='compressed', original=name, original_sha256=seal, original_bytes=raw.stat().st_size)
    if name == 'features.jsonl':
        entry['first_window_start'], entry['last_window_end'] = window_bounds(raw)
    gz = segment/(name + '.gz')
    os.replace(target, gz)
    entry.update(gzip=gz.name, gzip_bytes=gz.stat().st_size,
                 gzip_sha256=hashlib.sha256(gz.read_bytes()).hexdigest(), compressed_at_unix=time.time())
    return entry


def compress(segment: Path, names) -> list[dict]:
    seals = json.loads((segment/'TERMINAL.json').read_text())['seals']
    results = []
    for name in names:
        if not (segment/name).exists() or name not in seals:
            continue
        entry = compress_file(segment, name, seals[name])
        if entry['status'] == 'compressed':
            if name == 'raw.jsonl':
                receipt = dict(entry, segment=str(segment))
                (segment/'RAW_COMPRESSION.json').write_text(json.dumps(receipt, indent=2) + '\n')
            else:
                path = segment/'COMPRESSION.json'
                doc = json.loads(path.read_text()) if path.exists() else dict(files={})
                doc['files'][name] = entry
                tmp = path.with_suffix('.json.tmp'); tmp.write_text(json.dumps(doc, indent=2) + '\n'); os.replace(tmp, path)
            (segment/name).unlink()
        results.append(dict(entry, segment=str(segment), name=name))
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--run-root', type=Path, required=True, help='e.g. .../matched-parallel-20261015')
    parser.add_argument('--files', nargs='+', default=['raw.jsonl'])
    args = parser.parse_args()
    total = dict(compressed=0, saved_bytes=0, mismatched=[])
    for seal in sorted(args.run_root.glob('workers/*/segments/s*/TERMINAL.json')):
        for result in compress(seal.parent, args.files):
            if result['status'] == 'compressed':
                total['compressed'] += 1
                total['saved_bytes'] += result['original_bytes'] - result['gzip_bytes']
            else:
                total['mismatched'].append(result)
            print(json.dumps(dict(segment=seal.parent.name, worker=seal.parent.parent.parent.name,
                                  name=result['name'], status=result['status'])), flush=True)
    print(json.dumps(total))


if __name__ == '__main__':
    main()
