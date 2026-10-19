#!/usr/bin/env python3
"""Losslessly compress sealed raw.jsonl files of a finished matched run to free NFS space.

raw.jsonl duplicates features.jsonl (features + full_counts_delta) and no analysis reads it,
but it is sealed evidence. Each file is streamed once: SHA-256 of the original bytes is
computed while writing raw.jsonl.gz. The original is removed only if that hash equals the
segment's TERMINAL.json seal. A receipt (RAW_COMPRESSION.json) per segment records both hashes,
so `gzip -dc raw.jsonl.gz | sha256sum` can re-prove the seal later.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import time


def compress(segment: Path) -> dict | None:
    raw = segment/'raw.jsonl'
    if not raw.exists():
        return None
    seal = json.loads((segment/'TERMINAL.json').read_text())['seals'].get('raw.jsonl')
    target = segment/'raw.jsonl.gz.partial'
    digest = hashlib.sha256()
    with raw.open('rb') as src, gzip.open(target, 'wb', compresslevel=1) as dst:
        for block in iter(lambda: src.read(4 << 20), b''):
            digest.update(block)
            dst.write(block)
    if digest.hexdigest() != seal:
        target.unlink()
        return dict(segment=str(segment), status='seal_mismatch_kept_original', sha256=digest.hexdigest(), seal=seal)
    gz = segment/'raw.jsonl.gz'
    os.replace(target, gz)
    receipt = dict(segment=str(segment), status='compressed', original='raw.jsonl', original_sha256=seal,
                   original_bytes=raw.stat().st_size, gzip='raw.jsonl.gz', gzip_bytes=gz.stat().st_size,
                   gzip_sha256=hashlib.sha256(gz.read_bytes()).hexdigest(), compressed_at_unix=time.time())
    (segment/'RAW_COMPRESSION.json').write_text(json.dumps(receipt, indent=2) + '\n')
    raw.unlink()
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-root', type=Path, required=True, help='e.g. .../matched-parallel-20261015')
    args = parser.parse_args()
    total = dict(compressed=0, saved_bytes=0, mismatched=[])
    for seal in sorted(args.run_root.glob('workers/*/segments/s*/TERMINAL.json')):
        result = compress(seal.parent)
        if result is None:
            continue
        if result['status'] == 'compressed':
            total['compressed'] += 1
            total['saved_bytes'] += result['original_bytes'] - result['gzip_bytes']
        else:
            total['mismatched'].append(result)
        print(json.dumps(dict(segment=seal.parent.name, worker=seal.parent.parent.parent.name, status=result['status'])), flush=True)
    print(json.dumps(total))


if __name__ == '__main__':
    main()
