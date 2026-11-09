#!/usr/bin/env python3
"""Gate of sentinel_pulse/protocol/lidds-ml-v4.json: the official-run token matrices (ml-v4-tokens) must equal the
development-only cross-fitted matrices (ml-xfit-tokens) exactly, on every key of the latter: held-out training and
validation recordings (val/<name>), development test recordings and every CB-DS recording. Keys that exist only in
ml-v4-tokens are the official recordings: they are counted, their values are not read.

    python3 gate_tokens.py NEW_DIR OLD_DIR
"""
from pathlib import Path
import sys

import numpy as np

new_dir, old_dir = map(Path, sys.argv[1:3])
bad = 0
total = dict(keys=0, windows=0, only_new=0)
names = sorted(p.name for p in old_dir.glob('*.npz'))
if names != sorted(p.name for p in new_dir.glob('*.npz')):
    raise SystemExit('scenario files differ')
for name in names:
    old, new = np.load(old_dir / name), np.load(new_dir / name)
    missing = set(old.files) - set(new.files)
    differ = [k for k in old.files if k in new.files and not np.array_equal(old[k], new[k])]
    windows = sum(len(old[k]) for k in old.files)
    only_new = len(set(new.files) - set(old.files))
    print(f'{name:28s} keys {len(old.files):5d} windows {windows:8d} missing {len(missing)} differ {len(differ)} only_in_new {only_new}')
    bad += len(missing) + len(differ)
    total['keys'] += len(old.files)
    total['windows'] += windows
    total['only_new'] += only_new
print(f"total keys {total['keys']} windows {total['windows']} only_in_new {total['only_new']} mismatches {bad}")
print('GATE', 'PASS' if not bad else 'FAIL')
sys.exit(1 if bad else 0)
