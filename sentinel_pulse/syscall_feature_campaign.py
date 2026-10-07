"""Durable offline experiment launcher; new receipt per restart, no raw edits."""
from __future__ import annotations

import argparse
import fcntl
import json
from pathlib import Path
import signal

from .syscall_feature_experiment import run


def campaign(inputs, root, initial_checkpoint=None):
    root.mkdir(parents=True, exist_ok=True)
    with (root / "campaign.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        attempts = sorted(p for p in root.glob("attempt-*") if p.is_dir())
        parent = next((p for p in reversed(attempts)
                       if (p / "START.json").is_file() and (p / "RESULTS.json").is_file()), initial_checkpoint)
        if parent and (parent / "TERMINAL.json").is_file():
            terminal = json.loads((parent / "TERMINAL.json").read_text())
            if terminal["state"] == "completed":
                return terminal  # service may start after reboot; do not re-fit
        output = root / f"attempt-{len(attempts) + 1:06d}"
        return run(inputs, output, parent)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--inputs", type=Path, required=True)
    p.add_argument("--root", type=Path, required=True)
    p.add_argument("--initial-checkpoint", type=Path)
    args = p.parse_args()
    def stop(_signal, _frame):
        raise KeyboardInterrupt("system stop; next service start will resume the checkpoint")
    signal.signal(signal.SIGTERM, stop)
    try:
        result = campaign(args.inputs.resolve(), args.root.resolve(),
                          args.initial_checkpoint.resolve() if args.initial_checkpoint else None)
    except ValueError:
        # Never retry corruption/binding failures as if they were normal fits.
        import traceback
        traceback.print_exc()
        raise SystemExit(65)
    except KeyboardInterrupt:
        raise SystemExit(130)
    if result["state"] == "completed_with_errors":
        raise SystemExit(1)  # preserve errors, reattempt only missing/error fits


if __name__ == "__main__":
    main()
