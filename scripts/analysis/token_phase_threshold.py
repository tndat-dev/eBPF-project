#!/usr/bin/env python3
"""Phase threshold of lidds-ml-v5 (amendment 1) on the cluster: moment Gumbel without the top 1 % on the maximum pool score
within the phase after the execve of each benign launch of a finished live run. Only benign binary intervals are read, no
attack data. Writes GATE.json of token_branch_fit.py again with phase_threshold and the fit. Run after the live run.

    python3 token_phase_threshold.py --run-root ROOT --gate GATE.json --seconds 1 --level 0.01 --output GATE-phase.json
"""
import argparse
from collections import defaultdict
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from sentinel_pulse.common import open_sealed  # noqa: E402
from sentinel_pulse.detector.token_model import CountTokenLM, has_execve  # noqa: E402
from token_branch_fit import threshold, trimmed_gumbel  # noqa: E402

CAMPAIGN = 'pulse-development-matrix'
HORIZON = 15.0


def benign_starts(campaign):
    """{(pod_uid, container): sorted starts of the benign binary intervals}."""
    out = defaultdict(list)
    for line in (campaign / 'INTERVALS.jsonl').read_text().splitlines():
        row = json.loads(line) if line else {}
        if row.get('control_kind') == 'benign_exec':
            out[(row['pod_uid'], row['container_name'])].append(float(row['start_at']))
    return {k: sorted(v) for k, v in out.items()}


def launch_maxima(windows, starts, pool, seconds):
    """Maximum pool score within `seconds` after the last execve, per benign launch; windows in time order per container."""
    last, maxima = {}, {}
    for w in windows:
        key = (w['pod_uid'], w['container_name'])
        end = w['window_end']
        if has_execve(w['grams']):
            last[key] = end
        start = next((s for s in starts.get(key, ()) if s <= end <= s + HORIZON), None)
        if start is None or end - last.get(key, -1e18) > seconds:
            continue
        maxima[key + (start,)] = max(maxima.get(key + (start,), 0.0), pool.window_score(w['grams']))
    return maxima


def read_windows(root, keys):
    for segment in sorted({p.parent for p in root.glob('workers/*/segments/*/tokens.jsonl*')}):
        with open_sealed(segment / 'tokens.jsonl') as stream:
            for line in stream:
                w = json.loads(line)
                if (w['pod_uid'], w['container_name']) in keys:
                    yield w


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--run-root', type=Path, required=True)
    ap.add_argument('--gate', type=Path, required=True)
    ap.add_argument('--seconds', type=float, required=True)
    ap.add_argument('--level', type=float, required=True)
    ap.add_argument('--output', type=Path, required=True)
    a = ap.parse_args()
    gate = json.loads(a.gate.read_text())
    pool = CountTokenLM.load(Path(gate['pool']['lm']))
    starts = benign_starts(a.run_root / CAMPAIGN)
    maxima = launch_maxima(read_windows(a.run_root, set(starts)), starts, pool, a.seconds)
    fit = trimmed_gumbel(list(maxima.values()))
    gate.update(exec_hold_seconds=a.seconds, phase_threshold=threshold(fit, a.level), phase_level=a.level,
                phase_fit=fit, phase_launches=len(maxima), phase_source=str(a.run_root))
    a.output.write_text(json.dumps(gate, indent=1) + '\n')
    print(json.dumps({k: gate[k] for k in ('phase_threshold', 'phase_level', 'phase_launches')}))


if __name__ == '__main__':
    main()
