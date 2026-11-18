#!/usr/bin/env python3
"""improvement-round-v1 D5(b): a model of the session stream itself, learnt from the session parts of a normal capture.

The lineage build reports, for every window, the part counted on session-lineage threads (runtime exec and descendants).
On a normal capture that part is the kubelet's exec probes (python -c health checks) and any other exec. One count token
model (lidds-ml-v5-t3 scoring: top 3) is learnt on the session grams of all workloads together, half of the capture by
time; the other half gives held-out window scores. Thresholds, registered in the protocol amendment: the moment Gumbel
(trim 0.5 %, alpha' 0.0003) on held-out 60 s block maxima, and the empirical 99.9 % and 99.99 % of held-out windows.

A live-run interval (control, admin, benign, attack, lotl) is flagged when a window ending in [start, start + 15 s] has
a session-part score above the threshold. Criterion (D5): >= 95 % of attacks and <= 20 % of unseen operator commands
and harmless binaries.

    python3 session_channel.py --capture CAPTURE_RUN --run-root LIVE_RUN --output out.json [--jobs 6]
"""
# KÊNH SESSION (vòng cải thiện D5b): học mô hình riêng cho dòng session từ normal (exec probe của kubelet), rồi xem nó
# có tách được tấn công khỏi lệnh quản trị và binary vô hại không.
import argparse
from collections import defaultdict
import json
import math
from multiprocessing import Pool
from pathlib import Path
import sys

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from sentinel_pulse.common import open_sealed  # noqa: E402
from sentinel_pulse.detector.token_model import CountTokenLM, strip  # noqa: E402
import live_attribution as la  # noqa: E402
import lidds_ml_v2 as m  # noqa: E402
import lidds_ml_v4 as v4  # noqa: E402
import native_stream as ns  # noqa: E402

TOP, TRIM, ALPHA, BLOCK = 3, 0.005, 0.0003, 60.0


def session_rows(path):
    """[(container key, window_end, session grams)] of one tokens.jsonl, windows with a session part only."""
    out = []
    with open_sealed(Path(path)) as stream:
        for line in stream:
            if '"session":[[' not in line:
                continue
            w = json.loads(line)
            if w.get('session'):
                out.append(((w['pod_uid'], w['container_name']), float(w['window_end']), w['session']))
    return out


def capture_sessions(root, jobs):
    files = [str(p) for p in sorted(Path(root).glob('workers/*/segments/*/tokens.jsonl*'))]
    rows = []
    with Pool(jobs) as pool:
        for part in pool.imap_unordered(session_rows, files, chunksize=1):
            rows.extend(part)
    rows.sort(key=lambda r: r[1])
    return rows


def fit(rows):
    """Learn on the first half by time, score the second half: (model on all, held-out window scores, block maxima)."""
    if not rows:
        raise SystemExit('the capture has no session part (not a lineage build)')
    mid = rows[len(rows) // 2][1]
    lm = CountTokenLM()
    for _, end, grams in rows:
        if end < mid:
            for *g, c in grams:
                lm.learn(strip(g), int(c))
    lm.finalize()
    scores, blocks = [], defaultdict(float)
    for key, end, grams in rows:
        if end >= mid:
            s = lm.window_score(grams, TOP)
            scores.append(s)
            cell = (key, math.floor(end / BLOCK))
            blocks[cell] = max(blocks[cell], s)
    full = CountTokenLM()
    for _, _, grams in rows:
        for *g, c in grams:
            full.learn(strip(g), int(c))
    return full.finalize(), np.asarray(scores), np.asarray(list(blocks.values()))


def evaluate(trials, windows, lm, thresholds):
    out = {name: defaultdict(lambda: [0, 0]) for name in thresholds}
    pair_pad = {t['pair']: t.get('pad') or 0 for t in trials if t['label'] == 'attack'}
    for t in trials:
        if t['label'] not in ns.LABELS or pair_pad.get(t['pair'], 0):
            continue
        a, b = t['start'], t['start'] + la.HORIZON
        best = max((lm.window_score(s, TOP) for e, _, s in windows.get(t['key'], ()) if a <= e <= b and s), default=0.0)
        for name, thr in thresholds.items():
            out[name][t['label']][0] += best > thr
            out[name][t['label']][1] += 1
    return {name: {lab: dict(k=k, n=n, rate=k / n if n else None) for lab, (k, n) in rows.items()} for name, rows in out.items()}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--capture', type=Path, required=True)
    ap.add_argument('--run-root', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--jobs', type=int, default=6)
    a = ap.parse_args()
    rows = capture_sessions(a.capture, a.jobs)
    lm, held, blocks = fit(rows)
    thresholds = dict(gumbel_blocks=m.threshold(v4.trimmed_gumbel(blocks, TRIM), ALPHA),
                      empirical_999=float(np.quantile(held, 0.999)), empirical_9999=float(np.quantile(held, 0.9999)))
    trials = la.live.load_trials(a.run_root / la.CAMPAIGN)
    windows, files = ns.collect(a.run_root, trials, a.jobs)
    res = evaluate(trials, windows, lm, thresholds)
    criterion = {name: bool(r.get('attack', {}).get('rate') is not None and r['attack']['rate'] >= 0.95
                            and all(r.get(lab, {}).get('rate') is not None and r[lab]['rate'] <= 0.20 for lab in ('admin', 'benign')))
                 for name, r in res.items()}
    doc = dict(schema='improvement-round-v1-session-channel', protocol='sentinel_pulse/protocol/improvement-round-v1.json (D5b)',
               capture=str(a.capture), run=str(a.run_root), session_windows=len(rows), held_out_windows=int(len(held)),
               held_out_blocks=int(len(blocks)), thresholds=thresholds, intervals=res, criterion_met=criterion)
    a.output.write_text(json.dumps(doc, indent=1, default=float))
    print(json.dumps(dict(thresholds=thresholds, criterion_met=criterion,
                          rates={n: {k: v['rate'] for k, v in r.items()} for n, r in res.items()}), default=float))


if __name__ == '__main__':
    main()
