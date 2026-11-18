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
from collections import Counter, defaultdict
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


def file_counts(job):
    """Pass 1 over one tokens.jsonl: session gram counts before and after the time split (no window is kept)."""
    path, mid = job
    early, late, n = Counter(), Counter(), 0
    with open_sealed(Path(path)) as stream:
        for line in stream:
            if '"session":[[' not in line:
                continue
            w = json.loads(line)
            if not w.get('session'):
                continue
            n += 1
            target = early if float(w['window_end']) < mid else late
            for *g, c in w['session']:
                target[strip(g)] += int(c)
    return early, late, n


LM_HALF = None


def file_scores(job):
    """Pass 2: held-out session window scores (after the split) by the first-half model, and 60 s block maxima."""
    path, mid = job
    scores, blocks = [], {}
    with open_sealed(Path(path)) as stream:
        for line in stream:
            if '"session":[[' not in line:
                continue
            w = json.loads(line)
            if not w.get('session') or float(w['window_end']) < mid:
                continue
            sc = LM_HALF.window_score(w['session'], TOP)
            scores.append(sc)
            cell = (w['pod_uid'], w['container_name'], math.floor(float(w['window_end']) / BLOCK))
            blocks[cell] = max(blocks.get(cell, 0.0), sc)
    return scores, blocks


def lm_of(counters):
    lm = CountTokenLM()
    for counter in counters:
        for g, c in counter.items():
            lm.learn(g, c)
    return lm.finalize()


def fit(root, jobs):
    """(model on the whole capture, held-out window scores, held-out block maxima, session windows) with a time split
    in the middle of the capture span."""
    global LM_HALF
    cfg = json.loads((Path(root) / 'CONFIG.json').read_text())
    mid = float(cfg['selection_start']) + float(cfg['seconds']) / 2
    files = [(str(p), mid) for p in sorted(Path(root).glob('workers/*/segments/*/tokens.jsonl*'))]
    early, late, n = Counter(), Counter(), 0
    with Pool(jobs) as pool:
        for e, l, k in pool.imap_unordered(file_counts, files, chunksize=1):
            early.update(e)
            late.update(l)
            n += k
    if not n:
        raise SystemExit('the capture has no session part (not a lineage build)')
    LM_HALF = lm_of([early])
    scores, blocks = [], {}
    with Pool(jobs) as pool:                                    # forked after LM_HALF is set
        for sc, bl in pool.imap_unordered(file_scores, files, chunksize=1):
            scores.extend(sc)
            for cell, v in bl.items():
                blocks[cell] = max(blocks.get(cell, 0.0), v)
    return lm_of([early, late]), np.asarray(scores), np.asarray(list(blocks.values())), n


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
    lm, held, blocks, n_windows = fit(a.capture, a.jobs)
    thresholds = dict(gumbel_blocks=m.threshold(v4.trimmed_gumbel(blocks, TRIM), ALPHA),
                      empirical_999=float(np.quantile(held, 0.999)), empirical_9999=float(np.quantile(held, 0.9999)))
    trials = la.live.load_trials(a.run_root / la.CAMPAIGN)
    windows, files = ns.collect(a.run_root, trials, a.jobs)
    res = evaluate(trials, windows, lm, thresholds)
    criterion = {name: bool(r.get('attack', {}).get('rate') is not None and r['attack']['rate'] >= 0.95
                            and all(r.get(lab, {}).get('rate') is not None and r[lab]['rate'] <= 0.20 for lab in ('admin', 'benign')))
                 for name, r in res.items()}
    doc = dict(schema='improvement-round-v1-session-channel', protocol='sentinel_pulse/protocol/improvement-round-v1.json (D5b)',
               capture=str(a.capture), run=str(a.run_root), session_windows=n_windows, held_out_windows=int(len(held)),
               held_out_blocks=int(len(blocks)), thresholds=thresholds, intervals=res, criterion_met=criterion)
    a.output.write_text(json.dumps(doc, indent=1, default=float))
    print(json.dumps(dict(thresholds=thresholds, criterion_met=criterion,
                          rates={n: {k: v['rate'] for k, v in r.items()} for n, r in res.items()}), default=float))


if __name__ == '__main__':
    main()
