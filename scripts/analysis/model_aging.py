#!/usr/bin/env python3
"""Model aging (protocol pulse-live-v6-v1 amendment 1): the v5 token models and thresholds, unchanged, on a later normal
capture made after the cluster was resized (12/11) and recovered.

Per workload, as the fit builds its threshold data (token_branch_fit.crossfit_one): the maximum window score of each
container and 60 s block; a block is above when its maximum exceeds the v5 threshold. The design level is alpha' =
0.0002 x 0.9 per block. Next to it, when --heldout is given (cluster-threshold.json of ml-final-study-v1 part C, whose
Gumbel thresholds equal MODELS.json), the share of v5's own held-out blocks above the same threshold and v5's burden. Burden: episodes (alarms of one container less than 15 s apart)
per replica-hour, a replica-hour being 7,200 windows of one container.

    python3 model_aging.py --run-root CAPTURE --models FIT/token/MODELS.json [--heldout cluster-threshold.json] --output out.json [--jobs 4]

load-diurnal-v1 step A: --by-regime also reports blocks above, episodes and replica-hours per traffic regime (the
regime of the run's traffic_schedule at the block's start; an episode belongs to the regime at its first alarm), and
--design-alpha sets the design level (t3: 0.0003).
"""
# Mô hình v5 KHÔNG ĐỔI chấm normal mới sau khi đổi cấu hình cụm: tỉ lệ khối vượt ngưỡng so với mức giữ ra của chính nó.
import argparse
from collections import defaultdict
import json
import math
from multiprocessing import Pool
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from sentinel_pulse.common import open_sealed  # noqa: E402
from sentinel_pulse.detector.token_model import CountTokenLM  # noqa: E402

ALPHA = 0.0002 * 0.9
BLOCK = 60.0
QUIET = 15.0
_LMS = {}


def _lm(path, top=None):
    """The model with the window score its fit used (MODELS.json "top"; absent = the model default, v5's 10)."""
    if path not in _LMS:
        _LMS[path] = CountTokenLM.load(Path(path))
        if top is not None:
            _LMS[path].default_top = int(top)
    return _LMS[path]


def read_file(job):
    """(block maxima {(workload, pod, container, block): max}, windows per workload, alarms [(workload, pod, container,
    end)], workloads without a model {workload: windows}) of one tokens.jsonl."""
    path, models, block = job
    maxima, windows, alarms, unknown = {}, defaultdict(int), [], defaultdict(int)
    windows_at = defaultdict(int)                          # windows per 60 s block start (regime split)
    with open_sealed(Path(path)) as stream:
        for line in stream:
            w = json.loads(line)
            key = w['workload_key']
            if key not in models:
                unknown[key] += 1
                continue
            lm_path, thr, *top = models[key]
            s = _lm(lm_path, top[0] if top else None).window_score(w['grams'])
            cell = (key, w['pod_uid'], w['container_name'], math.floor(w['window_end'] / block))
            maxima[cell] = max(maxima.get(cell, 0.0), s)
            windows[key] += 1
            windows_at[math.floor(w['window_end'] / block)] += 1
            if s > thr:
                alarms.append((key, w['pod_uid'], w['container_name'], w['window_end']))
    return maxima, dict(windows), alarms, dict(unknown), dict(windows_at)


def regime_of(t, schedule):
    """Regime of the traffic schedule phase holding t (None outside the schedule)."""
    for p in schedule:
        if p['start'] <= t < p['end']:
            return p['regime']
    return None


def by_regime(maxima, windows_at, alarms, models, schedule, block=BLOCK):
    """{regime: blocks, above, rate, replica_hours, episodes, per_replica_hour}."""
    out = defaultdict(lambda: dict(blocks=0, above=0, windows=0, episodes=0))
    for (w, _, _, b), m in maxima.items():
        r = regime_of(b * block, schedule)
        out[r]['blocks'] += 1
        out[r]['above'] += m > models[w][1]
    for t, n in windows_at.items():
        out[regime_of(t * block, schedule)]['windows'] += n
    by_container = defaultdict(list)
    for w, pod, container, end in alarms:
        by_container[(w, pod, container)].append(end)
    for times in by_container.values():
        times = sorted(times)
        starts = [times[0]] + [b for a, b in zip(times, times[1:]) if b - a >= QUIET] if times else []
        for t in starts:
            out[regime_of(t, schedule)]['episodes'] += 1
    for r, v in out.items():
        v['rate'] = v['above'] / v['blocks'] if v['blocks'] else None
        v['replica_hours'] = v['windows'] / 7200
        v['per_replica_hour'] = v['episodes'] / v['replica_hours'] if v['windows'] else None
    return {str(k): v for k, v in out.items()}


def episodes(times, quiet=QUIET):
    times = sorted(times)
    return (1 + sum(1 for a, b in zip(times, times[1:]) if b - a >= quiet)) if times else 0


def v5_heldout(doc, models):
    """{workload: v5's held-out blocks and how many were above its threshold} from the part C receipt."""
    out = {}
    for w, t in doc['thresholds'].items():
        if w in models:
            if abs(t['gumbel'] - models[w][1]) > 1e-9:
                raise ValueError(f'{w}: the receipt threshold is not the model threshold')
            out[w] = dict(blocks=t['blocks'], above=round(t['blocks'] * t['gumbel_exceedance']))
    return out


def summarize(maxima, windows, alarms, models, heldout=None):
    blocks, above = defaultdict(int), defaultdict(int)
    for (w, *_), m in maxima.items():
        blocks[w] += 1
        above[w] += m > models[w][1]
    by_container = defaultdict(list)
    for w, pod, container, end in alarms:
        by_container[(w, pod, container)].append(end)
    ep = defaultdict(int)
    for (w, *_), times in by_container.items():
        ep[w] += episodes(times)
    rows = {}
    for w in sorted(blocks):
        hours = windows[w] / 7200
        rows[w] = dict(blocks=blocks[w], above=above[w], rate=above[w] / blocks[w], design=ALPHA,
                       windows=windows[w], replica_hours=hours, episodes=ep[w],
                       per_replica_hour=ep[w] / hours if hours else None)
        if heldout and w in heldout:
            h = heldout[w]
            rows[w]['v5_heldout'] = dict(h, rate=h['above'] / h['blocks'] if h['blocks'] else None)
    tb, ta = sum(blocks.values()), sum(above.values())
    th, te = sum(windows.values()) / 7200, sum(ep.values())
    pooled: dict = dict(blocks=tb, above=ta, rate=ta / tb if tb else None, design=ALPHA, replica_hours=th, episodes=te,
                  per_replica_hour=te / th if th else None)
    if heldout:
        hb = sum(h['blocks'] for h in heldout.values())
        ha = sum(h['above'] for h in heldout.values())
        pooled['v5_heldout'] = dict(blocks=hb, above=ha, rate=ha / hb if hb else None)
    return rows, pooled


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--run-root', type=Path, required=True)
    ap.add_argument('--models', type=Path, required=True)
    ap.add_argument('--heldout', type=Path, help='cluster-threshold.json of ml-final-study-v1 part C')
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--jobs', type=int, default=4)
    ap.add_argument('--by-regime', action='store_true', help='load-diurnal-v1 A: split by the run traffic regime')
    ap.add_argument('--design-alpha', type=float, default=ALPHA)
    a = ap.parse_args()
    doc = json.loads(a.models.read_text())
    models = {k: (v['lm'], float(v['threshold']), v.get('top')) for k, v in doc.items()}   # t3: top 3
    files = [str(p) for p in sorted(a.run_root.glob('workers/*/segments/*/tokens.jsonl*'))]
    maxima, windows, alarms, unknown = {}, defaultdict(int), [], defaultdict(int)
    windows_at = defaultdict(int)
    with Pool(a.jobs) as pool:
        for m, w, al, un, wa in pool.imap_unordered(read_file, [(f, models, BLOCK) for f in files], chunksize=1):
            for cell, s in m.items():                       # a block can straddle two segment files
                maxima[cell] = max(maxima.get(cell, 0.0), s)
            for k, n in w.items():
                windows[k] += n
            for k, n in un.items():
                unknown[k] += n
            for k, n in wa.items():
                windows_at[k] += n
            alarms += al
    receipt = json.loads(a.heldout.read_text()) if a.heldout else None
    heldout = v5_heldout(receipt, models) if receipt else None
    rows, pooled = summarize(maxima, windows, alarms, models, heldout)
    pooled['design'] = a.design_alpha
    regimes = None
    if a.by_regime:
        schedule = json.loads((a.run_root / 'CONFIG.json').read_text())['traffic_schedule']
        regimes = by_regime(maxima, windows_at, alarms, models, schedule)
    if receipt:
        pooled['v5_burden'] = receipt['burden']['gumbel']
    out = dict(schema='pulse-model-aging-v1', protocol='sentinel_pulse/protocol/pulse-live-v6-v1-amendment-1.json',
               run=str(a.run_root), models=str(a.models), segments_read=len(files), pooled=pooled, workloads=rows,
               without_model=dict(unknown), by_regime=regimes)
    a.output.write_text(json.dumps(out, indent=1))
    print(json.dumps(pooled))


if __name__ == '__main__':
    main()
