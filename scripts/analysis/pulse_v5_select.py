#!/usr/bin/env python3
"""Step 2 of protocol lidds-ml-v5 (+ amendments 1, 2): choose the gate of the token branch for the cluster.

Among the candidates that kept the lidds-ml-v4 numbers on LID-DS development and CB-DS (lidds_ml_v5.py), on the trials of
a finished live run scored with the new fit (token_branch_fit.py --pool-level): primary recall >= 95 %, then the lowest
benign flag rate, then a phase candidate before a hold candidate, then the shorter seconds, then the looser pool level.
The trials are development for this choice; the fit learnt none of their windows (token_branch_fit.trial_spans).

A window alarms when its workload score is above the workload threshold and it passes the candidate's gate:
hold candidate: more than `seconds` after the container's last execve, and pool score above the workload's pool threshold;
phase candidate: within `seconds` of the last execve the pool score must exceed the phase threshold instead. The phase
threshold is the moment Gumbel without the top 1 % of the maximum pool score within the phase of each benign launch.

Writes SELECT.json and, for the chosen candidate, MODELS.json and GATE.json for the worker (tokens.models, tokens.gate).

    python3 pulse_v5_select.py --lidds lidds-ml-v5.json --fit DIR --run-root ROOT --output DIR [--jobs 8]
"""
import argparse
from collections import defaultdict
import json
import math
from multiprocessing import Pool
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from sentinel_pulse.common import open_sealed  # noqa: E402
from sentinel_pulse.detector.token_model import CountTokenLM, has_execve  # noqa: E402
from token_branch_fit import sha, threshold, trimmed_gumbel  # noqa: E402
import lidds_ml_v5 as v5  # noqa: E402

CAMPAIGN = 'pulse-development-matrix'
HORIZON = 15.0
LEAD = 3.0                     # windows read before a trial: the longest hold is 2 s
PRIMARY = (6, 12, 24)
MIN_PRIMARY_RECALL = 0.95
MODELS, SPANS = {}, {}
POOL = CountTokenLM()


def load_trials(campaign):
    """[(label, start, (pod_uid, container), workload, rate)] with the pair's attack rate on its controls too."""
    rows = [json.loads(line) for line in (campaign / 'INTERVALS.jsonl').read_text().splitlines() if line]
    rate = {str(r['trial_id']).split(':')[0]: r.get('rate_per_second') for r in rows if r['label'] == 'attack'}
    out = []
    for r in rows:
        label = 'attack' if r['label'] == 'attack' else 'benign' if r.get('control_kind') == 'benign_exec' else 'control'
        out.append(dict(label=label, start=float(r['start_at']), key=(r['pod_uid'], r['container_name']),
                        workload=r['workload_key'], rate=rate.get(str(r['trial_id']).split(':')[0])))
    return out


def scan_segment(path):
    """Windows of one segment near a trial of their container: (pod, container, end, workload score, pool score, execve)."""
    out = []
    with open_sealed(Path(path)) as stream:
        for line in stream:
            w = json.loads(line)
            spans = SPANS.get((w['pod_uid'], w['container_name']))
            end = w['window_end']
            if not spans or not any(a <= end <= b for a, b in spans):
                continue
            lm = MODELS.get(w['workload_key'])
            if lm is None:
                continue
            out.append((w['pod_uid'], w['container_name'], end, lm.window_score(w['grams']), POOL.window_score(w['grams']),
                        has_execve(w['grams'])))
    return out


def since_exec(windows):
    """Seconds since the container's last execve for each window (inf before the first); windows in time order."""
    last, out = -math.inf, []
    for _, _, end, _, _, execve in windows:
        if execve:
            last = end
        out.append(end - last)
    return out


def phase_maxima(trials, by_container, seconds):
    """Maximum pool score within `seconds` of an execve, per benign launch."""
    maxima = []
    for t in trials:
        if t['label'] != 'benign':
            continue
        windows = by_container.get(t['key'], [])
        best = [w[4] for w, s in zip(windows, since_exec(windows)) if t['start'] <= w[2] <= t['start'] + HORIZON and s <= seconds]
        if best:
            maxima.append(max(best))
    return maxima


def fires(windows, since, start, workload_threshold, pool_threshold, seconds, phase_threshold):
    """One trial under one candidate. pool_threshold None: no pool condition; phase_threshold None: a hold candidate."""
    for w, s in zip(windows, since):
        if not start <= w[2] <= start + HORIZON or w[3] <= workload_threshold:
            continue
        held = bool(seconds) and s <= seconds
        if held and phase_threshold is not None:
            if w[4] > phase_threshold:
                return True
        elif not held and (pool_threshold is None or w[4] > pool_threshold):
            return True
    return False


def evaluate(trials, by_container, spec, pool_fits, candidates):
    """{name: counts}: per candidate, hits and totals of primary attacks, all attacks, benign launches and idle controls."""
    since = {k: since_exec(v) for k, v in by_container.items()}
    phase_fit = {s: trimmed_gumbel(m) if len(m) >= 3 else None
                 for s in v5.PHASES for m in [phase_maxima(trials, by_container, s)]}
    out = {}
    for name, branches, seconds, level, phase in candidates:
        if len(branches) != 1:
            continue
        fit = phase_fit.get(seconds) if phase else None
        if phase and fit is None:
            continue
        phase_threshold = threshold(fit, level) if phase else None
        c = defaultdict(int)
        for t in trials:
            entry = spec.get(t['workload'])
            if entry is None:
                continue
            pool_threshold = None if level is None else threshold(pool_fits[t['workload']][f'{seconds:g}'], level)
            hit = fires(by_container.get(t['key'], []), since.get(t['key'], []), t['start'], entry['threshold'],
                        pool_threshold, seconds, phase_threshold)
            groups = [t['label']] + (['primary'] if t['label'] == 'attack' and t['rate'] in PRIMARY else [])
            for g in groups:
                c[g + '_n'] += 1
                c[g + '_hits'] += hit
        out[name] = dict(c, seconds=seconds, level=level, phase=phase, phase_threshold=phase_threshold)
    return out


def choose(results, eligible):
    """The registered order; None when no candidate qualifies."""
    ok = [n for n, r in results.items() if n in eligible and r.get('primary_n')
          and r['primary_hits'] / r['primary_n'] >= MIN_PRIMARY_RECALL]
    if not ok:
        return None
    return min(ok, key=lambda n: (results[n]['benign_hits'] / max(1, results[n]['benign_n']), not results[n]['phase'],
                                  results[n]['seconds'], -(results[n]['level'] or 1.0), n))


def gate_files(chosen, result, spec, pool_fits, fit_dir, output):
    """MODELS.json and GATE.json of the chosen candidate; no GATE.json when it has no gate."""
    seconds, level = result['seconds'], result['level']
    gated = bool(seconds) or level is not None
    models = {}
    for key, entry in spec.items():
        models[key] = {k: entry[k] for k in ('lm', 'lm_sha256', 'threshold')}
        if gated:      # -1: every window passes (scores are >= 0), for a candidate without a pool level
            models[key]['pool_threshold'] = -1.0 if level is None else threshold(pool_fits[key][f'{seconds:g}'], level)
    (output / 'MODELS.json').write_text(json.dumps(models, indent=1, sort_keys=True) + '\n')
    if gated:
        pool = fit_dir / 'pool.lm.json.gz'
        gate = dict(pool=dict(lm=str(pool), lm_sha256=sha(pool)), exec_hold_seconds=seconds, level=level, candidate=chosen)
        if result['phase']:
            gate['phase_threshold'] = result['phase_threshold']
        (output / 'GATE.json').write_text(json.dumps(gate, indent=1) + '\n')


def main():
    global POOL
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--lidds', type=Path, required=True)
    ap.add_argument('--fit', type=Path, required=True)
    ap.add_argument('--run-root', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--jobs', type=int, default=8)
    a = ap.parse_args()
    a.output.mkdir(parents=True, exist_ok=False)
    eligible = {n for n, r in json.loads(a.lidds.read_text())['candidates'].items() if r['keeps_v4']}
    spec = json.loads((a.fit / 'MODELS.json').read_text())
    report = json.loads((a.fit / 'FIT.json').read_text())['workloads']
    pool_fits = {k: report[k]['pool_gumbel'] for k in spec}
    MODELS.update({k: CountTokenLM.load(Path(e['lm'])) for k, e in spec.items()})
    POOL = CountTokenLM.load(a.fit / 'pool.lm.json.gz')
    trials = load_trials(a.run_root / CAMPAIGN)
    for t in trials:
        SPANS.setdefault(t['key'], []).append((t['start'] - LEAD, t['start'] + HORIZON))
    segments = sorted({str(p.parent / 'tokens.jsonl') for p in a.run_root.glob('workers/*/segments/*/tokens.jsonl*')})
    with Pool(a.jobs) as pool:      # fork: the workers share the loaded models
        parts = pool.map(scan_segment, segments, chunksize=1)
    by_container = defaultdict(list)
    for part in parts:
        for w in part:
            by_container[(w[0], w[1])].append(w)
    for windows in by_container.values():
        windows.sort(key=lambda w: w[2])
    results = evaluate(trials, by_container, spec, pool_fits, list(v5.candidates()))
    chosen = choose(results, eligible)
    (a.output / 'SELECT.json').write_text(json.dumps(dict(schema='pulse-v5-select-v1', run_root=str(a.run_root), fit=str(a.fit),
                                                           eligible=sorted(eligible), candidates=results, chosen=chosen), indent=1) + '\n')
    for name, r in results.items():
        print(f"{name:28s} lidds {'keep' if name in eligible else 'no  '} primary {r['primary_hits']}/{r['primary_n']} "
              f"all {r['attack_hits']}/{r['attack_n']} benign {r['benign_hits']}/{r['benign_n']} control {r['control_hits']}/{r['control_n']}")
    print('chosen', chosen)
    if chosen:
        gate_files(chosen, results[chosen], spec, pool_fits, a.fit, a.output)


if __name__ == '__main__':
    main()
