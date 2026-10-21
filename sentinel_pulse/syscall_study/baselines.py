"""Baseline detectors on Pulse's data and decision pipeline (protocol baseline-evaluation-v1).

Only the scorer differs between arms; features, training data, conformal thresholding, k-of-n confirmation and
matched alert budgets are Pulse's:

- ``base29``       : Pulse scorer (syscall-arms base29 models: ExtraTrees history -> current + support branch);
- ``iforest``      : Isolation Forest (200 trees) on the standardized current 249-column vector;
- ``autoencoder``  : MLP autoencoder (249-64-16-64-249) on the standardized current vector, score = reconstruction MSE;
- ``freq_profile`` : bag-of-system-calls style frequency deviation: L1 distance of the syscall-frequency columns
                     (29 ratios + 64 hashed syscall bins) to the training mean, scaled by training MAD.

``fit`` trains the baselines per workload on the syscall-arms selection rows (train contexts, same capped indices
and the same minimum-data rule as Pulse's fits). ``score`` streams a sealed capture (local copy) once, builds Pulse
contexts with ``ContextBuilder``, scores every arm and writes (1) a holdout score dump in score_dump's format for
the normal span and (2) replay windows for the campaign trials; ``arm_budget`` / ``arm_bootstrap`` read both
unchanged. Baselines put the same score in both branch fields, so their joint p-value is min(1, 2p); the matched
budget absorbs that constant factor.

Combined arms (protocol baseline-fresh-replication-v1): ``tree_ae`` keeps base29's tree score and puts the
autoencoder score (same seed) in the second branch, i.e. Pulse with the autoencoder in place of the support branch.
``score`` computes it on the fly; ``combine`` derives it from an existing evaluation's dumps and replay.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
import hashlib
import json
from pathlib import Path
import pickle
import time

import numpy as np

from ..common import atomic_json, load_artifact, open_sealed
from ..detector.fast_forest import VerifiedFastScorer
from ..integrity import contained_artifact, sha256_file
from .arm_attack_replay import HISTORY_LEAD_SECONDS, INTERVAL_SECONDS, TRIAL_IDENTITY, load_trials, trial_key
from .matched_holdout import ContextBuilder, bounds
from .score_dump import ScoreCollector

SEEDS = (73021, 73022, 73023)
BASELINES = ('iforest', 'autoencoder', 'freq_profile')
COMBOS = {'tree_ae': ('base29', 'autoencoder')}   # name -> (arm giving the tree score, arm giving the second score)
ARMS = ('base29', *BASELINES, *COMBOS)
FREQ_COLUMNS = list(range(29, 58)) + list(range(63, 127))
WIDTH = 249
TRAIN_CAP = 3000
MINIMUM_CONTEXTS = 1200
CAMPAIGN_MARGIN_SECONDS = 60.0


class Standardizer:
    def __init__(self, x):
        self.mean = x.mean(0); self.std = np.maximum(x.std(0), 1e-6)

    def __call__(self, x):
        return (x - self.mean) / self.std


class FreqProfile:
    def __init__(self, x):
        f = x[:, FREQ_COLUMNS]
        self.mean = f.mean(axis=0)
        self.mad = np.maximum(np.median(np.abs(f - np.median(f, axis=0)), axis=0), 1e-4)

    def score(self, x):
        return (np.abs(x[:, FREQ_COLUMNS] - self.mean) / self.mad).sum(axis=1)


def fit_workload(train_current, seeds=SEEDS):
    from sklearn.ensemble import IsolationForest
    from sklearn.neural_network import MLPRegressor
    scaler = Standardizer(train_current); z = scaler(train_current)
    out = dict(scaler=scaler, freq_profile=FreqProfile(train_current), iforest={}, autoencoder={})
    for seed in seeds:
        out['iforest'][seed] = IsolationForest(n_estimators=200, random_state=seed, n_jobs=1).fit(z)
        out['autoencoder'][seed] = MLPRegressor(hidden_layer_sizes=(64, 16, 64), max_iter=300, early_stopping=True,
                                                random_state=seed).fit(z, z)
    return out


def baseline_scores(models, current):
    """{(arm, seed): score array} for a batch of current vectors (higher = more anomalous).
    freq_profile is deterministic, so it is one model reported under the first seed."""
    z = models['scaler'](current); out = {}
    for seed, m in models['iforest'].items():
        out['iforest', seed] = -m.score_samples(z)
    for seed, m in models['autoencoder'].items():
        out['autoencoder', seed] = ((m.predict(z) - z) ** 2).mean(axis=1)
    out['freq_profile', SEEDS[0]] = models['freq_profile'].score(current)
    return out


def fit(source_study: Path, workload_dir: Path, output: Path):
    from .matched_study import contexts as base_contexts
    index = json.loads((source_study/'INDEX.json').read_text())
    # syscall-arms study (INPUTS.json) or a study derived from it (feature groups keep the span in INDEX.json)
    inputs = json.loads((source_study/'INPUTS.json').read_text()) if (source_study/'INPUTS.json').exists() else index
    start, end = inputs['selection_start'], inputs['selection_end']
    output.mkdir(parents=True, exist_ok=True)
    previous = json.loads((output/'FIT.json').read_text())['workloads'] if (output/'FIT.json').exists() else {}
    report = {}
    for key, item in sorted(index['workloads'].items()):
        target = output/(hashlib.sha256(key.encode()).hexdigest() + '.pkl')
        if isinstance(previous.get(key), dict) and target.exists():
            report[key] = previous[key]; continue
        path = workload_dir/Path(item['path']).name
        if sha256_file(path) != item['sha256']:
            raise ValueError('workload rows changed: ' + key)
        with path.open() as f:
            rows = sorted((json.loads(line) for line in f), key=lambda r: (r['window_end'], str(r['cgroup_id'])))
        parts = base_contexts(rows, dict(add=[], drop=[]), start, end)
        if any(len(parts.get(p, ())) < MINIMUM_CONTEXTS for p in ('train', 'calibration')):
            report[key] = dict(skipped={p: len(parts.get(p, ())) for p in ('train', 'calibration')}); continue
        train = parts['train']
        if len(train) > TRAIN_CAP:   # same capped indices as Pulse's syscall-arms fits
            train = train[np.linspace(0, len(train)-1, TRAIN_CAP, dtype=int)]
        t0 = time.time()
        models = fit_workload(train[:, -WIDTH:].astype(np.float64))
        partial = target.with_suffix('.partial')
        with partial.open('wb') as f:
            pickle.dump(dict(workload=key, models=models, train_contexts=len(train)), f, pickle.HIGHEST_PROTOCOL)
        partial.replace(target)
        report[key] = dict(train_contexts=len(train), seconds=round(time.time() - t0, 1), sha256=sha256_file(target))
        atomic_json(output/'FIT.json', dict(schema='pulse-baselines-fit-v1', state='fitting', workloads={**previous, **report}))
        print(key, report[key], flush=True)
    atomic_json(output/'FIT.json', dict(schema='pulse-baselines-fit-v1', state='completed', source_study=str(source_study),
                                       source_sha256=sha256_file(Path(__file__)), arms=list(BASELINES), seeds=list(SEEDS),
                                       train_context_cap=TRAIN_CAP, workloads=report, finished_at_unix=time.time()))
    return report


def combined(scores):
    """{(combo, seed): (tree, second)} from per-arm {(arm, seed): (tree, support)} score pairs."""
    return {(name, seed): (scores[a, seed][0], scores[b, seed][0])
            for name, (a, b) in COMBOS.items() for seed in SEEDS if (a, seed) in scores and (b, seed) in scores}


def combine(source: Path, output: Path, pulse_study: Path, holdout: tuple):
    """Derive the combined arms from an evaluation written by ``score``; the output holds base29 + combos."""
    for npz in sorted((source/'score-dump').glob('*/s*/scores.npz')):
        with np.load(npz, allow_pickle=False) as data:
            arrays = {k: data[k] for k in data.files}
        tags = {k.rsplit('::', 1)[0] for k in arrays if '::' in k}
        out = {'identities': arrays['identities']}
        for tag in tags:
            if tag.split('|')[1] == 'base29':
                out.update({k: v for k, v in arrays.items() if k.startswith(tag + '::')})
        for tag in tags:
            workload, arm, seed = tag.split('|')
            for name, (a, b) in COMBOS.items():
                other = f'{workload}|{b}|{seed}'
                if a != arm or other not in tags:
                    continue
                for field in ('identity', 'window_end'):
                    if not np.array_equal(arrays[f'{tag}::{field}'], arrays[f'{other}::{field}']):
                        raise ValueError(f'rows differ between {tag} and {other}')
                new = f'{workload}|{name}|{seed}'
                out[f'{new}::identity'] = arrays[f'{tag}::identity']; out[f'{new}::window_end'] = arrays[f'{tag}::window_end']
                out[f'{new}::tree_score'] = arrays[f'{tag}::tree_score']; out[f'{new}::support_score'] = arrays[f'{other}::tree_score']
        target = output/'score-dump'/npz.parent.parent.name/npz.parent.name/'scores.npz'
        target.parent.mkdir(parents=True, exist_ok=True)
        partial = target.with_suffix('.partial.npz')
        with partial.open('wb') as f:
            np.savez_compressed(f, **out)
        partial.replace(target)
    lines = {}
    with (source/'replay'/'windows.jsonl').open() as f:
        for line in f:
            row = json.loads(line)
            if row['tag'].split('|')[1] in {x for pair in COMBOS.values() for x in pair}:
                lines[row['tag'], row['trial_key']] = row['windows']
    rp = output/'replay'; rp.mkdir(parents=True, exist_ok=True)
    with (rp/'windows-all.jsonl').open('w') as f:
        for (tag, tk), windows in sorted(lines.items()):
            workload, arm, seed = tag.split('|')
            if arm == 'base29':
                f.write(json.dumps(dict(tag=tag, trial_key=tk, windows=windows)) + '\n')
            for name, (a, b) in COMBOS.items():
                other = lines.get((f'{workload}|{b}|{seed}', tk))
                if a != arm or other is None:
                    continue
                if [w['end'] for w in windows] != [w['end'] for w in other]:
                    raise ValueError(f'replay windows differ for {tag} / {tk}')
                merged = [dict(w, support_score=o['tree_score']) for w, o in zip(windows, other)]
                f.write(json.dumps(dict(tag=f'{workload}|{name}|{seed}', trial_key=tk, windows=merged)) + '\n')
    atomic_json(rp/'RESULTS-all.json', dict(schema='pulse-baselines-combine-v1', source=str(source), combos=COMBOS,
                                           source_sha256=sha256_file(Path(__file__)), finished_at_unix=time.time()))
    register(output, pulse_study, holdout, arms=('base29', *COMBOS))


def load_baselines(directory: Path):
    """Models written by ``fit`` on this host; FIT.json pins every file's hash before it is unpickled."""
    fitted = json.loads((directory/'FIT.json').read_text())['workloads']
    out = {}
    for key, item in fitted.items():
        if not isinstance(item, dict) or 'sha256' not in item:
            continue
        path = directory/(hashlib.sha256(key.encode()).hexdigest() + '.pkl')
        if sha256_file(path) != item['sha256']:
            raise ValueError('baseline model hash mismatch: ' + key)
        with path.open('rb') as f:
            out[key] = pickle.load(f)['models']
    return out


def campaign_span(campaign: Path, margin=CAMPAIGN_MARGIN_SECONDS):
    """First interval start to campaign end, +- margin (the normal-span exclusion used for policy selection)."""
    starts = [float(json.loads(line)['start_at']) for line in (campaign/'INTERVALS.jsonl').read_text().splitlines() if line]
    return min(starts) - margin, float(json.loads((campaign/'TERMINAL.json').read_text())['finished_at_unix']) + margin


def in_spans(a, b, spans):
    return any(b > x and a < y for x, y in spans)


def score(workers_root: Path, pulse_study: Path, baseline_dir: Path | None, campaigns, output: Path,
          holdout: tuple, exclude=(), batch=2048, nodes=(), study_arms=('base29',)):
    """Stream every sealed segment once; dump holdout scores and campaign replay windows for all arms.
    ``nodes`` restricts the run to some worker directories (one process per node; ``register`` merges).
    ``study_arms``: fitted arms of ``pulse_study`` to score (feature-group study: all of its arms, each with its
    own ``ContextBuilder`` spec); baselines and combos are computed from the base29 contexts only."""
    terminal = json.loads((pulse_study/'TERMINAL.json').read_text())['completed']
    index = json.loads((pulse_study/'INDEX.json').read_text())
    keys = set(index['workloads'])
    specs = {arm: index.get('arms', {}).get(arm, dict(add=[], drop=[])) for arm in study_arms}
    baselines = load_baselines(baseline_dir) if baseline_dir else {}
    trials = load_trials(campaigns)
    windows_of = defaultdict(list)   # trial identity -> (first, last, trial key)
    for t in trials:
        begin = float(t['start_at'])
        windows_of[tuple(str(t[k]) for k in TRIAL_IDENTITY)].append(
            (begin - HISTORY_LEAD_SECONDS, begin + INTERVAL_SECONDS + 2, trial_key(t)))
    exclude = list(exclude) + [campaign_span(c) for c in campaigns]
    first = min([holdout[0]] + [a for spans in windows_of.values() for a, _, _ in spans])
    fast = VerifiedFastScorer()   # exact-equality check against sklearn on each model's first batch
    base_models, replay, stats = {}, defaultdict(list), defaultdict(int)

    def fitted(workload, arm='base29'):
        if (workload, arm) not in base_models:
            base_models[workload, arm] = {}
            for seed in SEEDS:
                item = terminal.get(f'{workload}|{arm}|{seed}')
                if item is None:
                    continue
                path = contained_artifact(pulse_study, item['artifact'])
                if sha256_file(path) != item['sha256']:
                    raise ValueError('frozen model hash mismatch: ' + workload)
                with path.open('rb') as f:
                    m = load_artifact(f)
                m.base.estimator.n_jobs = 1
                base_models[workload, arm][seed] = m
        return base_models[workload, arm]

    for node_dir in sorted(p for p in workers_root.iterdir() if p.is_dir() and (not nodes or p.name in nodes)):
        builders = {arm: ContextBuilder(spec, first, holdout[1]) for arm, spec in specs.items()}   # continuous across segments
        for seal in sorted((node_dir/'segments').glob('s*/TERMINAL.json')):
            segment = seal.parent; collector = ScoreCollector(); pending = defaultdict(list)
            if (bounds(segment/'features.jsonl')[1] or first) < first:
                continue   # wholly before the first window that can matter (history state stays empty)

            def flush(key):
                workload, study_arm = key
                items = pending.pop(key, [])
                models = fitted(workload, study_arm)
                if not items or not models:
                    return
                rows = [r for r, _, _ in items]; ctx = np.stack([c for _, c, _ in items])
                hold = np.array([h for _, _, (h, _) in items]); tks = [t for _, _, (_, t) in items]
                alpha = float(next(iter(models.values())).alpha)
                scores = {}
                for seed, m in models.items():
                    p = fast(f'{workload}|{study_arm}', m, ctx)
                    scores[study_arm, seed] = (np.asarray(p['tree_score']), np.asarray(p['support_score']))
                if study_arm == 'base29' and workload in baselines:
                    for (arm, seed), s in baseline_scores(baselines[workload], ctx[:, -WIDTH:].astype(np.float64)).items():
                        scores[arm, seed] = (s, s)
                scores.update(combined(scores))
                for (arm, seed), (tree, support) in scores.items():
                    tag = f'{workload}|{arm}|{seed}'
                    if hold.any():
                        collector(tag, [r for r, h in zip(rows, hold) if h],
                                  dict(tree_score=tree[hold], support_score=support[hold]))
                    for i, keys_i in enumerate(tks):
                        for tk in keys_i:
                            replay[tag, tk].append(dict(start=float(rows[i]['window_start']), end=float(rows[i]['window_end']),
                                                        alpha=alpha, tree_score=float(tree[i]), support_score=float(support[i])))

            with open_sealed(segment/'features.jsonl') as stream:
                for line in stream:
                    if '"full_counts_delta"' not in line:
                        continue
                    row = json.loads(line)
                    workload = row.get('workload_key')
                    if workload not in keys:
                        continue
                    contexts = {arm: b.observe(row) for arm, b in builders.items()}
                    if all(c is None for c in contexts.values()):
                        continue
                    a, b = float(row['window_start']), float(row['window_end'])
                    in_holdout = holdout[0] <= a and b <= holdout[1] and not in_spans(a, b, exclude)
                    tks = [tk for lo, hi, tk in windows_of.get(tuple(str(row.get(k)) for k in TRIAL_IDENTITY), ())
                           if lo <= a and b <= hi]
                    if not in_holdout and not tks:
                        continue
                    stats['holdout_rows'] += int(in_holdout); stats['trial_rows'] += int(bool(tks))
                    for arm, ctx in contexts.items():
                        if ctx is None:
                            continue
                        pending[workload, arm].append((row, ctx, (in_holdout, tks)))
                        if len(pending[workload, arm]) >= batch:
                            flush((workload, arm))
            for key in list(pending):
                flush(key)
            if collector.data:
                target = output/'score-dump'/node_dir.name/segment.name/'scores.npz'
                target.parent.mkdir(parents=True, exist_ok=True)
                collector.save(target)
            print(node_dir.name, segment.name, dict(stats), flush=True)
    rp = output/'replay'; rp.mkdir(parents=True, exist_ok=True); part = '+'.join(sorted(nodes)) or 'all'
    with (rp/f'windows-{part}.jsonl').open('w') as f:
        for (tag, tk), windows in sorted(replay.items()):
            f.write(json.dumps(dict(tag=tag, trial_key=tk, windows=sorted(windows, key=lambda w: w['end']))) + '\n')
    atomic_json(rp/f'RESULTS-{part}.json', dict(schema='pulse-baselines-replay-v1', trials=len(trials), stats=dict(stats),
                                        holdout_unix=list(holdout), excluded_unix=[list(s) for s in exclude],
                                        fast_path_disabled=fast.disabled,
                                        source_sha256=sha256_file(Path(__file__)), finished_at_unix=time.time()))
    return dict(stats)


def register(output: Path, pulse_study: Path, holdout: tuple, arms=ARMS):
    """Merge per-node replay parts and write the study files that ``score_dump.load_study`` / ``arm_budget``
    require for the baseline evaluation. A trial lives on one node, so parts never share a (tag, trial) key."""
    rp = output/'replay'; seen = set()
    with (rp/'windows.jsonl').open('w') as merged:
        for part in sorted(rp.glob('windows-*.jsonl')):
            for line in part.open():
                key = tuple(json.loads(line)[k] for k in ('tag', 'trial_key'))
                if key in seen:
                    raise ValueError('replay key in two parts: ' + repr(key))
                seen.add(key); merged.write(line)
    atomic_json(rp/'RESULTS.json', dict(schema='pulse-baselines-replay-v1', parts={
        p.name: json.loads(p.read_text()) for p in sorted(rp.glob('RESULTS-*.json'))}, tag_trials=len(seen)))
    workloads = json.loads((pulse_study/'INDEX.json').read_text())['workloads']
    arms = {name: dict(add=[], drop=[]) for name in arms}
    atomic_json(output/'INDEX.json', dict(arms=arms, workloads=workloads, pulse_study=str(pulse_study),
                                         columns=json.loads((pulse_study/'INDEX.json').read_text())['columns']))
    atomic_json(output/'TERMINAL.json', dict(state='baselines_scored', protocol='baseline-evaluation-v1', completed={}))
    atomic_json(output/'R4_FIT_AUDIT.json', dict(binding=dict(index_sha256=sha256_file(output/'INDEX.json'))))
    atomic_json(output/'NORMAL_HOLDOUT_START.json', dict(
        schema='pulse-baselines-holdout-v1', holdout_start_unix=holdout[0], planned_end_unix=holdout[1],
        workload_keys=sorted(workloads), fit_audit_sha256=sha256_file(output/'R4_FIT_AUDIT.json'),
        r4_terminal_sha256=sha256_file(output/'TERMINAL.json')))


def span(text):
    a, b = (float(x) for x in text.split(':'))
    return a, b


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest='command', required=True)
    f = sub.add_parser('fit'); f.add_argument('--source-study', type=Path, required=True)
    f.add_argument('--workload-dir', type=Path, required=True); f.add_argument('--output', type=Path, required=True)
    s = sub.add_parser('score'); s.add_argument('--workers-root', type=Path, required=True)
    s.add_argument('--pulse-study', type=Path, required=True); s.add_argument('--baselines', type=Path)
    s.add_argument('--study-arm', action='append', help='fitted arms of --pulse-study to score (default base29); "all" = every arm')
    s.add_argument('--campaign', type=Path, action='append', required=True); s.add_argument('--output', type=Path, required=True)
    s.add_argument('--holdout', type=span, required=True); s.add_argument('--exclude', type=span, action='append', default=[])
    s.add_argument('--node', action='append', default=[], help='score only these worker directories')
    r = sub.add_parser('register'); r.add_argument('--output', type=Path, required=True)
    r.add_argument('--pulse-study', type=Path, required=True); r.add_argument('--holdout', type=span, required=True)
    r.add_argument('--arm', action='append', help='arms to register (default: base29 + baselines + combos); "study" = every arm of --pulse-study')
    c = sub.add_parser('combine'); c.add_argument('--source', type=Path, required=True)
    c.add_argument('--output', type=Path, required=True); c.add_argument('--pulse-study', type=Path, required=True)
    c.add_argument('--holdout', type=span, required=True)
    a = p.parse_args()
    if a.command == 'fit':
        fit(a.source_study, a.workload_dir, a.output)
    elif a.command == 'score':
        arms = a.study_arm or ['base29']
        if arms == ['all']:
            arms = sorted(json.loads((a.pulse_study/'INDEX.json').read_text())['arms'])
        print(score(a.workers_root, a.pulse_study, a.baselines, a.campaign, a.output, a.holdout, a.exclude, nodes=a.node,
                    study_arms=tuple(arms)))
        if not a.node:
            register(a.output, a.pulse_study, a.holdout)
    elif a.command == 'combine':
        combine(a.source, a.output, a.pulse_study, a.holdout)
    else:
        arms = a.arm or list(ARMS)
        if arms == ['study']:
            arms = sorted(json.loads((a.pulse_study/'INDEX.json').read_text())['arms'])
        register(a.output, a.pulse_study, a.holdout, arms=tuple(arms))


if __name__ == '__main__':
    main()
