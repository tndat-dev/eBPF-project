"""Replay every frozen R4 syscall arm on recorded attack/control pairs.

The matched worker records full syscall-ID deltas for every window, so one
live attack campaign is enough to evaluate all arms offline on identical
intervals: no per-arm attack runs. This rebuilds each arm's R4 contexts from
the sealed feature segments around every trial and scores all three seeds.

Detection delay here is ``first positive window_end - kernel_event_at``; it
excludes live scoring/emission time, so it is a lower bound on kernel->alert.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
import json
import math
from pathlib import Path
import time

import numpy as np

from ..common import atomic_json, load_artifact
from ..integrity import contained_artifact, sha256_file
from .matched_holdout import ContextBuilder, bounds
from .score_dump import load_study

TRIAL_IDENTITY = ('node_name', 'pod_uid', 'container_name', 'workload_revision', 'cgroup_id')
HISTORY_LEAD_SECONDS = 30.0   # rolling-10 + history-3 need ~6.5 s; keep margin
INTERVAL_SECONDS = 15.0


def load_trials(campaigns):
    trials = []
    for campaign in campaigns:
        for path in sorted(campaign.glob('trials/*/EVALUATION_INPUT.json')):
            data = json.loads(path.read_text())
            for label in ('control', 'benign', 'attack'):
                if label in data:
                    trials.append(dict(data[label], campaign=campaign.name, evidence=str(path)))
    return trials


def interval_outcome(windows, trial, alpha_of):
    """Same unit as preview_evaluation: one 15 s interval, >= 13.5 s scored exposure."""
    begin = float(trial['start_at']); finish = begin + INTERVAL_SECONDS
    inside = [w for w in windows if w['end'] > begin and w['start'] < finish]
    covered, last = 0.0, -math.inf
    for w in sorted(inside, key=lambda w: w['start']):
        covered += max(0.0, min(w['end'], finish) - max(w['start'], begin, last))
        last = max(last, min(w['end'], finish))
    if covered < 13.5 or trial.get('infrastructure_issue'):
        return dict(outcome='unknown', delay=None)
    positives = [w for w in inside if w['start'] >= begin and w['end'] <= finish and w['joint_p'] <= alpha_of(w)]
    if trial['label'] != 'attack':
        return dict(outcome='FP_expected' if positives else 'TN_expected', delay=None)
    kernel = trial.get('kernel_event_at')
    if kernel is None:
        return dict(outcome='unknown', delay=None)
    if not positives:
        return dict(outcome='FN', delay=None)
    first = min(w['end'] for w in positives)
    return dict(outcome='TP' if first >= kernel else 'unknown', delay=first - kernel if first >= kernel else None)


def replay(study: Path, campaigns, output: Path, alpha_scales=(1.0,), workers_root: Path | None = None):
    registration, index, terminal = load_study(study)
    trials = load_trials(campaigns)
    by_node = defaultdict(list)
    for t in trials:
        by_node[t['node_name']].append(t)
    models, scored = {}, defaultdict(list)   # (tag, trial_id) -> windows
    for node, node_trials in by_node.items():
        # A later capture (e.g. R6) records the same full-ID deltas under its own worker root.
        worker = dict(output=str(workers_root/node)) if workers_root else registration['workers'][node]
        spans = [(float(t['start_at']) - HISTORY_LEAD_SECONDS, float(t['start_at']) + INTERVAL_SECONDS + 2)
                 for t in node_trials]
        for seal in sorted(Path(worker['output']).glob('segments/s*/TERMINAL.json')):
            first, last = bounds(seal.parent/'features.jsonl')
            if first is None or not any(a < last and b > first for a, b in spans):
                continue
            wanted = defaultdict(list)
            for t in node_trials:
                a = float(t['start_at']) - HISTORY_LEAD_SECONDS; b = float(t['start_at']) + INTERVAL_SECONDS + 2
                if a < last and b > first:
                    wanted[tuple(str(t[k]) for k in TRIAL_IDENTITY)].append((a, b, t))
            rows = defaultdict(list)
            with (seal.parent/'features.jsonl').open() as stream:
                for line in stream:
                    if '"window_end"' not in line:
                        continue
                    row = json.loads(line)
                    key = tuple(str(row.get(k)) for k in TRIAL_IDENTITY)
                    if key in wanted and any(a <= row['window_start'] and row['window_end'] <= b for a, b, _ in wanted[key]):
                        rows[key].append(row)
            for key, items in wanted.items():
                for a, b, trial in items:
                    trial_rows = sorted((r for r in rows[key] if a <= r['window_start'] and r['window_end'] <= b),
                                        key=lambda r: r['window_end'])
                    workload = trial['workload_key']
                    for arm, spec in index['arms'].items():
                        builder = ContextBuilder(spec, a, b)
                        contexts, meta = [], []
                        for row in trial_rows:
                            if row.get('workload_key') != workload:
                                continue
                            context = builder.observe(row)
                            if context is not None:
                                contexts.append(context); meta.append(row)
                        if not contexts:
                            continue
                        for seed in registration['seeds']:
                            tag = f'{workload}|{arm}|{seed}'
                            if tag not in models:
                                item = terminal['completed'][tag]
                                path = contained_artifact(study, item['artifact'])
                                if sha256_file(path) != item['sha256']:
                                    raise ValueError('frozen model hash mismatch: ' + tag)
                                with path.open('rb') as stream:
                                    models[tag] = load_artifact(stream)
                                models[tag].base.estimator.n_jobs = 1
                            pred = models[tag].predict_contexts(np.stack(contexts))
                            alpha = float(models[tag].alpha)
                            scored[tag, trial['trial_id']] = [
                                dict(start=float(r['window_start']), end=float(r['window_end']), alpha=alpha,
                                     joint_p=float(pred['joint_p'][i]), tree_score=float(pred['tree_score'][i]),
                                     support_score=float(pred['support_score'][i]))
                                for i, r in enumerate(meta)]
    report = {}
    for scale in alpha_scales:
        arms = defaultdict(lambda: defaultdict(lambda: defaultdict(int)))
        delays = defaultdict(list)
        for trial in trials:
            workload = trial['workload_key']
            for arm in index['arms']:
                for seed in registration['seeds']:
                    tag = f'{workload}|{arm}|{seed}'
                    windows = scored.get((tag, trial['trial_id']), [])
                    result = interval_outcome(windows, trial, lambda w: w['alpha'] * scale)
                    kind = 'benign' if trial.get('control_kind') == 'benign_exec' else trial['label']
                    arms[arm][seed][f"{kind}:{result['outcome']}"] += 1
                    if result['delay'] is not None:
                        delays[arm].append(result['delay'])
        summary = {}
        for arm, seeds in arms.items():
            per_seed = []
            for seed, c in seeds.items():
                tp, fn = c['attack:TP'], c['attack:FN']; fp, tn = c['expected_normal:FP_expected'], c['expected_normal:TN_expected']
                bfp, btn = c['benign:FP_expected'], c['benign:TN_expected']
                per_seed.append(dict(seed=seed, TP=tp, FN=fn, FP=fp, TN=tn, unknown=sum(v for k, v in c.items() if k.endswith('unknown')),
                                     recall=tp/(tp+fn) if tp+fn else None, control_positive_rate=fp/(fp+tn) if fp+tn else None,
                                     precision=tp/(tp+fp) if tp+fp else None, benign_FP=bfp, benign_TN=btn,
                                     benign_positive_rate=bfp/(bfp+btn) if bfp+btn else None))
            d = delays[arm]
            summary[arm] = dict(seeds=per_seed,
                recall_mean=float(np.mean([s['recall'] for s in per_seed if s['recall'] is not None])),
                control_positive_rate_mean=float(np.mean([s['control_positive_rate'] for s in per_seed if s['control_positive_rate'] is not None])),
                benign_positive_rate_mean=(float(np.mean([s['benign_positive_rate'] for s in per_seed]))
                                           if all(s['benign_positive_rate'] is not None for s in per_seed) else None),
                delay_p50=float(np.percentile(d, 50)) if d else None, delay_p95=float(np.percentile(d, 95)) if d else None)
        report[f'a{scale:g}'] = summary
    output.mkdir(parents=True, exist_ok=False)
    with (output/'windows.jsonl').open('w') as stream:
        for (tag, trial_id), windows in scored.items():
            stream.write(json.dumps(dict(tag=tag, trial_id=trial_id, windows=windows)) + '\n')
    result = dict(schema='pulse-r4-arm-attack-replay-v1', study=str(study), campaigns=[str(c) for c in campaigns],
                  workers_root=str(workers_root) if workers_root else None,
                  trials=len(trials), scored_tag_trials=len(scored), alpha_scales=list(alpha_scales),
                  evidence_class='development: R3/R5 scenarios were exposed while building the Pulse candidate, '
                                 'never used to fit or tune R4 arms; not the protocol v2 fresh blind set',
                  delay_definition='first positive window_end - kernel_event_at (lower bound on kernel->alert)',
                  arms=report, source_sha256=sha256_file(Path(__file__)), finished_at_unix=time.time())
    atomic_json(output/'RESULTS.json', result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--study', type=Path, required=True)
    parser.add_argument('--campaign', type=Path, action='append', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--alpha-scale', type=float, action='append')
    parser.add_argument('--workers-root', type=Path, help='capture worker root (default: the R4 registration)')
    args = parser.parse_args()
    result = replay(args.study.resolve(), args.campaign, args.output, tuple(args.alpha_scale or (1.0,)), args.workers_root)
    print(json.dumps({k: v for k, v in result.items() if k != 'arms'}))
    for arm, s in sorted(result['arms'][f"a{(args.alpha_scale or [1.0])[0]:g}"].items()):
        print(arm, round(s['recall_mean'], 3), round(s['control_positive_rate_mean'], 3), s['delay_p95'])


if __name__ == '__main__':
    main()
