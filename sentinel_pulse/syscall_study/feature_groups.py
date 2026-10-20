"""Feature-group study: evidence for every part of Pulse's feature vector, not only the 29 syscalls.

The syscall study (syscall-arms) varied only the explicit syscall channels; every arm kept the
hashed syscall bins, hashed transition bins, aggregates, rolling statistics and the three-window
history. This study removes one part at a time with everything else held equal:

- same normal selection data, train/calibration split and capped sample indices as syscall-arms
  (contexts are cut from the syscall-arms ``base29`` contexts, so every arm sees the same windows);
- same model (ExtraTrees reference tree + support branch, conformal p-values), same three seeds;
- the reference arm is called ``base29`` = the full Pulse vector, so the downstream syscall-study
  tools (score dump, attack replay, arm_budget, arm_bootstrap) work unchanged.

Layout of the 249-column vector (``collector/features.py``):
  0-28 log-count of the 29 syscalls · 29-57 their ratio of all calls · 58-62 aggregates
  (log/ratio of other calls, log total, sensitive ratio, seccomp denials) · 63-126 hashed syscall-ID
  bins · 127-190 hashed transition (syscall pair) bins · 191-219 rolling-10 mean · 220-248 rolling-10 std.
A context is the current vector plus the previous three (996 values); ``history`` arms keep one or two.
The tree branch learns history -> current consistency and needs at least one previous window; the
support branch sees only the current vector, so "no history at all" is the support-only p-value.

Evaluation-time variants of the p-value (tree branch only / support branch only) need no refit and
are handled by ``arm_budget --pvalue``.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import pickle
import time

import numpy as np

from ..common import atomic_json
from ..integrity import sha256_file

WIDTH = 249
HISTORY = 3
GROUPS = {
    'log_counts': range(0, 29),
    'ratios': range(29, 58),
    'aggregates': range(58, 63),
    'syscall_bins': range(63, 127),
    'transition_bins': range(127, 191),
    'rolling': range(191, 249),
}
SEEDS = (73021, 73022, 73023)


def _keep(*dropped):
    gone = {i for g in dropped for i in GROUPS[g]}
    return [i for i in range(WIDTH) if i not in gone]


def feature_arms():
    """Arm name -> spec. ``add``/``drop`` stay empty (no syscall change); ``columns`` are the kept
    columns of the 249 vector; ``history`` is the number of previous vectors in the context."""
    def arm(columns=None, history=HISTORY):
        return dict(add=[], drop=[], columns=list(range(WIDTH)) if columns is None else columns, history=history)
    arms = {'base29': arm()}
    for group in GROUPS:
        arms[f'drop_{group}'] = arm(_keep(group))
    arms['drop_all_bins'] = arm(_keep('syscall_bins', 'transition_bins'))
    arms['bins_only'] = arm(_keep('log_counts', 'ratios', 'rolling'))
    # the reference tree models history -> current consistency, so it needs >= 1 previous window;
    # "no history" is the support branch alone (``arm_budget --pvalue support``)
    arms['history1'] = arm(history=1)
    arms['history2'] = arm(history=2)
    return arms


def transform(contexts, spec):
    """Cut full 4 x 249 contexts down to an arm: last ``history``+1 vectors, kept columns only."""
    contexts = np.asarray(contexts)
    columns = spec.get('columns'); history = spec.get('history', HISTORY)
    if columns is None and history == HISTORY:
        return contexts
    single = contexts.ndim == 1
    blocks = contexts.reshape(1 if single else len(contexts), HISTORY + 1, WIDTH)[:, HISTORY - history:, :]
    if columns is not None:
        blocks = blocks[:, :, columns]
    out = blocks.reshape(len(blocks), -1)
    return out[0] if single else out


def fit(config_path: Path):
    """Fit every feature arm x workload x seed on the syscall-arms selection data."""
    from ..detector.extended_reference_experiment import PulseExtendedReferenceTree
    from ..detector.support_model import PulseSupportEnsemble
    from .matched_study import contexts as base_contexts

    cfg = json.loads(config_path.read_text())
    source = Path(cfg['source_study']); root = Path(cfg['study_output']); root.mkdir(parents=True, exist_ok=True)
    source_index = json.loads((source/'INDEX.json').read_text())
    inputs = json.loads((source/'INPUTS.json').read_text())
    start, end = inputs['selection_start'], inputs['selection_end']
    arms = feature_arms()
    binding = dict(config_sha256=sha256_file(config_path), source_sha256=sha256_file(Path(__file__)),
                   source_study=str(source), source_index_sha256=sha256_file(source/'INDEX.json'),
                   seeds=list(SEEDS), train_context_cap=3000, calibration_context_cap=1500,
                   sample_rule='syscall-arms base29 contexts and capped indices, cut per arm',
                   trees=192, tree_alpha=.001, support_budget=.05, attacks_used_for_fit=False,
                   normal_labels='expected_normal_unadjudicated', purpose='feature-group evidence for Pulse',
                   automatic_promotion=False)
    if (root/'START.json').exists():
        if json.loads((root/'START.json').read_text()) != binding:
            raise ValueError('study binding changed')
    else:
        atomic_json(root/'START.json', binding)
    if (root/'TERMINAL.json').exists():
        return json.loads((root/'TERMINAL.json').read_text())
    index = dict(arms=arms, workloads=source_index['workloads'], columns=source_index['columns'],
                 missing_workloads=source_index.get('missing_workloads', []), groups={k: [v.start, v.stop] for k, v in GROUPS.items()},
                 source_study=str(source), selection_start=start, selection_end=end)
    if not (root/'INDEX.json').exists():
        atomic_json(root/'INDEX.json', index)
    index = json.loads((root/'INDEX.json').read_text())
    status_path = root/'STATUS.json'
    existing = json.loads(status_path.read_text()) if status_path.exists() else {}
    state = dict(state='fitting_feature_arms', completed=existing.get('completed', {}), unknown=existing.get('unknown', {}),
                 expected_models=len(index['workloads'])*len(arms)*len(SEEDS), index_sha256=sha256_file(root/'INDEX.json'))
    base_spec = dict(add=[], drop=[])
    for key, item in sorted(index['workloads'].items()):
        path = Path(cfg.get('workload_dir', '')) / Path(item['path']).name if cfg.get('workload_dir') else Path(item['path'])
        if sha256_file(path) != item['sha256']:
            raise ValueError('workload rows changed: ' + key)
        with path.open() as f:
            rows = [json.loads(line) for line in f]
        rows.sort(key=lambda r: (r['window_end'], str(r['cgroup_id'])))
        parts = base_contexts(rows, base_spec, start, end)
        if any(len(parts.get(p, ())) < 1200 for p in ('train', 'calibration')):
            state['unknown'][key] = {p: len(parts.get(p, ())) for p in ('train', 'calibration')}
            continue
        for p, cap in (('train', 3000), ('calibration', 1500)):
            if len(parts[p]) > cap:
                parts[p] = parts[p][np.linspace(0, len(parts[p])-1, cap, dtype=int)]
        for arm, spec in arms.items():
            cut = {p: transform(parts[p], spec) for p in ('train', 'calibration')}
            history = spec['history']; width = cut['train'].shape[1] // (history + 1)
            for seed in SEEDS:
                tag = f'{key}|{arm}|{seed}'
                if tag in state['completed']:
                    continue
                state.update(current_model=tag, updated_at_unix=time.time()); atomic_json(status_path, state)
                tree = PulseExtendedReferenceTree(history=history, alpha=.001, random_state=seed)
                fit_report = tree.fit_sequences({p: [c.reshape(history + 1, width) for c in cut[p]] for p in cut})
                model = PulseSupportEnsemble(tree)
                support = model.fit_support(cut['train'][:, -width:], cut['calibration'][:, -width:])
                name = hashlib.sha256(tag.encode()).hexdigest() + '.pkl'; temporary = root/(name + '.partial')
                with temporary.open('wb') as f:
                    pickle.dump(model, f, pickle.HIGHEST_PROTOCOL)
                temporary.replace(root/name)
                state['completed'][tag] = dict(artifact=name, sha256=sha256_file(root/name), fit=fit_report, support=support,
                                               arm=spec, feature_dim=width, workload=key, seed=seed)
                atomic_json(status_path, state)
    state.update(state='completed_feature_arms' if len(state['completed']) == state['expected_models']
                 else 'completed_feature_arms_with_coverage_gaps', finished_at_unix=time.time(),
                 completed_models=len(state['completed']), automatic_promotion=False)
    atomic_json(status_path, state); atomic_json(root/'TERMINAL.json', state)
    return state


def compare_reference(study: Path, source: Path, workload_dir: Path | None = None, limit=300):
    """base29 here must reproduce syscall-arms base29: same data, sample indices and seeds.
    Predicts the first ``limit`` calibration contexts of every workload with both models."""
    from ..common import load_artifact
    from .matched_study import contexts as base_contexts
    index = json.loads((study/'INDEX.json').read_text())
    mine = json.loads((study/'TERMINAL.json').read_text())['completed']
    theirs = json.loads((source/'TERMINAL.json').read_text())['completed']
    report = {}
    for key, item in sorted(index['workloads'].items()):
        tag = f'{key}|base29|{SEEDS[0]}'
        if tag not in mine or tag not in theirs:
            report[key] = 'missing'; continue
        path = workload_dir/Path(item['path']).name if workload_dir else Path(item['path'])
        with path.open() as f:
            rows = sorted((json.loads(line) for line in f), key=lambda r: (r['window_end'], str(r['cgroup_id'])))
        cal = base_contexts(rows, dict(add=[], drop=[]), index['selection_start'], index['selection_end'])['calibration'][:limit]
        preds, models = [], []
        for root, entry in ((study, mine[tag]), (source, theirs[tag])):
            with (root/entry['artifact']).open('rb') as f:
                model = load_artifact(f)
            model.base.estimator.n_jobs = 1
            models.append(model); preds.append(model.predict_contexts(cal))
        cal_diff = float(np.abs(np.sort(models[0].base.calibration_scores) - np.sort(models[1].base.calibration_scores)).max())
        report[key] = dict(
            scores_identical=all(np.array_equal(preds[0][k], preds[1][k]) for k in ('tree_score', 'support_score')),
            support_calibration_identical=bool(np.array_equal(models[0].support_calibration, models[1].support_calibration)),
            tree_calibration_max_abs_diff=cal_diff,
            # calibration contexts score exactly at calibration values, so a 1e-16 difference can move a tie by one rank
            tree_p_rank_ties_moved=int((preds[0]['tree_p'] != preds[1]['tree_p']).sum()),
            anomalous_flags_identical=bool(np.array_equal(preds[0]['anomalous'], preds[1]['anomalous'])))
    ok = lambda v: isinstance(v, dict) and v['scores_identical'] and v['support_calibration_identical'] and v['tree_calibration_max_abs_diff'] <= 1e-12
    result = dict(schema='feature-groups-reference-check-v2', windows_per_workload=limit, workloads=report,
                  criterion='tree and support scores bit-identical, support calibration identical, tree calibration '
                            'scores within 1e-12 (fit-time scores are summed in parallel; order changes the last bit)',
                  reproduces_syscall_arms_base29=all(ok(v) for v in report.values()),
                  max_tree_calibration_abs_diff=max((v['tree_calibration_max_abs_diff'] for v in report.values() if isinstance(v, dict)), default=None),
                  checked_at_unix=time.time())
    atomic_json(study/'REFERENCE_CHECK.json', result)
    return result


def register_holdout(study: Path, source: Path):
    """Write the audit + holdout registration that ``score_dump.load_study`` requires, reusing the
    syscall-arms holdout span (normal capture after selection, never used for fitting)."""
    terminal = study/'TERMINAL.json'
    audit = dict(schema='feature-groups-fit-audit-v1', binding=dict(index_sha256=sha256_file(study/'INDEX.json')),
                 models={tag: item['sha256'] for tag, item in json.loads(terminal.read_text())['completed'].items()},
                 audited_at_unix=time.time())
    atomic_json(study/'R4_FIT_AUDIT.json', audit)
    registration = json.loads((source/'NORMAL_HOLDOUT_START.json').read_text())
    registration.update(fit_audit_sha256=sha256_file(study/'R4_FIT_AUDIT.json'), r4_terminal_sha256=sha256_file(terminal),
                        schema='feature-groups-normal-holdout-v1', source_registration_sha256=sha256_file(source/'NORMAL_HOLDOUT_START.json'),
                        note='holdout span of syscall-arms reused; fitted on the same selection data')
    atomic_json(study/'NORMAL_HOLDOUT_START.json', registration)
    return registration


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest='command', required=True)
    f = sub.add_parser('fit'); f.add_argument('--config', type=Path, required=True)
    r = sub.add_parser('register'); r.add_argument('--study', type=Path, required=True); r.add_argument('--source', type=Path, required=True)
    c = sub.add_parser('check'); c.add_argument('--study', type=Path, required=True); c.add_argument('--source', type=Path, required=True)
    c.add_argument('--workload-dir', type=Path)
    sub.add_parser('arms')
    args = parser.parse_args()
    if args.command == 'fit':
        print(json.dumps({k: v for k, v in fit(args.config).items() if k != 'completed'}))
    elif args.command == 'register':
        print(json.dumps(register_holdout(args.study, args.source))[:400])
    elif args.command == 'check':
        print(json.dumps({k: v for k, v in compare_reference(args.study, args.source, args.workload_dir).items() if k != 'workloads'}))
    else:
        print(json.dumps({k: dict(columns=len(v['columns']), history=v['history']) for k, v in feature_arms().items()}, indent=1))


if __name__ == '__main__':
    main()
