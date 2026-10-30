"""Leave-one-out syscall ablation (protocol syscall-ablation-loo-v1 + amendment 1): fit every arm of
``matched_study.loo_arm_specs`` on the syscall-arms selection data, reusing that study's per-workload rows,
capped sample indices and fit settings, so the syscall-study tools (score_dump, arm_attack_replay, arm_budget,
arm_bootstrap) score it unchanged. Seeds come from the config (stage 1: one seed; stage 2: three).

    python3 -m sentinel_pulse.syscall_study.loo_study --config CONFIG.json
CONFIG: {"source_study": ".../syscall-matched-study", "study_output": DIR, "seeds": [73021], "arms": [optional subset]}

Parallel fit: ``--shard K/N`` fits only the workloads whose sorted position is K modulo N, with its own status
file; ``--merge N`` then writes the combined STATUS/TERMINAL that the scoring tools read.
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
from .matched_study import contexts, loo_arm_specs


def fit(config_path: Path, shard=None):
    from ..detector.extended_reference_experiment import PulseExtendedReferenceTree
    from ..detector.support_model import PulseSupportEnsemble
    cfg = json.loads(config_path.read_text())
    source = Path(cfg['source_study']); root = Path(cfg['study_output']); root.mkdir(parents=True, exist_ok=True)
    seeds = list(cfg['seeds'])
    arms = loo_arm_specs()
    if cfg.get('arms'):
        arms = {k: v for k, v in arms.items() if k in set(cfg['arms']) | {'base29'}}
    source_index = json.loads((source/'INDEX.json').read_text())
    inputs = json.loads((source/'INPUTS.json').read_text())
    start, end = inputs['selection_start'], inputs['selection_end']
    binding = dict(config_sha256=sha256_file(config_path), source_sha256=sha256_file(Path(__file__)),
                   matched_study_sha256=sha256_file(Path(__file__).with_name('matched_study.py')),
                   source_study=str(source), source_index_sha256=sha256_file(source/'INDEX.json'), seeds=seeds,
                   arms=sorted(arms), train_context_cap=3000, calibration_context_cap=1500, trees=192, tree_alpha=.001,
                   support_budget=.05, attacks_used_for_fit=False, protocol='syscall-ablation-loo-v1 + amendment 1',
                   automatic_promotion=False)
    if (root/'START.json').exists():
        if json.loads((root/'START.json').read_text()) != binding:
            raise ValueError('study binding changed')
    else:
        atomic_json(root/'START.json', binding)
    if (root/'TERMINAL.json').exists():
        return json.loads((root/'TERMINAL.json').read_text())
    if not (root/'INDEX.json').exists():
        atomic_json(root/'INDEX.json', dict(arms=arms, workloads=source_index['workloads'], columns=source_index['columns'],
                                            missing_workloads=source_index.get('missing_workloads', []),
                                            source_study=str(source), selection_start=start, selection_end=end))
    index = json.loads((root/'INDEX.json').read_text())
    status_path = root/('STATUS.json' if shard is None else f'STATUS-shard-{shard[0]}-of-{shard[1]}.json')
    existing = json.loads(status_path.read_text()) if status_path.exists() else {}
    state = dict(state='fitting_loo_arms', completed=existing.get('completed', {}), unknown=existing.get('unknown', {}),
                 expected_models=len(index['workloads'])*len(arms)*len(seeds), index_sha256=sha256_file(root/'INDEX.json'))
    for position, (key, item) in enumerate(sorted(index['workloads'].items())):
        if shard is not None and position % shard[1] != shard[0]:
            continue
        path = Path(item['path'])
        if sha256_file(path) != item['sha256']:
            raise ValueError('workload rows changed: ' + key)
        with path.open() as f:
            rows = [json.loads(line) for line in f]
        rows.sort(key=lambda r: (r['window_end'], str(r['cgroup_id'])))
        for arm, spec in arms.items():
            if all(f'{key}|{arm}|{seed}' in state['completed'] for seed in seeds):
                continue
            parts = contexts(rows, spec, start, end)
            if any(len(parts.get(p, ())) < 1200 for p in ('train', 'calibration')):
                state['unknown'][f'{key}|{arm}'] = {p: len(parts.get(p, ())) for p in ('train', 'calibration')}
                continue
            for p, cap in (('train', 3000), ('calibration', 1500)):      # same indices as syscall-arms
                if len(parts[p]) > cap:
                    parts[p] = parts[p][np.linspace(0, len(parts[p])-1, cap, dtype=int)]
            width = parts['train'].shape[1] // 4
            for seed in seeds:
                tag = f'{key}|{arm}|{seed}'
                if tag in state['completed']:
                    continue
                state.update(current_model=tag, updated_at_unix=time.time()); atomic_json(status_path, state)
                tree = PulseExtendedReferenceTree(history=3, alpha=.001, random_state=seed)
                fit_report = tree.fit_sequences({p: [c.reshape(4, width) for c in parts[p]] for p in ('train', 'calibration')})
                model = PulseSupportEnsemble(tree)
                support = model.fit_support(parts['train'][:, -width:], parts['calibration'][:, -width:])
                name = hashlib.sha256(tag.encode()).hexdigest() + '.pkl'; temporary = root/(name + '.partial')
                with temporary.open('wb') as f:
                    pickle.dump(model, f, pickle.HIGHEST_PROTOCOL)
                temporary.replace(root/name)
                state['completed'][tag] = dict(artifact=name, sha256=sha256_file(root/name), fit=fit_report, support=support,
                                               arm=spec, feature_dim=width, workload=key, seed=seed)
                atomic_json(status_path, state)
    if shard is not None:
        state.update(state='completed_shard', finished_at_unix=time.time(), completed_models=len(state['completed']))
        atomic_json(status_path, state)
        return state
    return finish(root, state)


def finish(root: Path, state):
    state.update(state='completed_loo_arms' if len(state['completed']) == state['expected_models']
                 else 'completed_loo_arms_with_coverage_gaps', finished_at_unix=time.time(),
                 completed_models=len(state['completed']), automatic_promotion=False)
    atomic_json(root/'STATUS.json', state); atomic_json(root/'TERMINAL.json', state)
    return state


def merge(config_path: Path, shards: int):
    cfg = json.loads(config_path.read_text()); root = Path(cfg['study_output'])
    parts = [json.loads((root/f'STATUS-shard-{k}-of-{shards}.json').read_text()) for k in range(shards)]
    if any(p.get('state') != 'completed_shard' for p in parts):
        raise ValueError('a shard has not finished')
    index = json.loads((root/'INDEX.json').read_text())
    state = dict(state='merging', completed={}, unknown={}, expected_models=parts[0]['expected_models'],
                 index_sha256=sha256_file(root/'INDEX.json'), shards=shards, arms=len(index['arms']))
    for p in parts:
        state['completed'].update(p['completed']); state['unknown'].update(p['unknown'])
    return finish(root, state)


if __name__ == '__main__':
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--config', type=Path, required=True)
    ap.add_argument('--shard', help='K/N')
    ap.add_argument('--merge', type=int, help='N: combine the N shard status files')
    a = ap.parse_args()
    if a.merge:
        out = merge(a.config, a.merge)
    else:
        out = fit(a.config, tuple(int(x) for x in a.shard.split('/')) if a.shard else None)
    print(json.dumps({k: v for k, v in out.items() if k != 'completed'}, indent=1))
