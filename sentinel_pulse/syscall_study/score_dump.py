"""Keep every syscall-arms arm score on the sealed normal holdout for offline analysis.

The registered holdout evaluator kept only positive windows, so arms cannot
be compared under recalibrated p-values or other decision policies. This
re-scores the same sealed segments with the same frozen models and writes,
per segment, every window's tree/support score for every arm/seed model.
Per-segment counts must reproduce the registered evaluation exactly.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
import json
from pathlib import Path
import time

import numpy as np

from ..common import atomic_json
from ..integrity import sha256_file
from .matched_holdout import bounds, score_segment, study_seeds

IDENTITY = ('node_name', 'pod_uid', 'container_name', 'workload_revision', 'cgroup_id')


def load_study(study: Path):
    registration_path = study/'NORMAL_HOLDOUT_START.json'
    registration = json.loads(registration_path.read_text())
    audit_path = study/'R4_FIT_AUDIT.json'
    audit = json.loads(audit_path.read_text())
    if sha256_file(audit_path) != registration['fit_audit_sha256']:
        raise ValueError('fit audit changed since holdout registration')
    if sha256_file(study/'TERMINAL.json') != registration['r4_terminal_sha256']:
        raise ValueError('syscall-arms terminal changed since holdout registration')
    if sha256_file(study/'INDEX.json') != audit['binding']['index_sha256']:
        raise ValueError('syscall-arms arm index changed')
    terminal = json.loads((study/'TERMINAL.json').read_text())
    index = json.loads((study/'INDEX.json').read_text())
    registration = dict(registration, seeds=study_seeds(study), episode_quiet_seconds=15.)
    return registration, index, terminal


class ScoreCollector:
    def __init__(self):
        self.identities = {}
        self.data = defaultdict(lambda: defaultdict(list))

    def __call__(self, tag, rows, predictions):
        d = self.data[tag]
        for row in rows:
            key = json.dumps([row['workload_key'], *[str(row[k]) for k in IDENTITY]])
            d['identity'].append(self.identities.setdefault(key, len(self.identities)))
            d['window_end'].append(float(row['window_end']))
        d['tree_score'].extend(np.asarray(predictions['tree_score']).tolist())
        d['support_score'].extend(np.asarray(predictions['support_score']).tolist())

    def save(self, path: Path):
        arrays = {}
        for tag, d in self.data.items():
            for name, values in d.items():
                dtype = {'identity': np.int32, 'window_end': np.float64}.get(name, np.float32)
                arrays[f'{tag}::{name}'] = np.asarray(values, dtype=dtype)
        identities = [json.loads(k) for k, _ in sorted(self.identities.items(), key=lambda kv: kv[1])]
        partial = path.with_suffix('.partial.npz')
        with partial.open('wb') as stream:
            np.savez_compressed(stream, identities=np.array(json.dumps(identities)), **arrays)
        partial.replace(path)


def dump_node(study: Path, node: str, output: Path, compare_root: Path | None = None):
    registration, index, terminal = load_study(study)
    worker = registration['workers'][node]
    output.mkdir(parents=True, exist_ok=True)
    begin, finish = registration['holdout_start_unix'], registration['planned_end_unix']
    done, mismatches = [], []
    for seal in sorted(Path(worker['output']).glob('segments/s*/TERMINAL.json')):
        segment = seal.parent
        first, last = bounds(segment/'features.jsonl')
        if first is None or last <= begin or first >= finish:
            continue
        dest = output/segment.name
        if (dest/'scores.npz').exists():
            done.append(segment.name)
            continue
        if dest.exists():
            raise ValueError(f'incomplete segment output {dest}; inspect before resuming')
        collector = ScoreCollector()
        result = score_segment(segment, node, registration, index, terminal, study, dest/'evaluation',
                               score_sink=collector)
        if compare_root is not None:
            original = json.loads((compare_root/node/segment.name/'RESULTS.json').read_text())
            if original['model_counts'] != result['model_counts'] or original['counts'] != result['counts']:
                mismatches.append(segment.name)
        collector.save(dest/'scores.npz')
        done.append(segment.name)
        atomic_json(output/'STATUS.json', dict(state='dumping', node=node, completed=len(done),
                                               last=segment.name, mismatched_segments=mismatches,
                                               updated_at_unix=time.time()))
    report = dict(schema='pulse-r4-holdout-score-dump-v1', node=node, study=str(study),
                  completed_segments=done, mismatched_segments=mismatches,
                  reproduces_registered_counts=None if compare_root is None else not mismatches,
                  source_sha256=sha256_file(Path(__file__)), finished_at_unix=time.time())
    atomic_json(output/'TERMINAL.json', report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--study', type=Path, required=True)
    parser.add_argument('--node', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--compare-evaluation', type=Path,
                        help='segments/ dir of the registered holdout evaluation, to check counts')
    args = parser.parse_args()
    report = dump_node(args.study.resolve(), args.node, args.output.resolve(), args.compare_evaluation)
    print(json.dumps({k: v for k, v in report.items() if k != 'completed_segments'}))


if __name__ == '__main__':
    main()
