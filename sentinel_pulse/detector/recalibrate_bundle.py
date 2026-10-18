"""Write a new candidate bundle whose conformal calibration uses recent normal.

Fitted estimators and support boundaries are copied unchanged; only the two
calibration score arrays per workload are replaced by the frozen model's own
scores on a registered recent-normal span (from ``confirmation_study
calibrate``). The new manifest records the source manifest, the calibration
file and its span, so the result is a distinct, hash-pinned candidate.
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
from .idle_candidate import IdleCandidateScorer


def recalibrate(source: Path, source_hash: str, calibration: Path, output: Path, name: str):
    scorer = IdleCandidateScorer(source, source_hash)  # verifies every artifact
    data = np.load(calibration, allow_pickle=False)
    meta = json.loads(str(data['metadata']))
    if meta.get('model_hash') != source_hash:
        raise ValueError('calibration scores were not produced by this candidate')
    output.mkdir(parents=True, exist_ok=False)
    manifest = json.loads((source/'CANDIDATE_MANIFEST.json').read_text())
    workloads = {}
    for key, entry in manifest['workloads'].items():
        tree = data[f"tree::{key}"] if f"tree::{key}" in data.files else None
        support = data[f"support::{key}"] if f"support::{key}" in data.files else None
        model = scorer.models[key]
        minimum = model.minimum_calibration_examples_per_branch
        if tree is None or support is None or min(len(tree), len(support)) < minimum:
            raise ValueError(f'too few recalibration examples for {key}')
        model.base.calibration_scores = np.sort(np.asarray(tree, dtype=np.float64))
        model.support_calibration = np.sort(np.asarray(support, dtype=np.float64))
        blob = pickle.dumps(model, protocol=pickle.HIGHEST_PROTOCOL)
        digest = hashlib.sha256(blob).hexdigest()
        artifact = f'model-{digest}.pkl'
        (output/artifact).write_bytes(blob)
        workloads[key] = dict(entry, artifact=artifact, artifact_sha256=digest,
                              tree_calibration_examples=len(tree), support_calibration_examples=len(support),
                              original_artifact_sha256=entry['artifact_sha256'])
    manifest.update(candidate_name=name, workloads=workloads, created_at_unix=time.time(),
                    excluded_degenerate_workloads={}, excluded_degenerate_workload_count=0,
                    recalibration=dict(source_manifest_sha256=source_hash,
                        calibration_sha256=sha256_file(calibration), calibration_span_unix=[meta['since_unix'], meta['until_unix']],
                        excluded_spans=meta.get('excluded_spans', []), attack_data_used=False,
                        estimators_changed=False, generator_sha256=sha256_file(Path(__file__))))
    atomic_json(output/'CANDIDATE_MANIFEST.json', manifest)
    new_hash = sha256_file(output/'CANDIDATE_MANIFEST.json')
    IdleCandidateScorer(output, new_hash)  # the result must load under the normal checks
    return new_hash


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--candidate', type=Path, required=True)
    parser.add_argument('--candidate-hash', required=True)
    parser.add_argument('--calibration', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--name', required=True)
    args = parser.parse_args()
    print(recalibrate(args.candidate, args.candidate_hash, args.calibration, args.output, args.name))


if __name__ == '__main__':
    main()
