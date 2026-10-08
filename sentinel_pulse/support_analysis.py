"""Read-only matched-budget ablation of a completed normal support experiment."""
from __future__ import annotations
import argparse
from collections import Counter
import json
from pathlib import Path
import pickle
import numpy as np

from .integrity import contained_artifact, sha256_file
from .run_500ms_blind_matrix import atomic_json


def analyze(root, analysis, model, output):
    start = json.loads((root/'START.json').read_text())
    result = json.loads((root/'RESULTS.json').read_text())
    terminal = json.loads((root/'TERMINAL.json').read_text())
    heldout = json.loads(analysis.read_text())
    archive = Path(heldout['context_archive']['path'])
    if (terminal['state'] != 'completed'
            or result['start_sha256'] != sha256_file(root/'START.json')
            or start['analysis_sha256'] != sha256_file(analysis)
            or start['context_archive_sha256'] != sha256_file(archive)
            or start['base_manifest_sha256'] != sha256_file(model/'manifest.json')):
        raise ValueError('completed normal experiment binding differs')
    columns = json.loads((model/'manifest.json').read_text())['feature_columns']
    workloads, totals = {}, Counter()
    with np.load(archive, allow_pickle=False) as data:
        for key, row in result['workloads'].items():
            path = contained_artifact(root, row['artifact'])
            if sha256_file(path) != row['artifact_sha256']:
                raise ValueError('support artifact checksum differs')
            if key not in data.files:
                workloads[key] = {'holdout_status': 'missing; not zero FP'}
                continue
            with path.open('rb') as stream:
                ensemble = pickle.load(stream)
            scored = ensemble.predict_contexts(data[key])
            tree = scored['tree_p'] <= ensemble.alpha/2
            support = scored['support_p'] <= ensemble.alpha/2
            if not np.array_equal(scored['anomalous'], tree | support):
                raise ValueError('joint decision differs from corrected branch union')
            counts = dict(normal_contexts=len(tree), tree_original_alpha=int(np.sum(scored['tree_p'] <= ensemble.base.alpha)),
                          tree_matched_branch_budget=int(np.sum(tree)), support_branch=int(np.sum(support)),
                          support_only=int(np.sum(support & ~tree)), combined=int(np.sum(tree | support)))
            # Explain normal anomalies, not rank features for training selection.
            x = data[key][:,-ensemble.base.feature_dim:]
            excess = np.maximum(np.maximum(ensemble.low-x, x-ensemble.high),0)/ensemble.scale
            contributing = Counter(columns[i] for i in np.argmax(excess[support],axis=1))
            workloads[key] = dict(counts, support_normal_anomaly_argmax_counts=dict(contributing),
                                  matched_per_branch_alpha=ensemble.alpha/2)
            totals.update(counts)
    report = dict(schema='pulse-support-matched-normal-analysis-v1',
                  evidence_class='exploratory_previously_inspected_normal_holdout',
                  start_sha256=sha256_file(root/'START.json'), results_sha256=sha256_file(root/'RESULTS.json'),
                  terminal_sha256=sha256_file(root/'TERMINAL.json'), workloads=workloads, totals=dict(totals),
                  confusion_matrix=None, precision=None, recall=None, policy_evaluated=False,
                  thresholds_selected_from_this_report=False, automatic_promotion=False)
    atomic_json(output,report)
    return report


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('root','analysis','model','output'):p.add_argument('--'+name,type=Path,required=True)
    args=p.parse_args();analyze(args.root,args.analysis,args.model,args.output)


if __name__=='__main__':main()
