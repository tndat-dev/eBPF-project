"""Checkpointed, normal-only exploratory support ensemble; no live promotion."""
from __future__ import annotations

import argparse
import fcntl
import json
import importlib.metadata
import platform
import os
from pathlib import Path
import pickle
import signal
import time

import numpy as np

from .finalize_candidate import verify_model_bundle
from .integrity import contained_artifact, sha256_file
from .model import PulseExtraTrees
from .recovery_worker_probe import clean_source
from .run_500ms_blind_matrix import atomic_json
from .support_model import PulseSupportEnsemble
from .train import load_dataset_manifest, load_sequences


def run(dataset, model_dir, analysis, root):
    manifest, candidates, _ = verify_model_bundle(model_dir)
    provenance_path, provenance = load_dataset_manifest(dataset)
    if provenance['dataset_sha256'] != manifest['dataset_sha256'] or sha256_file(provenance_path) != manifest['dataset_manifest_sha256']:
        raise ValueError('original normal training dataset binding differs')
    heldout = json.loads(analysis.read_text())
    archive = Path(heldout['context_archive']['path'])
    if (not heldout['independent_capture_hash_and_post_training_time']
            or heldout['model_manifest_sha256'] != sha256_file(model_dir / 'manifest.json')
            or heldout['capture_sha256'] == manifest['dataset_sha256']
            or sha256_file(archive) != heldout['context_archive']['sha256']):
        raise ValueError('independent normal exploratory holdout binding differs')
    commit, files = clean_source(Path(__file__).resolve().parents[1])
    software = {'python': platform.python_version(), 'numpy': np.__version__}
    software.update({key: importlib.metadata.version(dist) for key, dist in (
        ('scikit_learn','scikit-learn'), ('scipy','scipy'), ('joblib','joblib'),
        ('threadpoolctl','threadpoolctl'), ('narwhals','narwhals'))})
    if software != manifest['software']:
        raise ValueError('support experiment software differs from frozen reference')
    binding = dict(schema='pulse-support-experiment-start-v1', source_commit=commit, source_files=files,
                   dataset_sha256=manifest['dataset_sha256'], base_manifest_sha256=sha256_file(model_dir / 'manifest.json'),
                   analysis_sha256=sha256_file(analysis), context_archive_sha256=sha256_file(archive),
                   normal_only=True, attack_data_used_for_fit=False, live_deployment=False, automatic_promotion=False,
                   base_model_weights_unchanged=True, calibration_split=.7, interval_fpr_budget=.05,
                   horizon_windows=30, reference_quantiles=[.01,.99], scale_floor=.05,
                   evidence_class='exploratory_previously_inspected_normal_holdout',
                   new_unseen_attack_and_normal_evaluation_required=True)
    binding['software'] = software
    root.mkdir(parents=True, exist_ok=True)
    if (root / 'START.json').exists():
        start = json.loads((root / 'START.json').read_text())
        if any(start.get(k) != v for k,v in binding.items()):
            raise ValueError('support experiment registration drift')
    else:
        start = dict(binding, started_at_unix=time.time())
        atomic_json(root / 'START.json', start); (root / 'START.json').chmod(0o444)
    result_path = root / 'RESULTS.json'
    result = json.loads(result_path.read_text()) if result_path.exists() else dict(
        schema='pulse-support-experiment-results-v1', start_sha256=sha256_file(root / 'START.json'), workloads={})
    if result['start_sha256'] != sha256_file(root / 'START.json'):
        raise ValueError('support checkpoint belongs to another registration')
    for row in result['workloads'].values():
        if sha256_file(root / row['artifact']) != row['artifact_sha256']:
            raise ValueError('support checkpoint artifact drift')
    if (root / 'TERMINAL.json').exists():
        return
    sequences, columns = load_sequences(dataset, manifest['max_contiguous_gap_seconds'])
    if columns != manifest['feature_columns']:
        raise ValueError('support feature schema differs')
    data = np.load(archive, allow_pickle=False)
    for key in candidates:
        if key in result['workloads']:
            continue
        base = PulseExtraTrees.load(contained_artifact(model_dir, manifest['workloads'][key]['artifact']))
        tx, ty, cx, cy, _ = base._split_sequences(sequences[key], .7)
        ensemble = PulseSupportEnsemble(base)
        fit = ensemble.fit_support(ty, cy)
        path = root / (key.replace('/', '__').replace(':', '__') + '.pkl')
        with path.with_suffix('.tmp').open('wb') as stream:
            pickle.dump(ensemble, stream, protocol=pickle.HIGHEST_PROTOCOL)
            stream.flush()
            os.fsync(stream.fileno())
        path.with_suffix('.tmp').replace(path)
        directory_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        row = dict(fit=fit, artifact=path.name, artifact_sha256=sha256_file(path),
                   artifact_schema='exploratory-PulseSupportEnsemble-not-serving-v2',
                   policy_evaluated=False, precision=None, recall=None)
        if key in data.files:
            started = time.perf_counter()
            scores = ensemble.predict_contexts(data[key])
            row.update(normal_contexts=len(scores['anomalous']),
                       tree_anomalies_at_original_alpha=int(np.sum(scores['tree_p'] <= base.alpha)),
                       ensemble_raw_normal_anomalies=int(np.sum(scores['anomalous'])),
                       ensemble_raw_normal_context_rate=float(np.mean(scores['anomalous'])),
                       offline_batch_seconds=time.perf_counter() - started,
                       interval_FPR=None, kernel_to_alert_seconds=None)
        else:
            row['holdout_status'] = 'missing_workload; not treated as zero FP'
        result['workloads'][key] = row
        atomic_json(result_path, result)
        atomic_json(root / 'STATUS.json', dict(state='fitting', completed=len(result['workloads']), expected=len(candidates),
                                              current_workload=key, updated_at_unix=time.time()))
        del tx, ty, cx, cy, base, ensemble
    atomic_json(root / 'TERMINAL.json', dict(state='completed', completed=len(result['workloads']),
                                           finished_at_unix=time.time(), automatic_promotion=False))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('dataset','model','analysis','root'):
        parser.add_argument('--'+name, type=Path, required=True)
    args = parser.parse_args()
    args.root.mkdir(parents=True, exist_ok=True)
    def stop(*_):
        raise KeyboardInterrupt('system stop; checkpoint retained')
    signal.signal(signal.SIGTERM, stop)
    with (args.root / 'campaign.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            run(args.dataset,args.model,args.analysis,args.root)
        except ValueError as exc:
            atomic_json(args.root / 'BLOCKED.json', dict(error=str(exc), automatic_promotion=False))
            raise SystemExit(65) from exc


if __name__ == '__main__':
    main()
