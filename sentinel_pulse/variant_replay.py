"""Verify C2 scoring against sealed predictions; resumable, model read-only.

This replay measures serialization/inference consistency on already inspected
normal contexts. It does not produce independent detection quality or live
kernel-to-alert latency.
"""
from __future__ import annotations

import argparse
import gc
import importlib.metadata
import json
from pathlib import Path
import pickle
import platform
import time
import warnings

import numpy as np
from sklearn.exceptions import InconsistentVersionWarning

from .derive_variant_manifest import _safe_model_path
from .integrity import sha256_file, verify_sha256
from .syscall_histogram_pilot import atomic_json


def check_chain(root, expected_hash):
    path = root / 'VARIANT_MODEL_MANIFEST.derived.json'
    verify_sha256(path, expected_hash)
    manifest = json.loads(path.read_text())
    if manifest.get('schema') != 'sentinel-pulse-syscall-variant-models-v1' or not manifest.get('derived_manifest'):
        raise ValueError('verified derived model manifest required')
    chain = manifest['derivation']
    for name, key in [('START.json', 'start_sha256'), ('RESULTS.json', 'results_sha256'),
                      ('TERMINAL.json', 'terminal_sha256'), ('VARIANT_MODEL_MANIFEST.json', 'source_manifest_sha256')]:
        verify_sha256(root / name, chain[key])
    start = json.loads((root / 'START.json').read_text())
    terminal = json.loads((root / 'TERMINAL.json').read_text())
    results = json.loads((root / 'RESULTS.json').read_text())
    if terminal['state'] != 'completed' or terminal.get('errors'):
        raise ValueError('clean terminal required')
    if results['start_sha256'] != chain['start_sha256'] or manifest['start_sha256'] != chain['start_sha256']:
        raise ValueError('START binding mismatch')
    if set(manifest['workloads']) != set(results['workloads']):
        raise ValueError('model/results workload coverage mismatch')
    actual = {'python': platform.python_version(), **{
        name: importlib.metadata.version(name) for name in ('numpy', 'scikit-learn', 'joblib')}}
    for name, version in actual.items():
        if start['software'].get(name.replace('-', '_')) != version:
            raise ValueError('software differs from C2: ' + name)
    return manifest, start, results, actual


def apply_mask(contexts, indices, feature_dim, history):
    values = np.asarray(contexts, dtype=np.float32)
    if values.ndim != 2 or values.shape[1] != feature_dim * (history + 1) or not np.isfinite(values).all():
        raise ValueError('invalid temporal contexts')
    if any(type(i) is not int or not 0 <= i < feature_dim for i in indices):
        raise ValueError('invalid feature mask')
    values = values.copy()
    values[:, [i + lag * feature_dim for lag in range(history + 1) for i in indices]] = 0
    return values


def predict(model, contexts):
    scores = model.estimator.predict_proba(contexts)[:, 1]
    calibration = model.calibration_scores
    if calibration is None or not len(calibration) or np.any(np.diff(calibration) < 0):
        raise ValueError('sorted normal calibration required')
    p = (len(calibration) - np.searchsorted(calibration, scores, side='left') + 1) / (len(calibration) + 1)
    return scores, p, p <= model.alpha


def run(root, inputs, output, expected_hash):
    manifest, start, results, software = check_chain(root, expected_hash)
    input_analysis = json.loads((inputs / 'analysis.json').read_text())
    verify_sha256(inputs / 'manifest.json', manifest['training_manifest_sha256'])
    columns = json.loads((inputs / 'manifest.json').read_text())['feature_columns']
    if len(columns) != manifest['feature_dim'] or len(set(columns)) != len(columns):
        raise ValueError('invalid sealed feature columns')
    lookup = {name: i for i, name in enumerate(columns)}
    context_path = inputs / 'contexts.npz'
    verify_sha256(context_path, input_analysis['context_archive']['sha256'])
    # Same already inspected context archive used by the registered C2 fit.
    verify_sha256(inputs / 'analysis.json', start['input_sha256']['analysis.json'])
    output.mkdir(parents=True, exist_ok=True)
    binding = dict(model_manifest_sha256=expected_hash, contexts_sha256=sha256_file(context_path),
                   source_sha256=sha256_file(Path(__file__)), software=software)
    state_path = output / 'STATUS.json'
    if state_path.exists():
        state = json.loads(state_path.read_text())
        if state['binding'] != binding:
            raise ValueError('resume input/code/software binding changed')
    else:
        state = dict(binding=binding, verified={}, state='running', started_at_unix=time.time(),
                     evidence_class='consistency_replay_on_inspected_contexts', independent_test=False,
                     precision=None, recall=None, kernel_to_alert=None)
        atomic_json(output / 'START.json', state)
    with np.load(context_path, allow_pickle=False) as archive:
        if set(archive.files) != set(manifest['workloads']):
            raise ValueError('context workload coverage differs')
        for workload, variants in sorted(manifest['workloads'].items()):
            for variant, record in sorted(variants.items()):
                key = workload + '|' + variant
                if key in state['verified']:
                    continue
                model_path = _safe_model_path(root, record['artifact'])
                verify_sha256(model_path, record['sha256'])
                if model_path.stat().st_size != record['bytes']:
                    raise ValueError('model size mismatch')
                result = results['workloads'][workload]['variants'][variant]
                if record['masked_columns'] != result['masked_columns']:
                    raise ValueError('sealed mask mismatch')
                prediction_path = root / result['prediction_artifact']
                if prediction_path.resolve().parent != root.resolve():
                    raise ValueError('invalid prediction artifact path')
                verify_sha256(prediction_path, result['prediction_sha256'])
                with warnings.catch_warnings():
                    warnings.simplefilter('error', InconsistentVersionWarning)
                    with model_path.open('rb') as stream:
                        model = pickle.load(stream)
                if (model.feature_dim != manifest['feature_dim'] or model.history != manifest['history']
                        or model.alpha != manifest['alpha']):
                    raise ValueError('model temporal/threshold contract mismatch')
                try:
                    indices = [lookup[name] for name in record['masked_columns']]
                except KeyError as exc:
                    raise ValueError('masked column absent from sealed schema') from exc
                contexts = apply_mask(archive[workload], indices, model.feature_dim, model.history)
                before = time.perf_counter()
                score, p, anomalous = predict(model, contexts)
                batch_ms = (time.perf_counter() - before) * 1000
                with np.load(prediction_path, allow_pickle=False) as saved:
                    maximum_error = float(np.max(np.abs(score - saved['score'])))
                    if not (np.allclose(score, saved['score'], rtol=0, atol=1e-12) and np.array_equal(p, saved['conformal_p'])
                            and np.array_equal(anomalous, saved['anomalous'])):
                        raise ValueError('replay predictions differ from sealed C2 output: ' + key)
                state['verified'][key] = dict(contexts=len(contexts), prediction_sha256=result['prediction_sha256'],
                    batch_inference_ms=batch_ms, score_absolute_tolerance=1e-12,
                    maximum_score_error=maximum_error, exact_p_match=True, exact_decision_match=True)
                state.update(updated_at_unix=time.time(), completed_models=len(state['verified']))
                atomic_json(state_path, state)
                del model, contexts, score, p, anomalous
                gc.collect()
    state.update(state='completed_consistency_replay', finished_at_unix=time.time())
    atomic_json(state_path, state)
    atomic_json(output / 'TERMINAL.json', state)
    return state


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('root', 'inputs', 'output'):
        p.add_argument('--' + name, required=True, type=Path)
    p.add_argument('--manifest-sha256', required=True)
    a = p.parse_args()
    run(a.root, a.inputs, a.output, a.manifest_sha256)


if __name__ == '__main__':
    main()
