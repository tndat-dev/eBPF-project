"""Export fixed normal contexts and verify frozen scalar/batch equivalence.

This is an engineering timing comparison on already observed data. It reports
neither detection accuracy nor live kernel-to-alert latency.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import fcntl
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import time
import warnings

import numpy as np
from sklearn.exceptions import InconsistentVersionWarning

from .candidate_shadow import CandidateShadowRuntime, is_valid_feature_schema_record
from .idle_batch import DeferredScorer, SCORE_FIELDS, score_batch
from .idle_candidate import IdleCandidateScorer
from .integrity import sha256_file, verify_sha256
from .syscall_histogram_pilot import atomic_json


def export_contexts(capture, manifest_path, expected_hash, output, maximum_rows=20000, samples=64):
    verify_sha256(manifest_path, expected_hash)
    manifest = json.loads(manifest_path.read_text())
    terminal_path = capture/'TERMINAL.json'
    terminal = json.loads(terminal_path.read_text())
    if terminal.get('state') != 'completed_observation':
        raise ValueError('closed observation required for timing context export')
    if output.exists():
        raise FileExistsError('export output already exists')
    output.mkdir(parents=True)
    state = dict(schema='pulse-batch-context-export-v1', registered_at_unix=time.time(),
        candidate_manifest_sha256=expected_hash, capture_terminal_sha256=sha256_file(terminal_path),
        maximum_rows=maximum_rows, samples_per_workload=samples, selection='first contiguous contexts by identity',
        outcomes_used_for_selection=False, use_for_training=False, full_source_checksums_verified=False)
    atomic_json(output/'START.json', state)
    proxy = DeferredScorer(manifest, expected_hash)
    runtime = CandidateShadowRuntime(proxy)
    contexts, identities, statuses = defaultdict(list), defaultdict(list), Counter()
    prefix = hashlib.sha256()
    inspected = 0
    files = []
    for directory in sorted((capture/'segments').glob('s[0-9]*')):
        path = directory/'features.jsonl'
        if not (directory/'TERMINAL.json').exists():
            raise ValueError('source segment still open')
        before = path.stat()
        with path.open('rb') as stream:
            for line in stream:
                if inspected >= maximum_rows:
                    break
                prefix.update(line)
                row = json.loads(line)
                if is_valid_feature_schema_record(row):
                    continue
                proxy.requests.clear()
                decision = runtime.observe(row)
                inspected += 1
                statuses[decision['status']] += 1
                if decision['status'] == 'batch-pending':
                    workload, context = proxy.requests[-1]
                    if len(contexts[workload]) < samples:
                        contexts[workload].append(context)
                        identities[workload].append({k: row[k] for k in ('node_name','pod_uid',
                            'container_name','workload_revision','cgroup_id','window_end')})
        after = path.stat()
        if (before.st_ino,before.st_size,before.st_mtime_ns) != (after.st_ino,after.st_size,after.st_mtime_ns):
            raise ValueError('closed feature source changed during export')
        files.append(dict(path=str(path), bytes=before.st_size, mtime_ns=before.st_mtime_ns,
                          segment_terminal_sha256=sha256_file(directory/'TERMINAL.json')))
        if inspected >= maximum_rows:
            break
    archive = output/'CONTEXTS.npz'
    np.savez_compressed(archive, **{k: np.stack(rows) for k,rows in contexts.items()})
    result = dict(state, state='completed_context_export', finished_at_unix=time.time(),
        feature_rows_inspected=inspected, status_counts=dict(statuses), source_files=files,
        inspected_prefix_sha256=prefix.hexdigest(), contexts_sha256=sha256_file(archive), identities=identities,
        contexts_by_workload={k:len(v) for k,v in contexts.items()})
    atomic_json(output/'TERMINAL.json', result)
    for p in [output,*output.iterdir()]:
        os.chown(p, 1000, 1000)
    return result


def summarize_times(values):
    return dict(samples=len(values), total_ms=sum(values),
        p50_ms=float(np.percentile(values,50)), p95_ms=float(np.percentile(values,95)),
        p99_ms=float(np.percentile(values,99)))


def benchmark(inputs, candidate_dir, expected_hash, frozen_source, output, repeats=2):
    verify_sha256(candidate_dir/'CANDIDATE_MANIFEST.json', expected_hash)
    manifest = json.loads((candidate_dir/'CANDIDATE_MANIFEST.json').read_text())
    software = dict(python=platform.python_version(), numpy=np.__version__,
                    sklearn=importlib.metadata.version('scikit-learn'))
    if software != manifest['software']:
        raise ValueError('benchmark software differs from frozen candidate')
    source = Path(__file__).parent
    unchanged = {}
    for name in ('idle_candidate.py','model.py','support_model.py','extended_reference_experiment.py',
                 'candidate_shadow.py','candidate_policy.py','encoding.py'):
        if sha256_file(source/name) != sha256_file(frozen_source/'sentinel_pulse'/name):
            raise ValueError('frozen scoring/history implementation changed: '+name)
        unchanged[name] = sha256_file(source/name)
    output.mkdir(parents=True,exist_ok=True)
    lock = (output/'benchmark.lock').open('a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    x, input_binding = defaultdict(list), []
    for root in inputs:
        terminal = json.loads((root/'TERMINAL.json').read_text())
        if terminal['state'] != 'completed_context_export' or terminal['candidate_manifest_sha256'] != expected_hash:
            raise ValueError('input export not bound to frozen candidate')
        verify_sha256(root/'CONTEXTS.npz',terminal['contexts_sha256'])
        input_binding.append(dict(path=str(root), terminal_sha256=sha256_file(root/'TERMINAL.json'),
                                  contexts_sha256=terminal['contexts_sha256']))
        with np.load(root/'CONTEXTS.npz',allow_pickle=False) as archive:
            for key in archive.files:
                if key not in manifest['workloads']:
                    raise ValueError('unexpected exported workload')
                x[key].append(archive[key].copy())
    if set(x) != set(manifest['workloads']):
        raise ValueError('timing export does not cover every frozen workload')
    x = {k:np.concatenate(v)[:64] for k,v in x.items()}
    if any(v.shape!=(64,996) or not np.isfinite(v).all() for v in x.values()):
        raise ValueError('each timing workload needs 64 finite contexts')
    binding = dict(model_manifest_sha256=expected_hash, inputs=input_binding, software=software,
        source_sha256=sha256_file(Path(__file__)), batch_source_sha256=sha256_file(source/'idle_batch.py'),
        unchanged_source_sha256=unchanged, repeats=repeats, batch_sizes=[2,4,8,16,32,64],
        ordering='sorted workloads; scalar reference then ascending batch sizes; warm-up first')
    status_path = output/'STATUS.json'
    if status_path.exists():
        state = json.loads(status_path.read_text())
        if state['binding'] != binding: raise ValueError('benchmark resume binding differs')
        if state['state']=='completed_equivalence_benchmark': return state
    else:
        state=dict(schema='pulse-idle-batch-equivalence-benchmark-v1',state='running',binding=binding,
            registered_at_unix=time.time(),workloads={},model_changed=False,threshold_changed=False,
            attack_recall=None,precision=None,kernel_to_alert=None,independent_accuracy_test=False)
        atomic_json(output/'START.json',state)
    with warnings.catch_warnings():
        warnings.simplefilter('error',InconsistentVersionWarning)
        scorer=IdleCandidateScorer(candidate_dir,expected_hash)
    for key, values in sorted(x.items()):
        if key in state['workloads']: continue
        scorer.score_context(key,values[0])
        references = [scorer.score_context(key,v) for v in values]
        expected = {name:np.asarray([r[name] for r in references]) for name in (*SCORE_FIELDS,'raw_model_anomaly')}
        scalar_times=[]
        for _ in range(repeats):
            for v in values:
                begin=time.perf_counter();scorer.score_context(key,v)
                scalar_times.append((time.perf_counter()-begin)*1000)
        results={}
        for size in binding['batch_sizes']:
            times=[];maximum_error=0.
            for _ in range(repeats):
                for start in range(0,len(values),size):
                    stop=min(start+size,len(values));begin=time.perf_counter()
                    observed=score_batch(scorer,key,values[start:stop]);times.append((time.perf_counter()-begin)*1000)
                    for name in SCORE_FIELDS:
                        actual=np.asarray([r[name] for r in observed]);ref=expected[name][start:stop]
                        maximum_error=max(maximum_error,float(np.max(np.abs(actual-ref))))
                        if name.endswith('_p'):
                            equal=np.array_equal(actual,ref)
                        else: equal=np.allclose(actual,ref,rtol=0,atol=1e-12)
                        if not equal: raise ValueError('scalar/batch scores differ: '+key+' '+name)
                    if not np.array_equal([r['raw_model_anomaly'] for r in observed],expected['raw_model_anomaly'][start:stop]):
                        raise ValueError('scalar/batch decision differs: '+key)
            measured=summarize_times(times)
            results[str(size)]=dict(measured,maximum_score_error=maximum_error,exact_p_and_decision_match=True,
                contexts_scored=len(values)*repeats,
                amortized_ms_per_context=measured['total_ms']/(len(values)*repeats),
                total_time_speedup=sum(scalar_times)/measured['total_ms'])
        state['workloads'][key]=dict(contexts=64,scalar=summarize_times(scalar_times),batch=results)
        state['updated_at_unix']=time.time();atomic_json(status_path,state)
    state.update(state='completed_equivalence_benchmark',finished_at_unix=time.time())
    atomic_json(status_path,state);atomic_json(output/'TERMINAL.json',state)
    return state


def main():
    p=argparse.ArgumentParser(description=__doc__);sub=p.add_subparsers(dest='action',required=True)
    e=sub.add_parser('export')
    for name in ('capture','manifest','output'):e.add_argument('--'+name,type=Path,required=True)
    e.add_argument('--manifest-sha256',required=True)
    b=sub.add_parser('benchmark');b.add_argument('--input',type=Path,action='append',required=True)
    for name in ('candidate-dir','frozen-source','output'):b.add_argument('--'+name,type=Path,required=True)
    b.add_argument('--manifest-sha256',required=True)
    a=p.parse_args()
    if a.action=='export':export_contexts(a.capture,a.manifest,a.manifest_sha256,a.output)
    else:benchmark(a.input,a.candidate_dir,a.manifest_sha256,a.frozen_source,a.output)


if __name__=='__main__':main()
