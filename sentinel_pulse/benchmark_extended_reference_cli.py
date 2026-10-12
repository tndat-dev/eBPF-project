"""Single-context timing of frozen extended-reference artifacts, not alert latency.

Execute this file with PYTHONPATH set to the original frozen reference source.
This keeps the pickle's scoring helpers pinned while the benchmark itself is new.
"""
import argparse
import __main__
import importlib.metadata
import json
import platform
from pathlib import Path
import pickle
import time
import numpy as np
from sentinel_pulse.extended_reference_experiment import (
    PulseExtendedReferenceTree,
    partitions_for,
)
from sentinel_pulse.integrity import sha256_file
from sentinel_pulse.recovery_worker_probe import clean_source
from sentinel_pulse.run_500ms_blind_matrix import atomic_json


def load_reference_model(path):
    # The trainer runs with ``python -m`` and pickles this detector under the
    # module name ``__main__``. Recreate that name before loading the artifact.
    __main__.PulseExtendedReferenceTree=PulseExtendedReferenceTree
    with Path(path).open('rb') as f:
        return pickle.load(f)


def run(source,experiment,output,samples=128):
    commit,files=clean_source(source)
    start=json.loads((experiment/'START.json').read_text())
    software=dict(python=platform.python_version(),numpy=np.__version__,sklearn=importlib.metadata.version('scikit-learn'))
    if software!=start['software']:raise ValueError('frozen benchmark software differs')
    for name in ['extended_reference_experiment.py','model.py','support_model.py','syscall_analysis.py']:
        key='sentinel_pulse/'+name
        if files.get(key)!=start['source_files'].get(key):raise ValueError('frozen scoring helper differs: '+name)
    result=json.loads((experiment/'RESULTS.json').read_text());index=json.loads((experiment/'INDEX.json').read_text())
    binding=dict(schema='pulse-extended-reference-benchmark-start-v1',source_commit=commit,
        benchmark_script_sha256=sha256_file(Path(__file__)),experiment_start_sha256=sha256_file(experiment/'START.json'),
        results_sha256=sha256_file(experiment/'RESULTS.json'),samples_per_workload=samples,
        single_context=True,kernel_to_alert=False,attack_data_used=False,software=software)
    if (output/'START.json').exists():
        previous=json.loads((output/'START.json').read_text())
        if any(previous.get(k)!=v for k,v in binding.items()):raise ValueError('benchmark binding changed')
    else:atomic_json(output/'START.json',dict(binding,at_unix=time.time()))
    target=output/'RESULTS.json'
    measured=json.loads(target.read_text()) if target.exists() else dict(workloads={},not_kernel_to_alert=True)
    for key,row in result['workloads'].items():
        if key in measured['workloads']:continue
        if 'artifact' not in row:
            measured['workloads'][key]=dict(state='missing_model',error=row.get('error'));atomic_json(target,measured);continue
        artifact=experiment/row['artifact']
        if sha256_file(artifact)!=row['artifact_sha256']:raise ValueError('benchmark artifact drift')
        data=experiment/index['workloads'][key]['file']
        if sha256_file(data)!=index['workloads'][key]['sha256']:raise ValueError('benchmark reference input drift')
        model=load_reference_model(artifact)
        partitions,_=partitions_for(data,index['train_cut'],index['holdout_cut'])
        contexts=[]
        for seq in partitions['holdout']:
            if len(seq)>3:
                x,y=model.base._examples(seq);contexts.append(model.base._contexts(x,y))
        if not contexts:raise ValueError('no holdout contexts for benchmark')
        values=np.concatenate(contexts);selected=np.linspace(0,len(values)-1,min(samples,len(values)),dtype=int)
        model.predict_contexts(values[selected[:1]]) # warm-up, not a reported sample
        times=[];flags=0
        for i in selected:
            before=time.perf_counter();decision=model.predict_contexts(values[i:i+1]);times.append((time.perf_counter()-before)*1000)
            flags+=int(decision['anomalous'][0])
        measured['workloads'][key]=dict(state='measured',samples=len(times),inference_ms=times,
            p50_ms=float(np.quantile(times,.5)),p95_ms=float(np.quantile(times,.95)),p99_ms=float(np.quantile(times,.99)),
            reference_flags=flags,reference_flags_are_not_false_positives=True,artifact_sha256=row['artifact_sha256'])
        atomic_json(target,measured);del model,partitions,contexts,values
    if not (output/'TERMINAL.json').exists():atomic_json(output/'TERMINAL.json',dict(state='completed',at_unix=time.time()))


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('source','experiment','output'):p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--samples',type=int,default=128);a=p.parse_args()
    if not 16<=a.samples<=1024:raise ValueError('bounded sample count required')
    a.output.mkdir(parents=True,exist_ok=True);run(a.source,a.experiment,a.output,a.samples)


if __name__=='__main__':main()
