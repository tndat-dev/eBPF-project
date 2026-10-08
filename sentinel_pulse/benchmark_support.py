"""Single-context timing of frozen support artifacts; not kernel-to-alert."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import pickle
import platform
import time
import numpy as np
from .integrity import contained_artifact, sha256_file
from .run_500ms_blind_matrix import atomic_json


def benchmark(root, analysis, output, samples=64):
    if type(samples) is not int or samples < 20:
        raise ValueError('at least 20 single-context samples per workload required')
    start=json.loads((root/'START.json').read_text())
    results=json.loads((root/'RESULTS.json').read_text())
    terminal=json.loads((root/'TERMINAL.json').read_text())
    heldout=json.loads(analysis.read_text());archive=Path(heldout['context_archive']['path'])
    if (terminal['state']!='completed' or results['start_sha256']!=sha256_file(root/'START.json')
            or sha256_file(analysis)!=start['analysis_sha256']
            or sha256_file(archive)!=start['context_archive_sha256']):
        raise ValueError('support timing input binding differs')
    workloads={}
    with np.load(archive,allow_pickle=False) as data:
        for key,row in results['workloads'].items():
            path=contained_artifact(root,row['artifact'])
            if sha256_file(path)!=row['artifact_sha256']:raise ValueError('support artifact differs')
            if key not in data.files:
                workloads[key]={'status':'missing_normal_contexts'};continue
            with path.open('rb') as stream:model=pickle.load(stream)
            contexts=data[key]
            if not len(contexts):raise ValueError('empty normal timing contexts')
            for index in range(5):
                selected=index % len(contexts)
                model.predict_contexts(contexts[selected:selected+1])
            times=[]
            for index in np.linspace(0,len(contexts)-1,samples,dtype=int):
                then=time.perf_counter();model.predict_contexts(contexts[index:index+1])
                times.append((time.perf_counter()-then)*1000)
            workloads[key]=dict(samples=samples,p50_ms=float(np.quantile(times,.5)),
                                p95_ms=float(np.quantile(times,.95)),p99_ms=float(np.quantile(times,.99)),
                                maximum_ms=max(times),individual_inference_ms=times)
    report=dict(schema='pulse-support-single-context-timing-v1', measured_at_unix=time.time(),
                node=platform.node(),kernel=platform.release(),python=platform.python_version(),
                start_sha256=sha256_file(root/'START.json'),results_sha256=sha256_file(root/'RESULTS.json'),
                workloads=workloads,warmup_contexts=5,protocol_samples_per_workload=samples,
                batches_of_one=True,includes_tree_and_support_pvalues=True,
                kernel_to_alert_seconds=None,policy_evaluated=False,automatic_promotion=False,
                evidence_class='offline_master_timing_not_worker_latency',
                limitation='normal contexts only; p99 from 64 samples is exploratory; report service CPU quota separately')
    atomic_json(output,report);return report


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('root','analysis','output'):p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args();benchmark(a.root,a.analysis,a.output)


if __name__=='__main__':main()
