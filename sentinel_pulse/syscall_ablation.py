"""Retrain feature-group ablations on normal training data, then test holdout.

Test arrays are immutable independent contexts exported by syscall_analysis.
Thresholds are calibrated on the training dataset's temporal calibration split.
Normal-only evaluation supplies raw model FP/TN; attack TP/FN remain unknown.
"""
import argparse
import json
from pathlib import Path
import numpy as np

from .features import PulseFeatureBuilder
from .finalize_candidate import verify_model_bundle
from .integrity import sha256_file
from .model import PulseExtraTrees
from .observation_campaign import atomic_json
from .syscall_analysis import groups, pvalues
from .train import load_sequences


def run(dataset, model, analysis, output, workload=None):
    manifest,_,_=verify_model_bundle(model)
    if sha256_file(dataset)!=manifest['dataset_sha256']:raise ValueError('training dataset changed')
    heldout=json.loads(analysis.read_text())
    if not heldout['independent_capture_hash_and_post_training_time']:raise ValueError('independent holdout required')
    if heldout['model_manifest_sha256']!=sha256_file(model/'manifest.json'):raise ValueError('holdout model mismatch')
    archive=Path(heldout['context_archive']['path'])
    if sha256_file(archive)!=heldout['context_archive']['sha256']:raise ValueError('heldout context archive changed')
    data=np.load(archive,allow_pickle=False)
    # Training/calibration partition is the original temporal partition.
    sequences, observed_columns=load_sequences(dataset, manifest['max_contiguous_gap_seconds'])
    columns=list(PulseFeatureBuilder().columns)
    if list(observed_columns)!=columns:raise ValueError('training feature columns differ')
    variants={'full':[],**groups(columns)}
    result={'schema':'sentinel-pulse-retrained-normal-ablation-v1',
            'training_sha256':manifest['dataset_sha256'],'heldout_capture_sha256':heldout['capture_sha256'],
            'heldout_analysis_sha256':sha256_file(analysis),'automatic_promotion':False,
            'scope':'raw model, independent normal holdout; policy/attack recall not evaluated','workloads':{}}
    for k in sorted(data.files):
        if workload and k!=workload:continue
        evaluations={}
        for name,indices in variants.items():
            rows=[]
            for seq in sequences[k]:
                r=np.asarray(seq,dtype=np.float32).copy();r[:,indices]=0;rows.append(r)
            m=PulseExtraTrees(history=manifest['history_windows'],alpha=manifest['alpha'])
            fit=m.fit_sequences(rows)
            x=data[k].copy()
            expanded=[i+lag*249 for lag in range(m.history+1) for i in indices]
            x[:,expanded]=0
            score=m.estimator.predict_proba(x)[:,1]
            anomaly=pvalues(score,m.calibration_scores)<=m.alpha
            evaluations[name]={'normal_contexts':len(x),'FP_raw_model':int(anomaly.sum()),
                               'TN_raw_model':int((~anomaly).sum()),'raw_model_fpr':float(anomaly.mean()),
                               'TP':None,'FN':None,'precision':None,'recall':None,'fit':fit}
            result['workloads'][k]=evaluations
            atomic_json(output,result)
    return result


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('dataset','model','analysis','output'):p.add_argument('--'+n,type=Path,required=True)
    p.add_argument('--workload')
    a=p.parse_args();run(a.dataset,a.model,a.analysis,a.output,a.workload)


if __name__=='__main__':main()
