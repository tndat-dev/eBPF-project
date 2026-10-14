"""Verify completed independent normal inference; do not label raw flags FP."""
import argparse
from collections import defaultdict
import json
from pathlib import Path
import time

from .integrity import sha256_file,verify_sha256


def aggregate(terminal):
    if terminal['state']!='completed_independent_normal_raw_scores':raise ValueError('not completed')
    variants={};workload_rows={}
    for key,result in sorted(terminal['completed'].items()):
        workload,variant=key.rsplit('|',1)
        n=result['contexts'];positive=result['raw_model_positive']
        if not 0<=positive<=n or n<=0:raise ValueError('invalid counts')
        if workload in workload_rows and workload_rows[workload]!=n:raise ValueError('variant context mismatch')
        workload_rows[workload]=n
        v=variants.setdefault(variant,dict(contexts=0,raw_model_positive=0,raw_model_negative=0,by_regime={}))
        v['contexts']+=n;v['raw_model_positive']+=positive;v['raw_model_negative']+=n-positive
        rows=flags=0
        for source in result['source_captures']:
            if source['start_row']!=rows:raise ValueError('prediction source offset mismatch')
            rows+=source['rows'];flags+=source['raw_model_positive']
            g=v['by_regime'].setdefault(source['regime'],dict(contexts=0,raw_model_positive=0))
            g['contexts']+=source['rows'];g['raw_model_positive']+=source['raw_model_positive']
        if rows!=n or flags!=positive:raise ValueError('source sums differ')
    if any(v['contexts']!=sum(workload_rows.values()) for v in variants.values()):raise ValueError('unpaired variants')
    return dict(schema='pulse-independent-normal-verification-v1',completed_models=len(terminal['completed']),
        workloads=len(workload_rows),variants=len(variants),unique_source_contexts=sum(workload_rows.values()),
        labels='pending_health_and_behavior_adjudication',raw_model_only=True,policy_applied=False,
        variant_counts=variants,confusion_matrix=dict(TP=None,FP=None,TN=None,FN=None),
        precision=None,recall=None,false_positive_rate=None,kernel_to_alert=None,
        interpretation='raw positives/negatives are not FP/TN; no ranking or tuning from holdout')


def main():
    import numpy as np
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();root=a.root;terminal=json.loads((root/'TERMINAL.json').read_text())
    verify_sha256(root/'START.json',terminal['start_sha256']);verify_sha256(root/'DATASET.json',terminal['dataset_sha256'])
    result=aggregate(terminal)
    if (result['completed_models']!=608 or result['workloads']!=19 or result['variants']!=32
            or result['unique_source_contexts']!=334655):raise ValueError('registered evaluation coverage differs')
    dataset=json.loads((root/'DATASET.json').read_text())
    for capture in dataset['captures'].values():
        for relative,expected in capture['seals'].items():
            path=(root/relative).resolve()
            if root.resolve() not in path.parents:raise ValueError('unsafe context path')
            verify_sha256(path,expected)
    verified=0
    for record in terminal['completed'].values():
        path=(root/record['prediction_artifact']).resolve()
        if path.parent!=(root/'predictions').resolve():raise ValueError('unsafe prediction path')
        verify_sha256(path,record['sha256'])
        with np.load(path,allow_pickle=False) as saved:
            if (set(saved.files)!={'score','conformal_p','anomalous'}
                    or any(len(saved[n])!=record['contexts'] for n in saved.files)
                    or not np.isfinite(saved['score']).all() or not np.isfinite(saved['conformal_p']).all()
                    or saved['anomalous'].dtype!=np.dtype(bool)
                    or int(saved['anomalous'].sum())!=record['raw_model_positive']):
                raise ValueError('prediction arrays/counts differ')
            if not np.array_equal(saved['anomalous'],saved['conformal_p']<=.001):raise ValueError('threshold differs')
            for source in record['source_captures']:
                i=source['start_row'];n=source['rows']
                if int(saved['anomalous'][i:i+n].sum())!=source['raw_model_positive']:raise ValueError('source flag mismatch')
        verified+=1
    result.update(verified_at_unix=time.time(),prediction_archives_verified=verified,raw_context_seals_verified=True,
        bindings={name:sha256_file(root/name) for name in ('START.json','DATASET.json','TERMINAL.json')},
        verifier_sha256=sha256_file(Path(__file__)),automatic_promotion=False)
    with a.output.open('x') as stream:json.dump(result,stream,indent=2);stream.write('\n')
    print(json.dumps(dict(output=str(a.output),models_verified=verified,contexts=result['unique_source_contexts'],
        full=result['variant_counts']['full'])))


if __name__=='__main__':main()
