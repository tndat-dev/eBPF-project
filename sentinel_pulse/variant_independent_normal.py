"""Checkpointed C2 inference on sealed C3 normal holdout, without fitting.

Raw model positives remain unadjudicated. No FP/TN, precision, recall or
kernel-to-alert claim is inferred from a normal capture or offline timing.
"""
from __future__ import annotations

import argparse
from collections import Counter, deque
from datetime import datetime
import fcntl
import gc
import hashlib
import json
import math
import os
from pathlib import Path
import pickle
import time
import warnings

import numpy as np
from sklearn.exceptions import InconsistentVersionWarning

from .derive_variant_manifest import _safe_model_path
from .feature_profile import training_profile
from .integrity import sha256_file, verify_sha256
from .syscall_histogram_pilot import atomic_json
from .variant_capture_audit import IDENTITY, FAILURE_COUNTERS, decode
from .variant_replay import apply_mask, check_chain, predict


def temporal_contexts(stream, columns, revisions, probe_start, probe_end, node):
    """Match audit admission; do not bridge gaps, identities or excluded rows."""
    schema=hashlib.sha256(json.dumps(columns,separators=(',',':'),ensure_ascii=True).encode()).hexdigest()
    histories={};saw_schema=False
    for line_number,line in enumerate(stream,1):
        row=json.loads(line)
        if row.get('schema')=='sentinel-pulse-feature-schema-v1':
            if row.get('columns')!=columns or row.get('feature_schema_sha256')!=schema:
                raise ValueError('sealed columns differ')
            saw_schema=True;continue
        if (not saw_schema or row.get('schema')!='sentinel-pulse-feature-v1'
                or row.get('feature_schema_sha256')!=schema):raise ValueError('schema mismatch')
        vector=np.asarray(decode(row,len(columns)),dtype=np.float32)
        key=tuple(row.get(k) for k in IDENTITY)
        if any(v is None or v=='' for v in key) or row['node_name']!=node:raise ValueError('identity mismatch')
        start,end=row['window_start'],row['window_end']
        if not all(isinstance(x,(int,float)) and math.isfinite(x) for x in (start,end)) or end<=start:
            raise ValueError('invalid time')
        counts=row.get('exact_counts',{})
        if not counts or any(type(v) is not int or v<0 for v in counts.values()) or sum(counts.values())!=row.get('exact_total'):
            raise ValueError('invalid exact counts')
        w=row['workload_key'];stats=row.get('collector_stats')
        if (start<probe_start or end>probe_end or w not in revisions or row['workload_revision'] not in revisions[w]
                or not .35<=end-start<=.75 or not isinstance(stats,dict)
                or any(k not in stats or stats[k]!=0 for k in FAILURE_COUNTERS)):
            histories.pop(key,None);continue
        previous,history=histories.get(key,(None,deque(maxlen=3)))
        if previous is not None and abs(start-previous)>1e-4:history.clear()
        context=np.concatenate([*history,vector]) if len(history)==3 else None
        history.append(vector);histories[key]=(end,history)
        if context is not None:
            yield w,context,dict(source_line=line_number,**{k:row[k] for k in IDENTITY},
                window_start=start,window_end=end)


def checked_path(root,relative):
    p=(root/relative).resolve()
    if root.resolve() not in p.parents:raise ValueError('artifact outside output')
    return p


def verify_dataset(root,dataset):
    for capture in dataset['captures'].values():
        for relative,expected in capture['seals'].items():verify_sha256(checked_path(root,relative),expected)


def prepare(campaign,audit,training,manifest,root,model_ended,corrected_root=None):
    path=root/'DATASET.json'
    if path.exists():
        dataset=json.loads(path.read_text());verify_dataset(root,dataset);return dataset
    dataset=dict(schema='pulse-c3-heldout-contexts-v1',captures={},context_rows=0,
        labels='unadjudicated_observation',independent_post_training_capture=True,history=3,
        feature_dim=249,split='holdout',fitting_performed=False)
    revisions={k:training['approved_workload_revisions'].get(k,[]) for k in manifest['workloads']}
    for run_id,report in sorted(audit['captures'].items()):
        if Path(run_id).name!=run_id:raise ValueError('unsafe run id')
        source=campaign/'holdout'/run_id
        for name in ('features.jsonl','START.json','TERMINAL.json'):
            verify_sha256(source/name,report['seals'][name])
        features_source=source/'features.jsonl';feature_hash=report['seals']['features.jsonl']
        if corrected_root is not None:
            corrected=corrected_root/'holdout'/run_id
            correction=json.loads((corrected/'DERIVED.json').read_text())
            complete=json.loads((corrected_root/'TERMINAL.json').read_text())
            if (correction!=complete['captures']['holdout/'+run_id]
                    or correction['source_features_sha256']!=feature_hash
                    or correction['training_profile']!='exact-ebpf-500ms-rolling-10'
                    or correction['reference_vectors_exact'] is not True
                    or correction['nonrolling_191_features_unchanged'] is not True):raise ValueError('correction provenance differs')
            features_source=corrected/'features.jsonl';feature_hash=correction['corrected_features_sha256']
            verify_sha256(features_source,feature_hash)
        terminal=json.loads((source/'TERMINAL.json').read_text());start=json.loads((source/'START.json').read_text())
        if terminal['probe_started_at_unix']<=model_ended:raise ValueError('capture predates model freeze')
        final=root/'contexts'/run_id
        receipt=final/'RECEIPT.json'
        if receipt.exists():
            saved=json.loads(receipt.read_text())
            if saved['source_features_sha256']!=feature_hash:raise ValueError('resume capture changed')
            for relative,expected in saved['seals'].items():verify_sha256(checked_path(root,relative),expected)
        else:
            # Incomplete attempts survive for inspection; only complete receipts are reused.
            temporary=root/'contexts'/(run_id+'.partial-'+str(time.time_ns()));temporary.mkdir(parents=True)
            arrays={};files={};counts=Counter();expected={}
            for w,details in report['workloads'].items():
                n=details.get('eligible_four_window_contexts',0)
                if not n:continue
                name=hashlib.sha256(w.encode()).hexdigest()[:24]+'.npy'
                arrays[w]=np.lib.format.open_memmap(temporary/name,mode='w+',dtype=np.float32,shape=(n,996))
                files[w]=name;expected[w]=n
            meta=temporary/'metadata.jsonl'
            with features_source.open() as stream,meta.open('x') as metadata:
                for w,context,identity in temporal_contexts(stream,training['feature_columns'],revisions,
                        terminal['probe_started_at_unix'],terminal['probe_ended_at_unix'],start['node_name']):
                    i=counts[w]
                    if w not in arrays or i>=len(arrays[w]):raise ValueError('extraction exceeds audit')
                    arrays[w][i]=context;counts[w]+=1
                    metadata.write(json.dumps(dict(workload_row=i,**identity),separators=(',',':'))+'\n')
                metadata.flush();os.fsync(metadata.fileno())
            if dict(counts)!=expected:raise ValueError('extraction counts differ from verified audit')
            for array in arrays.values():array.flush()
            arrays.clear();gc.collect()
            verify_sha256(features_source,feature_hash)
            if final.exists():raise ValueError('unsealed final context directory')
            saved=dict(regime=report['regime'],source_features_sha256=feature_hash,
                probe_start=terminal['probe_started_at_unix'],probe_end=terminal['probe_ended_at_unix'],
                workloads={w:dict(rows=counts[w],path=str((final/name).relative_to(root))) for w,name in files.items()},
                seals={str((final/p.name).relative_to(root)):sha256_file(p) for p in temporary.iterdir() if p.is_file()})
            atomic_json(temporary/'RECEIPT.json',saved)
            temporary.rename(final)
        dataset['captures'][run_id]=saved;dataset['context_rows']+=sum(v['rows'] for v in saved['workloads'].values())
        atomic_json(root/'PREPARE_STATUS.json',dict(state='preparing',completed_captures=len(dataset['captures']),
            expected_captures=15,context_rows=dataset['context_rows'],updated_at_unix=time.time()))
    if dataset['context_rows']!=sum(x['counts'].get('eligible_four_window_contexts',0) for x in audit['captures'].values()):
        raise ValueError('dataset context cardinality mismatch')
    atomic_json(path,dataset);return dataset


def run(campaign,audit_path,audit_hash,training_path,model_root,model_hash,output,corrected_root=None):
    output.mkdir(parents=True,exist_ok=True)
    lock=(output/'run.lock').open('a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    verify_sha256(audit_path,audit_hash);audit=json.loads(audit_path.read_text())
    manifest,start,results,software=check_chain(model_root,model_hash)
    verify_sha256(training_path,manifest['training_manifest_sha256']);training=json.loads(training_path.read_text())
    profile=training_profile(training_path)
    if corrected_root is None:
        if profile['rolling_windows']!=5:
            raise ValueError('C3 rolling-5 differs from training profile; verified raw refeature required')
    else:
        correction=json.loads((corrected_root/'TERMINAL.json').read_text())
        if (correction['state']!='completed_profile_repair' or correction['completed_captures']!=30
                or correction['binding']['training_manifest_sha256']!=manifest['training_manifest_sha256']
                or correction['binding']['audit_sha256']['holdout']!=audit_hash
                or correction['binding']['target_profile']!=profile['name']
                or correction['binding']['campaign_start_sha256']!=sha256_file(campaign/'START.json')):
            raise ValueError('completed matching preprocessing repair required')
    verify_sha256(Path(__file__).with_name('model.py'),start['source_module_sha256']['model.py'])
    if (audit['split']!='holdout' or audit['captures_verified']!=15 or audit['variant_manifest_sha256']!=model_hash
            or audit['training_manifest_sha256']!=manifest['training_manifest_sha256']
            or audit['campaign_start_sha256']!=sha256_file(campaign/'START.json')):raise ValueError('audit binding differs')
    if len(training['feature_columns'])!=249 or manifest['history']!=3 or manifest['feature_dim']!=249:
        raise ValueError('temporal schema differs')
    binding=dict(audit_sha256=audit_hash,model_manifest_sha256=model_hash,
        training_manifest_sha256=manifest['training_manifest_sha256'],software=software,
        source_sha256={n:sha256_file(Path(__file__).with_name(n)) for n in
            ('variant_independent_normal.py','variant_capture_audit.py','variant_replay.py','model.py')},
        campaign_terminal_sha256=sha256_file(campaign/'TERMINAL.json'),training_feature_profile=profile,
        corrected_preprocessing_terminal_sha256=sha256_file(corrected_root/'TERMINAL.json') if corrected_root else None)
    if (output/'START.json').exists():
        if json.loads((output/'START.json').read_text())['binding']!=binding:raise ValueError('resume binding changed')
    else:
        atomic_json(output/'START.json',dict(binding=binding,registered_at_unix=time.time(),expected_models=608,
            evidence_class='frozen_model_inference_on_new_normal_holdout',no_training_or_threshold_change=True,
            policy_applied=False,labels='pending_health_and_behavior_adjudication',
            previously_scored_under_wrong_preprocessing=corrected_root is not None,
            precision=None,recall=None,false_positive_rate=None,kernel_to_alert=None,automatic_promotion=False))
    ended=datetime.fromisoformat(json.loads((model_root/'TERMINAL.json').read_text())['ended_at']).timestamp()
    dataset=prepare(campaign,audit,training,manifest,output,ended,corrected_root)
    state_path=output/'STATUS.json'
    state=json.loads(state_path.read_text()) if state_path.exists() else dict(state='scoring',completed={},binding=binding,
        registered_at_unix=time.time(),dataset_sha256=sha256_file(output/'DATASET.json'),expected_models=608)
    if state['binding']!=binding or state['dataset_sha256']!=sha256_file(output/'DATASET.json'):raise ValueError('state changed')
    lookup={n:i for i,n in enumerate(training['feature_columns'])};predictions=output/'predictions';predictions.mkdir(exist_ok=True)
    for workload,variants in sorted(manifest['workloads'].items()):
        for variant,record in sorted(variants.items()):
            key=workload+'|'+variant
            if key in state['completed']:
                d=state['completed'][key];verify_sha256(checked_path(output,d['prediction_artifact']),d['sha256']);continue
            artifact=_safe_model_path(model_root,record['artifact']);verify_sha256(artifact,record['sha256'])
            if artifact.stat().st_size!=record['bytes'] or record['masked_columns']!=results['workloads'][workload]['variants'][variant]['masked_columns']:
                raise ValueError('model artifact or mask differs')
            with warnings.catch_warnings():
                warnings.simplefilter('error',InconsistentVersionWarning)
                with artifact.open('rb') as handle:model=pickle.load(handle)
            if (model.history!=3 or model.feature_dim!=249 or model.alpha!=manifest['alpha']):raise ValueError('model contract changed')
            indices=[lookup[n] for n in record['masked_columns']]
            scores=[];ps=[];flags=[];sources=[];timing=0
            for run_id,capture in sorted(dataset['captures'].items()):
                if workload not in capture['workloads']:continue
                d=capture['workloads'][workload];x=np.load(checked_path(output,d['path']),mmap_mode='r',allow_pickle=False)
                offset=sum(len(a) for a in scores);positives=0
                for i in range(0,len(x),4096):
                    values=apply_mask(x[i:i+4096],indices,249,3);before=time.perf_counter()
                    score,p,flag=predict(model,values);timing+=time.perf_counter()-before
                    scores.append(score);ps.append(p);flags.append(flag);positives+=int(flag.sum())
                sources.append(dict(run_id=run_id,regime=capture['regime'],start_row=offset,rows=len(x),raw_model_positive=positives))
            score=np.concatenate(scores);p=np.concatenate(ps);flag=np.concatenate(flags)
            name=hashlib.sha256(key.encode()).hexdigest()[:32]+'.npz';path=predictions/name
            temporary=predictions/(name+'.partial-'+str(time.time_ns()))
            with temporary.open('xb') as handle:
                np.savez_compressed(handle,score=score,conformal_p=p,anomalous=flag);handle.flush();os.fsync(handle.fileno())
            os.replace(temporary,path)
            state['completed'][key]=dict(contexts=len(score),raw_model_positive=int(flag.sum()),
                raw_positive_fraction=float(flag.mean()),prediction_artifact=str(path.relative_to(output)),
                sha256=sha256_file(path),source_captures=sources,batch_inference_seconds=timing,
                labels='pending_adjudication_not_false_positive',precision=None,recall=None,kernel_to_alert=None)
            state.update(state='scoring',completed_models=len(state['completed']),updated_at_unix=time.time())
            atomic_json(state_path,state);del model,scores,ps,flags,score,p,flag;gc.collect()
    state.update(state='completed_independent_normal_raw_scores',finished_at_unix=time.time(),
        confusion_matrix=dict(TP=None,FP=None,TN=None,FN=None),precision=None,recall=None,
        false_positive_rate=None,kernel_to_alert=None,blind_attack_complete=False,
        start_sha256=sha256_file(output/'START.json'),automatic_promotion=False)
    atomic_json(state_path,state);atomic_json(output/'TERMINAL.json',state);return state


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('campaign','audit','training-manifest','model-root','output'):p.add_argument('--'+n,type=Path,required=True)
    for n in ('audit-sha256','model-sha256'):p.add_argument('--'+n,required=True)
    p.add_argument('--corrected-root',type=Path)
    a=p.parse_args();run(a.campaign,a.audit,a.audit_sha256,a.training_manifest,a.model_root,a.model_sha256,a.output,a.corrected_root)


if __name__=='__main__':main()
