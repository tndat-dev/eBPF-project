"""Normal-only matched 500ms addition/group-ablation fits, with checkpoints."""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict, deque
import fcntl
import hashlib
import json
from pathlib import Path
import pickle
import re
import time

import numpy as np

from .encoding import decode_vector
from .extended_reference_experiment import PulseExtendedReferenceTree
from .features import TRACKED_SYSCALLS
from .integrity import sha256_file
from .support_model import PulseSupportEnsemble
from .syscall_histogram_pilot import atomic_json

SEEDS=(73021,73022,73023)
SECURITY=(175,176,246,248,249,250,265,310,311,313,321,323,425,426,427)
GROUPS=dict(drop_accept_pair=(43,288),drop_open_pair=(2,257),
            drop_exec_pair=(59,322),drop_clone_pair=(56,435))


def arm_specs(counts, defined):
    ranked=[i for i,v in sorted(counts.items(),key=lambda item:(-item[1],item[0]))
            if v and i not in TRACKED_SYSCALLS]
    arms={'base29':dict(add=[],drop=[])}
    for n in (8,16,32):arms[f'plus_top{n}']=dict(add=ranked[:n],drop=[])
    arms['plus_security']=dict(add=list(SECURITY),drop=[])
    arms['plus_all_observed']=dict(add=ranked,drop=[])
    arms['plus_all_defined_native']=dict(add=sorted(set(defined)-set(TRACKED_SYSCALLS)),drop=[])
    arms.update({k:dict(add=[],drop=list(v)) for k,v in GROUPS.items()})
    return arms


def contexts(rows, spec, start, stop):
    """Recompute all rolling columns after every split/gap; preserve true order."""
    result=defaultdict(list);state={}
    added=spec['add'];drop=set(spec['drop']);ids=list(TRACKED_SYSCALLS)
    keep=[i for i in range(249) if not any(i==j+offset for j,n in enumerate(ids)
                                         if n in drop for offset in (0,29,191,220))]
    split=start+.7*(stop-start)
    for row in rows:
        a,b=row['window_start'],row['window_end']
        phase='train' if start<=a and b<split-2 else ('calibration' if split+2<a and b<=stop else None)
        ident=tuple(row[k] for k in ('node_name','pod_uid','container_name','workload_revision','cgroup_id'))
        if phase is None or not row.get('eligible_for_normal_review') or not .35<=b-a<=.8:
            state.pop(ident,None);continue
        prior=state.get(ident)
        if prior is None or prior['phase']!=phase or not .35<=b-prior['end']<=.8:
            prior=dict(phase=phase,rates=deque(maxlen=10),vectors=deque(maxlen=3))
            state[ident]=prior
        rates=np.array([row['full_counts_delta'].get(str(n),0)/(b-a) for n in ids+added])
        vector=decode_vector(row)
        if len(prior['rates'])==10:
            history=np.asarray(prior['rates'])
            mean,std=np.log1p(history.mean(0)),np.log1p(history.std(0))
            vector[191:220]=mean[:29];vector[220:249]=std[:29]
            selected=np.array([row['full_counts_delta'].get(str(n),0) for n in added])
            vector=np.concatenate([vector[keep],np.log1p(selected),selected/max(row['exact_total'],1),
                                   mean[29:],std[29:]]).astype(np.float32)
            if len(prior['vectors'])==3:
                result[phase].append(np.concatenate([*prior['vectors'],vector]))
            prior['vectors'].append(vector)
        prior['rates'].append(rates);prior['end']=b
    return {phase:np.stack(items) for phase,items in result.items() if items}


def sealed_selection_files(worker_root, selection_end, selection_start=0):
    """Return sealed feature files only after the last one covers selection end."""
    files=[];latest_end=None
    for terminal_path in sorted(worker_root.glob('segments/s*/TERMINAL.json')):
        segment=terminal_path.parent
        feature_path=segment/'features.jsonl'
        terminal=json.loads(terminal_path.read_text())
        if not terminal.get('seals',{}).get(feature_path.name):
            raise ValueError('feature segment has no seal: '+str(feature_path))
        with feature_path.open('rb') as stream:
            stream.seek(max(0,feature_path.stat().st_size-1024**2))
            if stream.tell():stream.readline()
            last=None
            for line in stream:
                if line.endswith(b'\n'):
                    row=json.loads(line)
                    if 'window_end' in row:last=max(last or float('-inf'),float(row['window_end']))
        if last is not None:
            latest_end=max(latest_end or last,last)
            if last>=selection_start:files.append(feature_path)
            if last>=selection_end:break
    if latest_end is None or latest_end < selection_end:
        return [],latest_end
    return files,latest_end


def run(config_path):
    cfg=json.loads(config_path.read_text());root=Path(cfg['study_output']);root.mkdir(parents=True,exist_ok=True)
    lock=(root/'study.lock').open('a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    binding=dict(config_sha256=sha256_file(config_path),source_sha256=sha256_file(Path(__file__)),
        seeds=list(SEEDS),train_context_cap=3000,calibration_context_cap=1500,
        sample_rule='equally spaced ordered contexts; same indices for every arm and seed',
        trees=192,tree_alpha=.001,support_budget=.05,horizon_windows=30,
        raw_observable='same full-ID 500ms frames, idle v2, transition64, rolling10, history3',
        attacks_used_for_fit=False,normal_labels='expected_normal_unadjudicated',
        purpose='prospective_feature_utility_development; no global optimum claim',automatic_promotion=False)
    if (root/'START.json').exists():
        if json.loads((root/'START.json').read_text())!=binding:raise ValueError('study binding changed')
    else:atomic_json(root/'START.json',binding)
    if (root/'TERMINAL.json').exists():return
    end=cfg['selection_end']
    while True:
        files=[];ready=True;coverage={};waiting={}
        for worker in cfg['workers'].values():
            worker_root=Path(worker['output'])
            try:
                state=json.loads((worker_root/'STATUS.json').read_text())
                if state.get('completed_seconds',0)<cfg['selection_seconds']:ready=False
                sealed,latest=sealed_selection_files(worker_root,end,cfg['selection_start'])
                coverage[state.get('node_name',worker['node_name'])]=latest
                if not sealed:ready=False
                files.extend(sealed)
            except (OSError,ValueError) as exc:
                ready=False;waiting[worker['node_name']]=str(exc)
        if time.time()>=end+60 and ready and len(files)>=3:break
        atomic_json(root/'STATUS.json',dict(state='waiting_for_clean_selection_capture',
            selection_end=end,sealed_feature_files=len(files),sealed_coverage_end=coverage,waiting_reasons=waiting,
            updated_at_unix=time.time()))
        time.sleep(30)
    index_path=root/'INPUTS.json'
    if not index_path.exists():
        inputs=[]
        for path in files:
            digest=sha256_file(path)
            terminal=json.loads((path.parent/'TERMINAL.json').read_text())
            if terminal['seals'].get(path.name)!=digest:
                raise ValueError('sealed feature segment hash mismatch: '+str(path))
            inputs.append(dict(path=str(path.resolve()),sha256=digest))
        excluded=[]
        journals=[Path(cfg['campaign_output'])/'INTERVALS.jsonl',
                  *[Path(p)/'INTERVALS.jsonl' for p in cfg.get('prior_campaign_outputs',[])],
                  *config_path.parent.glob('evaluator-smoke*/INTERVALS.jsonl')]
        for journal in journals:
            if not journal.exists():continue
            for line in journal.read_text().splitlines():
                row=json.loads(line)
                if row.get('label')=='attack':
                    excluded.append([row['start_at']-10,row['start_at']+45])
        atomic_json(index_path,dict(files=inputs,selection_start=cfg['selection_start'],selection_end=end,
                                   excluded_attack_intervals=excluded))
    inputs=json.loads(index_path.read_text())
    counts=Counter();columns=None;handles={};directory=root/'workloads';directory.mkdir(exist_ok=True)
    # Completed index is reused; partial indexes are rebuilt from immutable sources.
    if not (root/'INDEX.json').exists():
        try:
            for item in inputs['files']:
                path=Path(item['path'])
                if sha256_file(path)!=item['sha256']:raise ValueError('sealed selection input changed')
                with path.open() as stream:
                    for line in stream:
                        row=json.loads(line)
                        if 'columns' in row:
                            if columns is not None and columns!=row['columns']:raise ValueError('schema changed')
                            columns=row['columns'];continue
                        a,b=row['window_start'],row['window_end']
                        if a<cfg['selection_start'] or b>end:continue
                        if any(a<finish and b>begin for begin,finish in inputs.get('excluded_attack_intervals',[])):
                            continue
                        key=row['workload_key']
                        if key not in cfg['workload_keys']:continue
                        if key not in handles:handles[key]=(directory/(hashlib.sha256(key.encode()).hexdigest()+'.jsonl')).open('w')
                        handles[key].write(line)
                        if b<cfg['selection_start']+.7*cfg['selection_seconds']-2 and row.get('eligible_for_normal_review'):
                            counts.update({int(k):v for k,v in row['full_counts_delta'].items()})
        finally:
            for f in handles.values():f.close()
        defined=cfg['native_syscall_ids']
        index=dict(arms=arm_specs(counts,defined),training_counts={str(k):v for k,v in counts.items()},
            workloads={k:dict(path=str(Path(f.name).resolve()),sha256=sha256_file(Path(f.name))) for k,f in handles.items()},
            missing_workloads=sorted(set(cfg['workload_keys'])-set(handles)),
            input_manifest_sha256=sha256_file(index_path),columns=columns,
            hash_and_sensitive_aggregate_information_retained_in_group_ablations=True,
            native_syscall_abi_source=cfg['native_syscall_header'])
        atomic_json(root/'INDEX.json',index)
    index=json.loads((root/'INDEX.json').read_text())
    status_path=root/'STATUS.json'
    existing=json.loads(status_path.read_text()) if status_path.exists() else {}
    state=dict(state='fitting_matched_variants',completed=existing.get('completed',{}),
               unknown=existing.get('unknown',{}),expected_models=len(cfg['workload_keys'])*len(index['arms'])*3,
               index_sha256=sha256_file(root/'INDEX.json'),fresh_blind_complete=False)
    for key,item in sorted(index['workloads'].items()):
        path=Path(item['path'])
        if sha256_file(path)!=item['sha256']:raise ValueError('workload index changed')
        with path.open() as f:rows=[json.loads(line) for line in f]
        rows.sort(key=lambda r:(r['window_end'],str(r['cgroup_id'])))
        for arm,spec in index['arms'].items():
            parts=contexts(rows,spec,cfg['selection_start'],end)
            if any(len(parts.get(p,()))<1200 for p in ('train','calibration')):
                state['unknown'][key+'|'+arm]={p:len(parts.get(p,())) for p in ('train','calibration')};continue
            for p,cap in (('train',3000),('calibration',1500)):
                if len(parts[p])>cap:parts[p]=parts[p][np.linspace(0,len(parts[p])-1,cap,dtype=int)]
            width=parts['train'].shape[1]//4
            for seed in SEEDS:
                tag=f'{key}|{arm}|{seed}'
                if tag in state['completed']:
                    saved=state['completed'][tag]
                    if sha256_file(root/saved['artifact'])!=saved['sha256']:raise ValueError('model checkpoint changed')
                    continue
                state.update(current_model=tag,updated_at_unix=time.time());atomic_json(status_path,state)
                tree=PulseExtendedReferenceTree(history=3,alpha=.001,random_state=seed)
                fit=tree.fit_sequences({p:[c.reshape(4,width) for c in parts[p]] for p in ('train','calibration')})
                model=PulseSupportEnsemble(tree);support=model.fit_support(parts['train'][:,-width:],parts['calibration'][:,-width:])
                name=hashlib.sha256(tag.encode()).hexdigest()+'.pkl';temporary=root/(name+'.partial')
                with temporary.open('wb') as f:pickle.dump(model,f,pickle.HIGHEST_PROTOCOL)
                temporary.replace(root/name)
                state['completed'][tag]=dict(artifact=name,sha256=sha256_file(root/name),fit=fit,support=support,
                    arm=spec,feature_dim=width,workload=key,seed=seed)
                atomic_json(status_path,state)
    state.update(state='completed_matched_fits' if len(state['completed'])==state['expected_models']
                 else 'completed_matched_fits_with_coverage_gaps',finished_at_unix=time.time(),
                 completed_models=len(state['completed']),independent_holdout_and_blind_required=True,
                 precision=None,recall=None,automatic_promotion=False)
    atomic_json(status_path,state);atomic_json(root/'TERMINAL.json',state)


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--config',type=Path,required=True)
    run(p.parse_args().config)
