"""Queued reference-only ExtraTrees/support fit; never a production normal claim."""
from __future__ import annotations
import argparse
from collections import defaultdict
import fcntl
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import pickle
import platform
import signal
import time
import numpy as np
from .encoding import decode_vector
from .integrity import sha256_file
from .model import PulseExtraTrees
from .support_model import PulseSupportEnsemble
from .recovery_worker_probe import clean_source
from .run_500ms_blind_matrix import atomic_json

WORKERS=('10.1.16.237','10.1.16.238','10.1.16.239')
AUDIT='/var/lib/sentinel-pulse-extended-audit-r2-c1-20261008'


class PulseExtendedReferenceTree(PulseExtraTrees):
    """Explicit global temporal partitions, not per-replica fractional split."""
    def _split_sequences(self,partitions,train_fraction):
        parts={}
        dim=None
        for phase in ('train','calibration'):
            xs=[];ys=[]
            for sequence in partitions[phase]:
                if len(sequence)<=self.history:continue
                array=np.asarray(sequence,dtype=np.float32)
                if array.ndim!=2 or not np.isfinite(array).all():raise ValueError('invalid reference sequence')
                if dim is None:dim=array.shape[1]
                if array.shape[1]!=dim:raise ValueError('reference feature dimension changed')
                x,y=self._examples(array);xs.append(x);ys.append(y)
            if not xs:raise ValueError('insufficient reference contexts: '+phase)
            parts[phase]=(np.concatenate(xs),np.concatenate(ys))
        tx,ty=parts['train'];cx,cy=parts['calibration']
        if len(tx)<100:raise ValueError('insufficient reference training contexts')
        return tx,ty,cx,cy,dim


def phase_for(begin,end,cut1,cut2,embargo=2.):
    if end<cut1-embargo:return 'train'
    if begin>cut1+embargo and end<cut2-embargo:return 'calibration'
    if begin>cut2+embargo:return 'holdout'
    return None


def partitions_for(path,cut1,cut2):
    groups=defaultdict(lambda:defaultdict(list));last={};counts=defaultdict(int)
    with path.open() as f:
        for line in f:
            row=json.loads(line);begin=float(row['window_start']);end=float(row['window_end'])
            phase=phase_for(begin,end,cut1,cut2)
            identity=(row['node_name'],row['pod_uid'],row['container_name'],row['workload_revision'],row['cgroup_id'])
            if phase is None:last.pop(identity,None);counts['embargo']+=1;continue
            prior=last.get(identity);sequence_key=(identity,phase)
            if prior is None or prior[:2]!=(begin,phase):
                groups[phase][sequence_key].append([])
            groups[phase][sequence_key][-1].append(decode_vector(row));last[identity]=(end,phase)
            counts[phase]+=1
    return {phase:[np.stack(seq) for seqs in groups[phase].values() for seq in seqs]
            for phase in ('train','calibration','holdout')},dict(counts)


def fetch_inputs(root,credential,known_hosts):
    import paramiko
    if credential.stat().st_mode&0o077:raise ValueError('SSH credential is not private')
    password=credential.read_text().strip();inputs=root/'inputs';inputs.mkdir(exist_ok=True)
    reports={};paths=[]
    for host in WORKERS:
        client=paramiko.SSHClient();client.load_system_host_keys(str(known_hosts))
        try:
            client.connect(host,username='dat',password=password,timeout=8,auth_timeout=8,
                           banner_timeout=8,look_for_keys=False,allow_agent=False)
            with client.open_sftp() as sftp:
                def read(name):
                    with sftp.open(AUDIT+'/'+name) as f:return json.loads(f.read())
                try:terminal=read('TERMINAL.json')
                except OSError:return None
                if terminal.get('state')!='completed_audit':return None
                report=read('RESULTS.json');reports[host]=report
                for segment,data in report['segments'].items():
                    if not segment.startswith('s') or not segment[1:].isdigit():raise ValueError('unsafe audit segment')
                    dest=inputs/(host+'-'+segment+'.jsonl')
                    if not dest.exists() or sha256_file(dest)!=data['reference_sha256']:
                        temp=dest.with_suffix('.tmp');sftp.get(AUDIT+'/'+segment+'/reference.jsonl',str(temp))
                        if sha256_file(temp)!=data['reference_sha256']:raise ValueError('reference download checksum differs')
                        temp.replace(dest)
                    paths.append(dict(path=str(dest),sha256=data['reference_sha256'],host=host,segment=segment))
        finally:client.close()
    return dict(reports=reports,reference_files=paths)


def build_index(root,inputs):
    if (root/'INDEX.json').exists():
        index=json.loads((root/'INDEX.json').read_text())
        for item in index['workloads'].values():
            if sha256_file(root/item['file'])!=item['sha256']:raise ValueError('reference index changed')
        return index
    directory=root/'workloads';directory.mkdir(exist_ok=True);handles={};counts=defaultdict(int);columns=None
    minimum=float('inf');maximum=-minimum
    try:
        for item in inputs['reference_files']:
            with Path(item['path']).open() as f:
                for line in f:
                    row=json.loads(line)
                    if row['schema']=='sentinel-pulse-extended-feature-schema-v1':
                        if columns is not None and columns!=row['columns']:raise ValueError('reference schema differs by node')
                        columns=row['columns'];continue
                    if (row['schema']!='sentinel-pulse-extended-feature-v1' or row.get('normal_label')!='unadjudicated_observation'
                            or row.get('eligible_for_normal_review') is not True):raise ValueError('unexpected reference label or admission')
                    key=row['workload_key']
                    if key not in handles:handles[key]=(directory/(hashlib.sha256(key.encode()).hexdigest()+'.tmp')).open('w')
                    handles[key].write(line);counts[key]+=1
                    minimum=min(minimum,row['window_start']);maximum=max(maximum,row['window_end'])
    finally:
        for f in handles.values():f.close()
    if not handles or len(columns or [])!=249:raise ValueError('empty or incorrect reference index')
    index=dict(columns=columns,global_start=minimum,global_end=maximum,
        train_cut=minimum+(maximum-minimum)*.7,holdout_cut=minimum+(maximum-minimum)*.85,
        embargo_seconds=2.,workloads={})
    for key,handle in handles.items():
        path=Path(handle.name);target=path.with_suffix('.jsonl');path.replace(target)
        index['workloads'][key]=dict(file=str(target.relative_to(root)),rows=counts[key],sha256=sha256_file(target))
    atomic_json(root/'INDEX.json',index);return index


def run(source,root,credential,known_hosts):
    commit,files=clean_source(source)
    while not (root/'INPUTS.json').exists():
        try:inputs=fetch_inputs(root,credential,known_hosts)
        except (OSError,EOFError) as exc:
            inputs=None;atomic_json(root/'QUEUE.json',dict(state='waiting_for_worker_audits',error=type(exc).__name__,at_unix=time.time()))
        if inputs is None:
            atomic_json(root/'QUEUE.json',dict(state='waiting_for_worker_audits',at_unix=time.time()));time.sleep(30);continue
        atomic_json(root/'INPUTS.json',inputs)
    inputs=json.loads((root/'INPUTS.json').read_text())
    for item in inputs['reference_files']:
        if sha256_file(Path(item['path']))!=item['sha256']:raise ValueError('frozen reference input changed')
    binding=dict(schema='pulse-extended-reference-start-v1',source_commit=commit,source_files=files,
        input_manifest_sha256=sha256_file(root/'INPUTS.json'),reference_label='unadjudicated_observation',
        attack_data_used_for_fit=False,global_time_split=[.7,.15,.15],embargo_seconds=2.,
        history_windows=3,feature_dimensions=249,trees=192,max_depth=16,min_samples_leaf=4,
        seed=73021,interval_budget=.05,horizon_windows=30,automatic_promotion=False,
        normal_training_admission=False,serving_manifest_compatible=False,
        software=dict(python=platform.python_version(),numpy=np.__version__,
                      sklearn=importlib.metadata.version('scikit-learn')))
    if (root/'START.json').exists():
        previous=json.loads((root/'START.json').read_text())
        if any(previous.get(k)!=v for k,v in binding.items()):raise ValueError('reference experiment binding changed')
    else:atomic_json(root/'START.json',dict(binding,started_at_unix=time.time()))
    index=build_index(root,inputs);path=root/'RESULTS.json'
    result=json.loads(path.read_text()) if path.exists() else dict(start_sha256=sha256_file(root/'START.json'),workloads={})
    if result['start_sha256']!=sha256_file(root/'START.json'):raise ValueError('reference checkpoint changed')
    for key,item in index['workloads'].items():
        if key in result['workloads']:
            prior=result['workloads'][key]
            if 'artifact' in prior and sha256_file(root/prior['artifact'])!=prior['artifact_sha256']:raise ValueError('candidate artifact changed')
            continue
        atomic_json(root/'STATUS.json',dict(state='fitting_reference',workload=key,completed=len(result['workloads']),expected=len(index['workloads']),at_unix=time.time()))
        try:
            partitions,counts=partitions_for(root/item['file'],index['train_cut'],index['holdout_cut'])
            base=PulseExtendedReferenceTree(alpha=.001)
            fit=base.fit_sequences(partitions)
            tx,ty,cx,cy,_=base._split_sequences(partitions,.7)
            ensemble=PulseSupportEnsemble(base);support=ensemble.fit_support(ty,cy)
            artifact='model-'+hashlib.sha256(key.encode()).hexdigest()+'.pkl'
            with (root/(artifact+'.tmp')).open('wb') as f:
                pickle.dump(ensemble,f,pickle.HIGHEST_PROTOCOL);f.flush();os.fsync(f.fileno())
            (root/(artifact+'.tmp')).replace(root/artifact)
            holdout_count=raw=tree_flags=0
            for sequence in partitions['holdout']:
                if len(sequence)<=3:continue
                x,y=base._examples(sequence);scored=ensemble.predict_contexts(base._contexts(x,y))
                holdout_count+=len(y);raw+=int(scored['anomalous'].sum());tree_flags+=int((scored['tree_p']<=base.alpha).sum())
            row=dict(state='fitted_exploratory_reference',artifact=artifact,artifact_sha256=sha256_file(root/artifact),
                fit=fit,support=support,partition_rows=counts,holdout_contexts=holdout_count,
                raw_holdout_reference_flags=raw,tree_holdout_reference_flags=tree_flags,
                precision=None,recall=None,false_positive_rate=None,kernel_to_alert_seconds=None,
                model_serving_compatible=False,normal_label_adjudicated=False)
            del partitions,tx,ty,cx,cy,base,ensemble
        except ValueError as exc:
            row=dict(state='insufficient_or_invalid_reference',error=str(exc),precision=None,recall=None)
        result['workloads'][key]=row;atomic_json(path,result)
    if (root/'TERMINAL.json').exists():return
    atomic_json(root/'TERMINAL.json',dict(state='completed_reference_experiment',
        completed=len(result['workloads']),fitted=sum('artifact' in r for r in result['workloads'].values()),
        normal_training_admission=False,automatic_promotion=False,finished_at_unix=time.time()))


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ['source','root','credential','known-hosts']:p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args();a.root.mkdir(parents=True,exist_ok=True)
    def stop(*_):raise KeyboardInterrupt('system stop; reference checkpoints retained')
    signal.signal(signal.SIGTERM,stop)
    with (a.root/'experiment.lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        try:run(a.source,a.root,a.credential,a.known_hosts)
        except ValueError as exc:
            atomic_json(a.root/'BLOCKED.json',dict(error=str(exc),automatic_promotion=False));raise SystemExit(65) from exc


if __name__=='__main__':main()
