"""Independent normal frequency and held-out frozen-model sensitivity analysis.

Frequency is exact for tracked calls plus 'other'. Normal-only perturbations
measure score stability, not attack recall or predictive permutation importance.
"""
from __future__ import annotations
import argparse
from collections import Counter, defaultdict, deque
import json
from pathlib import Path
import subprocess
import numpy as np

from .encoding import decode_vector, schema_digest
from .features import PulseFeatureBuilder, TRACKED_SYSCALLS, SENSITIVE_IDS
from .finalize_candidate import verify_model_bundle
from .integrity import contained_artifact, sha256_file
from .model import PulseExtraTrees
from .telemetry_recovery import RecoveryTracker, SNAPSHOT_SCHEMA
from .observation_campaign import atomic_json


def pvalues(scores, calibration):
    return (len(calibration)-np.searchsorted(calibration,scores,side='left')+1)/(len(calibration)+1)


def groups(columns):
    result = {prefix: [i for i,c in enumerate(columns) if c.startswith(prefix+':')]
              for prefix in ('log_count','ratio','syscall_bin','transition_bin','rolling_mean','rolling_std')}
    result['security'] = [i for i,c in enumerate(columns) if c in ('sensitive_ratio','seccomp_denied')
                          or c.split(':')[-1] in {TRACKED_SYSCALLS[n] for n in SENSITIVE_IDS}]
    result['volume'] = [i for i,c in enumerate(columns) if c == 'log_total' or c.startswith('log_count:')]
    return result


def analyze(capture, model_dir, training_provenance, max_contexts=1024, repeats=3, training_contract=None, export_contexts=None):
    manifest, candidates, _ = verify_model_bundle(model_dir)
    provenance_hash = sha256_file(training_provenance)
    if provenance_hash != manifest['dataset_manifest_sha256']:
        raise ValueError('training provenance differs from frozen model')
    provenance = json.loads(training_provenance.read_text())
    raw_hash = sha256_file(capture)
    hashes = {manifest['dataset_sha256']}
    def walk(value):
        if isinstance(value,dict):
            for k,v in value.items():
                if isinstance(k,str) and len(k)==64: hashes.add(k)
                walk(v)
        elif isinstance(value,list):
            for v in value:walk(v)
        elif isinstance(value,str) and len(value)==64:hashes.add(value)
    walk(provenance)
    if raw_hash in hashes:raise ValueError('evaluation capture overlaps recorded training sources')
    # A sealed capture from a later registered run is still exploratory once
    # inspected; publication requires another preregistered unseen evaluation.
    subprocess.run(['sha256sum','--check','--strict','FORMAL_WORKER_SHA256SUMS'],
                   cwd=capture.parent,check=True,capture_output=True,timeout=900)
    columns = list(PulseFeatureBuilder().columns)
    schema = schema_digest(columns)
    history_n = manifest['history_windows']
    counts, totals, rows, duration = defaultdict(Counter),Counter(),Counter(),Counter()
    regimes, skipped, contexts = defaultdict(Counter),Counter(),defaultdict(list)
    histories, prev = {},{}
    profile = json.loads((capture.parent/'telemetry-recovery-profile.json').read_text())
    tracker = RecoveryTracker(profile)
    ready = False
    # Whole capture is disjoint by hash; also require it began after training.
    from datetime import datetime
    contract_path = training_contract or Path(manifest['training_contract'])
    if sha256_file(contract_path) != manifest['training_contract_sha256']:
        raise ValueError('training contract changed')
    contract = json.loads(contract_path.read_text())
    trained_after = datetime.fromisoformat(contract['created_at']).timestamp()
    with capture.open() as stream:
        for line in stream:
            r=json.loads(line)
            if r.get('schema')==SNAPSHOT_SCHEMA:
                ready=tracker.replay(r)['can_score']
                if not ready:histories.clear()
                continue
            if r.get('schema')!='sentinel-pulse-feature-v1':continue
            k=r['workload_key'];source=tuple(r.get(f) for f in ('node_name','pod_uid','container_name','cgroup_id','workload_revision'))
            eligible=(ready and r['telemetry_recovery']['eligible'] and
                      r.get('workload_revision') in manifest['approved_workload_revisions'].get(k,[]))
            if not eligible:
                skipped['ineligible_or_unapproved']+=1;histories.pop(source,None);continue
            if r['window_start']<=trained_after:raise ValueError('capture predates frozen training contract')
            if r.get('feature_schema_sha256')!=schema:raise ValueError('feature schema differs')
            exact=r['exact_counts']
            if any(type(v)is not int or v<0 for v in exact.values()) or sum(exact.values())!=r['exact_total']:
                raise ValueError('exact count mismatch')
            counts[k].update(exact);totals[k]+=r['exact_total'];rows[k]+=1
            duration[k]+=r['window_end']-r['window_start'];regimes[k][r.get('traffic_regime','unlabelled')]+=1
            v=decode_vector(r)
            if v.shape!=(249,) or not np.isfinite(v).all():raise ValueError('invalid vector')
            h=histories.setdefault(source,deque(maxlen=history_n))
            prior=prev.get(source)
            if prior and (r['window_end']-prior[0]>manifest['max_contiguous_gap_seconds'] or prior[1]!=r.get('traffic_regime')):h.clear()
            if len(h)==history_n and len(contexts[k])<max_contexts:
                contexts[k].append(np.concatenate([*h,v]))
            h.append(v);prev[source]=(r['window_end'],r.get('traffic_regime'))
    report={'schema':'sentinel-pulse-syscall-analysis-v1','capture':str(capture),'capture_sha256':raw_hash,
            'training_provenance_sha256':provenance_hash,'model_manifest_sha256':sha256_file(model_dir/'manifest.json'),
            'independent_capture_hash_and_post_training_time':True,'evidence_class':'exploratory_independent_normal',
            'skipped':dict(skipped),'attack_recall':None,'precision':None,'workloads':{}}
    group_map=groups(columns)
    if export_contexts:
        # Export exact held-out temporal contexts for separate retrained
        # ablation. No fitted parameter is derived from these test rows.
        np.savez_compressed(export_contexts, **{k:np.asarray(v,dtype=np.float32) for k,v in contexts.items()})
        report['context_archive']={'path':str(export_contexts),'sha256':sha256_file(export_contexts)}
    for k in sorted(counts):
        result={'rows':rows[k],'exact_total':totals[k],'container_seconds':duration[k],'regimes':dict(regimes[k]),
                'frequency':{n:{'count':v,'share':v/totals[k] if totals[k] else 0,
                    'per_container_second':v/duration[k] if duration[k] else 0} for n,v in counts[k].most_common()},
                'untracked_individual_frequency_available':False}
        if contexts[k]:
            m=PulseExtraTrees.load(contained_artifact(model_dir,manifest['workloads'][k]['artifact']))
            x=np.asarray(contexts[k],dtype=np.float32)
            base=m.estimator.predict_proba(x)[:,1]
            imp=m.estimator.feature_importances_.reshape(history_n+1,249).sum(axis=0)
            result['impurity_importance_descriptive']=[{'feature':columns[i],'weight':float(imp[i])}
                for i in np.argsort(imp)[::-1][:20]]
            result['normal_contexts']=len(x)
            result['raw_model_anomaly_rate']=float(np.mean(pvalues(base,m.calibration_scores)<=m.alpha))
            result['frozen_group_sensitivity']={}
            rng=np.random.default_rng(73021)
            for g,indices in group_map.items():
                indices=[i+lag*249 for lag in range(history_n+1) for i in indices]
                changes=[];rates=[]
                for _ in range(repeats):
                    # Whole 16-row context blocks are permuted; within-block
                    # structure is retained. This is sensitivity, no target y.
                    blocks=[np.arange(a,min(a+16,len(x))) for a in range(0,len(x),16)]
                    donor=np.concatenate([blocks[j] for j in rng.permutation(len(blocks))])
                    xp=x.copy();xp[:,indices]=x[donor][:,indices]
                    scores=m.estimator.predict_proba(xp)[:,1]
                    changes.append(float(np.mean(np.abs(scores-base))))
                    rates.append(float(np.mean(pvalues(scores,m.calibration_scores)<=m.alpha)))
                masked=x.copy();masked[:,indices]=np.median(x[:,indices],axis=0)
                s=m.estimator.predict_proba(masked)[:,1]
                result['frozen_group_sensitivity'][g]={'score_mae_repeats':changes,'raw_anomaly_rate_repeats':rates,
                    'median_mask_score_mae':float(np.mean(np.abs(s-base))),
                    'median_mask_raw_anomaly_rate':float(np.mean(pvalues(s,m.calibration_scores)<=m.alpha)),
                    'retrained_ablation':False,'predictive_permutation_importance':False}
        report['workloads'][k]=result
    return report


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('capture','model','training-provenance','output'):p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--max-contexts',type=int,default=1024)
    p.add_argument('--repeats',type=int,default=3)
    p.add_argument('--training-contract',type=Path)
    p.add_argument('--export-contexts',type=Path)
    a=p.parse_args()
    if a.max_contexts<32 or a.repeats<1:raise ValueError('insufficient analysis sample/repeats')
    atomic_json(a.output,analyze(a.capture,a.model,a.training_provenance,a.max_contexts,a.repeats,a.training_contract,a.export_contexts))


if __name__=='__main__':main()
