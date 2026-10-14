"""Read-only distribution audit: old normal reference versus C3 selection.

Never consumes C4/holdout scores, fits models, changes thresholds, or ranks a
syscall subset. Feature mean/std differences are descriptive, not causality.
"""
import argparse
from collections import Counter
import fcntl
import json
from pathlib import Path
import time

import numpy as np

from .integrity import sha256_file,verify_sha256
from .syscall_histogram_pilot import atomic_json
from .variant_capture_audit import FAILURE_COUNTERS,decode


def merge(parts):
    result={}
    for part in parts:
        for key,row in part.items():
            d=result.setdefault(key,dict(rows=0,sum=np.zeros(249),squares=np.zeros(249)))
            d['rows']+=row['rows'];d['sum']+=row['sum'];d['squares']+=row['squares']
    return result


def input_rows(path):
    with path.open() as stream:
        for line in stream:yield json.loads(line)


def read_input(path,columns,workloads,revisions,probe=None):
    sums={};excluded=Counter();saw_schema=False
    for row in input_rows(path):
        if row['schema']=='sentinel-pulse-feature-schema-v1':
            if row['columns']!=columns:raise ValueError('feature columns differ')
            saw_schema=True;continue
        if not saw_schema or row['schema']!='sentinel-pulse-feature-v1':raise ValueError('unexpected record')
        key=row['workload_key'];reason=None
        if key not in workloads:reason='no_frozen_variant_model'
        elif row['workload_revision'] not in revisions[key]:reason='unapproved_revision'
        elif probe:
            stats=row.get('collector_stats')
            if row['window_start']<probe[0] or row['window_end']>probe[1]:reason='outside_probe'
            elif not .35<=row['window_end']-row['window_start']<=.75:reason='cadence'
            elif not isinstance(stats,dict) or any(k not in stats or stats[k]!=0 for k in FAILURE_COUNTERS):reason='integrity'
        if reason:excluded[reason]+=1;continue
        value=np.asarray(decode(row,249),dtype=np.float64)
        d=sums.setdefault(key,dict(rows=0,sum=np.zeros(249),squares=np.zeros(249)))
        d['rows']+=1;d['sum']+=value;d['squares']+=value*value
    return dict(workloads={k:dict(rows=v['rows'],sum=v['sum'].tolist(),squares=v['squares'].tolist()) for k,v in sums.items()},
        excluded=dict(excluded),history_context_admission=False)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('campaign','selection-audit','training-manifest','training-features','variant-manifest','output'):
        p.add_argument('--'+n,type=Path,required=True)
    for n in ('audit-sha256','training-sha256','variant-sha256'):p.add_argument('--'+n,required=True)
    a=p.parse_args();a.output.mkdir(parents=True,exist_ok=True)
    lock=(a.output/'run.lock').open('a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    for path,expected in ((a.selection_audit,a.audit_sha256),(a.training_manifest,a.training_sha256),
                          (a.variant_manifest,a.variant_sha256)):verify_sha256(path,expected)
    audit=json.loads(a.selection_audit.read_text());training=json.loads(a.training_manifest.read_text())
    variants=json.loads(a.variant_manifest.read_text())
    if (audit['split']!='selection' or audit['captures_verified']!=15
            or audit['variant_manifest_sha256']!=a.variant_sha256
            or audit['training_manifest_sha256']!=a.training_sha256
            or variants['training_manifest_sha256']!=a.training_sha256):raise ValueError('selection binding differs')
    binding=dict(selection_audit_sha256=a.audit_sha256,training_manifest_sha256=a.training_sha256,
        variant_manifest_sha256=a.variant_sha256,source_sha256=sha256_file(Path(__file__)),
        decoder_sha256=sha256_file(Path(__file__).with_name('variant_capture_audit.py')),
        scope='old normal dataset versus C3 selection; no holdout, model score or fitting')
    start=a.output/'START.json'
    if start.exists():
        if json.loads(start.read_text())['binding']!=binding:raise ValueError('resume source/input changed')
    else:atomic_json(start,dict(binding=binding,registered_at_unix=time.time(),no_training_or_threshold_change=True))
    columns=training['feature_columns'];workloads=set(variants['workloads'])
    revisions={k:training['approved_workload_revisions'][k] for k in workloads}
    sources=[('reference',a.training_features,training['dataset_sha256'],None)]
    for run_id,report in sorted(audit['captures'].items()):
        if Path(run_id).name!=run_id:raise ValueError('unsafe capture')
        capture=a.campaign/'selection'/run_id
        verify_sha256(capture/'TERMINAL.json',report['seals']['TERMINAL.json'])
        terminal=json.loads((capture/'TERMINAL.json').read_text())
        sources.append((run_id,capture/'features.jsonl',report['seals']['features.jsonl'],
            (terminal['probe_started_at_unix'],terminal['probe_ended_at_unix'])))
    parts={}
    for label,path,expected,probe in sources:
        verify_sha256(path,expected);checkpoint=a.output/(label+'.json')
        if checkpoint.exists():
            d=json.loads(checkpoint.read_text())
            if d['input_sha256']!=expected:raise ValueError('checkpoint input differs')
        else:
            d=read_input(path,columns,workloads,revisions,probe);verify_sha256(path,expected)
            d.update(input_sha256=expected);atomic_json(checkpoint,d)
        parts[label]=d
        atomic_json(a.output/'STATUS.json',dict(state='describing',completed_inputs=len(parts),expected_inputs=len(sources),updated_at_unix=time.time()))
    reference=merge([parts['reference']['workloads']]);selection=merge([v['workloads'] for k,v in parts.items() if k!='reference'])
    out={}
    for workload in sorted(workloads):
        if workload not in reference or workload not in selection:continue
        r,s=reference[workload],selection[workload]
        rm=r['sum']/r['rows'];sm=s['sum']/s['rows']
        rs=np.sqrt(np.maximum(0,r['squares']/r['rows']-rm*rm));ss=np.sqrt(np.maximum(0,s['squares']/s['rows']-sm*sm))
        out[workload]=dict(reference_rows=r['rows'],selection_rows=s['rows'],features=[dict(name=n,
            reference_mean=float(rm[i]),reference_std=float(rs[i]),selection_mean=float(sm[i]),
            selection_std=float(ss[i]),mean_difference=float(sm[i]-rm[i])) for i,n in enumerate(columns)])
    result=dict(state='completed_descriptive_distribution_audit',binding=binding,finished_at_unix=time.time(),
        workloads=out,holdout_used=False,fitting_performed=False,model_or_threshold_changed=False,
        limitations=['old reference includes the sealed normal training/calibration dataset, not training prefix only',
            'single-feature window moments, not full temporal context distributions',
            'differences do not prove cause of alerts or feature utility; labels remain unadjudicated'],
        start_sha256=sha256_file(start))
    atomic_json(a.output/'STATUS.json',result);atomic_json(a.output/'TERMINAL.json',result)


if __name__=='__main__':main()
