"""Read-only replay audit of a completed extended capture; no normal label grant."""
from __future__ import annotations
import argparse
from collections import Counter
import fcntl
import json
import math
from pathlib import Path
import signal
import time
import numpy as np

from .encoding import decode_vector, schema_digest
from .extended_capture import ExtendedFeatureStream, CONTRACT, SCHEMA
from .integrity import sha256_file
from .recovery_worker_probe import clean_source
from .run_500ms_blind_matrix import atomic_json


def rows(path):
    with path.open() as handle:
        for line in handle:
            if not line.endswith('\n'):raise ValueError('incomplete sealed JSONL: '+str(path))
            yield json.loads(line)


def feature_rows(path):
    columns=None
    for row in rows(path):
        if row.get('schema')=='sentinel-pulse-extended-feature-schema-v1':
            if (len(row['columns'])!=249 or row['feature_schema_sha256']!=schema_digest(row['columns'])
                    or row.get('telemetry_contract')!=CONTRACT):raise ValueError('feature schema drift')
            if columns is not None and columns!=row['columns']:raise ValueError('feature columns changed')
            columns=row['columns'];continue
        if row.get('schema')!=SCHEMA or columns is None or row.get('feature_schema_sha256')!=schema_digest(columns):
            raise ValueError('unexpected stored feature contract')
        yield row


def audit_segment(directory,output,progress=None):
    seal=json.loads((directory/'TERMINAL.json').read_text())
    files={name:sha256_file(directory/name) for name in ['raw.jsonl','features.jsonl','observations.jsonl','loader.stderr']}
    if any(files[name]!=seal[name.replace('.jsonl','')+'_sha256'] for name in ['raw.jsonl','features.jsonl']):
        raise ValueError('capture segment seal mismatch')
    events=Counter();unplaced=0
    for event in rows(directory/'observations.jsonl'):
        events[event['event']]+=1
        if event['event']!='resolver_generation' and 'observed_at' not in event:unplaced+=1
    generations=(e for e in rows(directory/'observations.jsonl') if e['event']=='resolver_generation')
    next_generation=next(generations,None);metadata={};stream=ExtendedFeatureStream()
    stored=iter(feature_rows(directory/'features.jsonl'));pending=[];columns=None
    totals=Counter();workloads={};mismatches=[];last_boundary=None
    reference=output/'reference.tmp'
    with reference.open('w') as export:
        for row in rows(directory/'raw.jsonl'):
            kind=row.get('type')
            if kind=='cgroup_snapshot_extended':pending.append(row);continue
            if kind=='stat':stream.stats[row['name']]=int(row['cumulative']);continue
            if kind!='snapshot_end':raise ValueError('unexpected raw extended contract')
            boundary=float(row['observed_at'])
            if not math.isfinite(boundary):raise ValueError('nonfinite raw boundary')
            if last_boundary is not None:
                gap=boundary-last_boundary
                totals['cadence_gaps']+=int(not .35<=gap<=.8)
                if .35<=gap<=.8:totals['boundary_observation_seconds']+=gap
            last_boundary=boundary;totals['boundaries']+=1
            while next_generation is not None and next_generation['observed_at']<=boundary:
                metadata=next_generation['metadata']['cgroups'];known={int(k) for k in metadata}
                stream.builders={k:v for k,v in stream.builders.items() if k[-1] in known}
                stream.previous={k:v for k,v in stream.previous.items() if k[-1] in known}
                next_generation=next(generations,None)
            if len(pending)!=int(row['snapshots']) or len(pending)!=int(row['targets']):
                raise ValueError('raw target/snapshot count mismatch')
            if len({int(p['cgroup_id']) for p in pending})!=len(pending):raise ValueError('duplicate raw cgroup')
            for snapshot in pending:
                result=stream.snapshot(snapshot,boundary,metadata,boundary)
                if result is None:continue
                expected,schema=result;actual=next(stored,None);totals['replayed_feature_rows']+=1
                if actual is None:raise ValueError('stored feature missing for replayed snapshot')
                if columns is None:
                    columns=schema['columns'];export.write(json.dumps(schema,separators=(',',':'))+'\n')
                difference=[]
                for key in ['cgroup_id','workload_key','window_start','window_end','exact_counts','exact_total',
                            'feature_schema_sha256','history_before','node_name','pod_uid','container_name','workload_revision','collector_stats']:
                    if actual.get(key)!=expected.get(key):difference.append(key)
                vector=decode_vector(actual)
                if not np.array_equal(vector,decode_vector(expected)) or not np.isfinite(vector).all():difference.append('vector')
                lag=float(actual['emitted_at'])-boundary
                eligible=(expected['history_before']>=10 and 0<=lag<=1
                          and not any(stream.stats.get(k,0)>0 for k in ['task_state_update_fail','snapshot_projection_fail']))
                if actual.get('eligible_for_normal_review')!=eligible:difference.append('eligibility')
                if actual.get('normal_label')!='unadjudicated_observation' or actual.get('telemetry_contract')!=CONTRACT:
                    difference.append('observation_contract')
                key=actual['workload_key'];w=workloads.setdefault(key,dict(rows=0,eligible_rows=0,
                    verified_reference_rows=0,skip_delta=0,exact_total=0,exact_counts={},
                    first_end=actual['window_end'],last_end=actual['window_end'],eligible_union_seconds=0.,
                    _union_end=None,_identities=set(),_revisions=set(),_last_source={},contiguous_contexts=0))
                w['rows']+=1;w['eligible_rows']+=int(eligible);w['last_end']=actual['window_end']
                identity=(actual['node_name'],actual['pod_uid'],actual['container_name'],actual['workload_revision'],actual['cgroup_id'])
                w['_identities'].add(identity);w['_revisions'].add(actual['workload_revision'])
                if difference:
                    totals['mismatched_feature_rows']+=1
                    if len(mismatches)<20:mismatches.append(dict(workload_key=key,window_end=boundary,fields=difference))
                    w['_last_source'].pop(identity,None);continue
                w['skip_delta']+=int(vector[columns.index('seccomp_skipped_or_emulated')])
                w['exact_total']+=actual['exact_total']
                for name,value in actual['exact_counts'].items():w['exact_counts'][name]=w['exact_counts'].get(name,0)+value
                if not eligible or unplaced:
                    w['_last_source'].pop(identity,None);continue
                previous=w['_last_source'].get(identity);begin=actual['window_start'];end=actual['window_end']
                run=previous[1]+1 if previous is not None and begin==previous[0] else 1
                w['_last_source'][identity]=(end,run);w['contiguous_contexts']+=int(run>=4)
                w['eligible_union_seconds']+=max(0.,end-max(begin,w['_union_end'] if w['_union_end'] is not None else begin))
                w['_union_end']=end;w['verified_reference_rows']+=1
                export.write(json.dumps(actual,separators=(',',':'))+'\n')
            pending=[]
            if progress and totals['boundaries']%200==0:progress(dict(totals))
        # A graceful stop can preserve part of the next frame in the pipe.
        # Keep it in raw, but never turn it into a feature/exposure/normal row.
        totals['trailing_unclosed_raw_snapshots']=len(pending)
        if next(stored,None) is not None:raise ValueError('stored features remain after raw replay')
    for w in workloads.values():
        w['source_identities']=len(w.pop('_identities'));w['revisions']=sorted(w.pop('_revisions'))
        w.pop('_union_end');w.pop('_last_source')
    if any(sha256_file(directory/name)!=value for name,value in files.items()):raise ValueError('capture changed during audit')
    reference.replace(output/'reference.jsonl')
    return dict(schema='pulse-extended-segment-audit-v1',files_sha256=files,totals=dict(totals),
        observation_event_counts=dict(events),unplaced_observation_events=unplaced,workloads=workloads,
        trailing_raw_not_admitted=True,
        mismatch_examples=mismatches,all_features_replayed=totals['mismatched_feature_rows']==0 and unplaced==0,
        reference_file='reference.jsonl',reference_sha256=sha256_file(output/'reference.jsonl'),
        normal_label='unadjudicated_observation',normal_training_admission=False,
        confusion_matrix=None,precision=None,recall=None,automatic_promotion=False)


def run(capture,root,source):
    commit,files=clean_source(source)
    start=json.loads((capture/'START.json').read_text());terminal=json.loads((capture/'TERMINAL.json').read_text())
    if terminal.get('state')!='completed_observation' or terminal.get('start_sha256')!=sha256_file(capture/'START.json'):
        raise ValueError('capture not completed with bound terminal')
    # Replay exactly the mathematical contract that produced this capture.
    for name in ['extended_capture.py','features.py','encoding.py','capture.py']:
        path='sentinel_pulse/'+name
        if start['source_files'].get(path)!=files.get(path):raise ValueError('capture replay implementation drift: '+name)
    segments=sorted((capture/'segments').iterdir())
    if any(not p.is_dir() or p.is_symlink() or not p.name.startswith('s') for p in segments):raise ValueError('unsafe segment path')
    binding=dict(schema='pulse-extended-audit-start-v1',source_commit=commit,source_files=files,
        capture_start_sha256=sha256_file(capture/'START.json'),capture_terminal_sha256=sha256_file(capture/'TERMINAL.json'),
        segment_seals={p.name:sha256_file(p/'TERMINAL.json') for p in segments},normal_training_admission=False,
        automatic_promotion=False,replay_and_reference_export_only=True)
    if (root/'START.json').exists():
        previous=json.loads((root/'START.json').read_text())
        if any(previous.get(k)!=v for k,v in binding.items()):raise ValueError('audit registration drift')
    else:atomic_json(root/'START.json',dict(binding,started_at_unix=time.time()))
    result_path=root/'RESULTS.json'
    result=json.loads(result_path.read_text()) if result_path.exists() else dict(
        schema='pulse-extended-audit-results-v1',start_sha256=sha256_file(root/'START.json'),segments={})
    if result['start_sha256']!=sha256_file(root/'START.json'):raise ValueError('audit checkpoint drift')
    for segment in segments:
        output=root/segment.name;output.mkdir(exist_ok=True)
        if segment.name in result['segments']:
            existing=result['segments'][segment.name]
            if sha256_file(output/'reference.jsonl')!=existing['reference_sha256']:raise ValueError('reference artifact drift')
            for name,value in existing['files_sha256'].items():
                if sha256_file(segment/name)!=value:raise ValueError('audited capture drift')
            continue
        def progress(totals):atomic_json(root/'STATUS.json',dict(state='replaying',segment=segment.name,totals=totals,updated_at_unix=time.time()))
        result['segments'][segment.name]=audit_segment(segment,output,progress)
        atomic_json(result_path,result)
    totals=Counter()
    for s in result['segments'].values():totals.update(s['totals'])
    if totals['replayed_feature_rows']!=terminal['feature_rows']:raise ValueError('terminal feature count differs from audit')
    atomic_json(root/'TERMINAL.json',dict(state='completed_audit',totals=dict(totals),
        all_features_replayed=all(s['all_features_replayed'] for s in result['segments'].values()),
        normal_training_admission=False,automatic_promotion=False,finished_at_unix=time.time()))


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ['capture','root','source']:p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args();a.root.mkdir(parents=True,exist_ok=True)
    def stop(*_):raise KeyboardInterrupt('system stop; completed segments retained')
    signal.signal(signal.SIGTERM,stop)
    with (a.root/'audit.lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        try:run(a.capture,a.root,a.source)
        except ValueError as exc:
            atomic_json(a.root/'BLOCKED.json',dict(error=str(exc),automatic_promotion=False));raise SystemExit(65) from exc


if __name__=='__main__':main()
