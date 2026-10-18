"""Resumable 500ms full-ID capture and frozen candidate batch preview scoring.

The collector exports the full histogram, tracked counts and hash bins from
the same copied map values. No second asynchronous histogram is joined.
"""
from __future__ import annotations

import argparse
import fcntl
import json
import os
from pathlib import Path
import platform
import select
import signal
import subprocess
import time

from ..detector.candidate_policy import load_preview_policy
from ..collector.extended_capture import ExtendedFeatureStream
from ..collector.features import TRACKED_SYSCALLS
from ..detector.idle_batch import IdleBatchRuntime
from ..detector.idle_candidate import IdleCandidateScorer
from ..integrity import sha256_file
from ..common import atomic_json

# Files whose bytes must match the frozen source before a candidate may score.
FROZEN_SCORER_FILES = {
    'features.py': 'collector', 'extended_capture.py': 'collector', 'idle_candidate.py': 'detector',
    'model.py': 'detector', 'candidate_policy.py': 'detector', 'candidate_shadow.py': 'detector',
    'support_model.py': 'detector', 'extended_reference_experiment.py': 'detector', 'encoding.py': '',
}


def scorer_file(source, name):
    """Locate a scorer file in the package layout, falling back to the flat pre-2026-10-18 one."""
    nested = source/'sentinel_pulse'/FROZEN_SCORER_FILES[name]/name
    return nested if nested.is_file() else source/'sentinel_pulse'/name


class NullSink:
    """Stands in for raw.jsonl when a run registers ``write_raw_frames: false``."""
    def write(self, _): pass
    def flush(self): pass
    def __enter__(self): return self
    def __exit__(self, *_): return False


def full_delta(row, previous):
    current = {int(k): int(v) for k,v in row['full_counts'].items()}
    if any(not 0<=k<1024 or v<0 for k,v in current.items()):
        raise ValueError('invalid full-ID count')
    if sum(current.values()) != row['total']:
        raise ValueError('full-ID sum differs from Pulse total')
    for k in TRACKED_SYSCALLS:
        if current.get(k,0) != int(row['counts'][str(k)]):
            raise ValueError('explicit count differs from full-ID word')
    bins = [0]*64
    for k,v in current.items():
        bins[((k*2654435761)&0xffffffff)>>26] += v
    if bins != row['syscall_bins']:
        raise ValueError('hash bins differ from full-ID projection')
    if previous is None:
        return current, None
    if any(current.get(k,0)<v for k,v in previous.items()):
        return current, None
    return current, {str(k):v-previous.get(k,0) for k,v in current.items()
                     if v-previous.get(k,0)}


def run(config_path):
    cfg=json.loads(config_path.read_text()); root=Path(cfg['output'])
    root.mkdir(parents=True,exist_ok=True)
    lock=(root/'worker.lock').open('a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    config_hash=sha256_file(config_path)
    state_path=root/'STATUS.json'
    state=json.loads(state_path.read_text()) if state_path.exists() else dict(
        state='registered',config_sha256=config_hash,completed_seconds=0.,segments=0,frames=0,
        feature_rows=0,scored_rows=0,preview_positive=0,issues=0,started_at_unix=time.time())
    if state['config_sha256']!=config_hash:raise ValueError('worker checkpoint binding changed')
    if (root/'TERMINAL.json').exists():return
    if platform.release()!=cfg['kernel']:raise ValueError('kernel differs from validated proof')
    for path,digest in cfg['artifacts'].items():
        if sha256_file(Path(path))!=digest:raise ValueError('compiled artifact changed')
    proof=Path(cfg['proof'])
    proof_start=json.loads((proof/'START.json').read_text())
    proof_result=json.loads((proof/'RESULTS.json').read_text())
    if (not proof_result.get('valid') or proof_start['kernel']!=platform.release()
            or any(proof_start['artifact_sha256'].get(Path(p).name)!=h for p,h in cfg['artifacts'].items())):
        raise ValueError('collector proof does not bind this kernel/build')
    # Verify the frozen model's mathematical/preprocessing implementation.
    for name in FROZEN_SCORER_FILES:
        if sha256_file(scorer_file(Path(cfg['source']),name))!=sha256_file(scorer_file(Path(cfg['frozen_source']),name)):
            raise ValueError('frozen scorer/preprocessor differs: '+name)
    scorer=IdleCandidateScorer(Path(cfg['candidate']),cfg['model_hash'])
    policy=load_preview_policy(Path(cfg['policy']),scorer)
    if policy.sha256!=cfg['policy_hash']:raise ValueError('policy hash changed')
    stop=False
    def stopped(*_):
        nonlocal stop
        stop=True
    for sig in (signal.SIGTERM,signal.SIGINT):signal.signal(sig,stopped)
    while not stop and state['completed_seconds']<cfg['seconds']:
        if os.statvfs(root).f_bavail*os.statvfs(root).f_frsize<cfg['minimum_free_bytes']:
            state.update(state='waiting_for_storage_recovery',updated_at_unix=time.time())
            atomic_json(state_path,state);time.sleep(15);continue
        state['segments']+=1;segment=root/'segments'/f"s{state['segments']:05d}"
        while segment.exists():
            state['segments']+=1;segment=root/'segments'/f"s{state['segments']:05d}"
        segment.mkdir(parents=True)
        stream=ExtendedFeatureStream(include_idle=True);runtime=IdleBatchRuntime(scorer,policy)
        previous={};metadata={};mtime=None;pending=[];buffer=b'';last=None
        segment_begin=time.monotonic();last_data=segment_begin;checkpoint=segment_begin
        def issue(reason):
            state['issues']+=1
            issues.write(json.dumps(dict(at=time.time(),reason=reason,not_normal=True))+'\n');issues.flush()
        child=None
        # raw.jsonl duplicates features.jsonl (full_counts_delta + features) at ~30% of the
        # bytes; a run may skip it when shared storage is tight.
        raw_path=segment/'raw.jsonl' if cfg.get('write_raw_frames',True) else None
        with (raw_path.open('x') if raw_path else NullSink()) as raw,(segment/'features.jsonl').open('x') as features,\
             (segment/'decisions.jsonl').open('x') as decisions,(segment/'issues.jsonl').open('x') as issues,\
             (segment/'loader.log').open('x') as errors:
            schemas=set()
            try:
                child=subprocess.Popen([cfg['loader'],'--object',cfg['object'],'--allow-cgroup-file',
                    '/run/sentinel-pulse/allowed-cgroups','--interval-ms','500'],stdout=subprocess.PIPE,stderr=errors)
                while not stop and state['completed_seconds']<cfg['seconds']:
                    if not select.select([child.stdout],[],[],1)[0]:
                        if child.poll() is not None or time.monotonic()-last_data>30:
                            issue('loader_no_data_or_exit; recover_in_new_segment');break
                        continue
                    chunk=os.read(child.stdout.fileno(),65536)
                    if not chunk:issue('loader_eof');break
                    buffer+=chunk;last_data=time.monotonic()
                    if len(buffer)>8*1024**2:issue('oversized_frame');break
                    while b'\n' in buffer:
                        line,buffer=buffer.split(b'\n',1);raw.write(line.decode()+'\n')
                        try:
                            row=json.loads(line)
                            if row['type']=='cgroup_snapshot_extended':pending.append(row);continue
                            if row['type']=='stat':stream.stats[row['name']]=int(row['cumulative']);continue
                            if row['type']!='snapshot_end':raise ValueError('unexpected frame record')
                            boundary=float(row['observed_at']);now=time.time()
                            if last is not None:
                                gap=boundary-last
                                if .35<=gap<=.8:state['completed_seconds']+=gap
                                else:issue('cadence_gap');runtime.history.histories.clear();previous.clear()
                            last=boundary
                            meta=Path('/run/sentinel-pulse/cgroups.json')
                            if meta.stat().st_mtime_ns!=mtime:
                                doc=json.loads(meta.read_text());metadata=doc['cgroups'];mtime=meta.stat().st_mtime_ns
                                issues.write(json.dumps(dict(at=now,event='resolver_metadata',document=doc))+'\n')
                            if len(pending)!=int(row['targets']) or len(pending)!=int(row['snapshots']):
                                raise ValueError('frame target cardinality differs')
                            if len({p['cgroup_id'] for p in pending})!=len(pending):raise ValueError('duplicate cgroup')
                            records=[]
                            for snap in pending:
                                cg=str(snap['cgroup_id']);meta_row=metadata.get(cg,{})
                                ident=(cg,meta_row.get('pod_uid'),meta_row.get('workload_revision'),meta_row.get('container_name'))
                                current,delta=full_delta(snap,previous.get(ident));previous[ident]=current
                                result=stream.snapshot(snap,boundary,metadata,now)
                                if result is None:continue
                                record,schema=result
                                if delta is None:continue
                                if sum(delta.values())!=record['exact_total']:raise ValueError('full delta/feature total differ')
                                record['full_counts_delta']=delta
                                record['capture_segment']=segment.name;record['run_id']=cfg['run_id']
                                if schema['feature_schema_sha256'] not in schemas:
                                    features.write(json.dumps(schema,separators=(',',':'))+'\n');schemas.add(schema['feature_schema_sha256'])
                                features.write(json.dumps(record,separators=(',',':'))+'\n');records.append(record)
                            for offset in range(0,len(records),256):
                                batch=records[offset:offset+256]
                                for rec,decision in zip(batch,runtime.observe_many(batch)):
                                    decision.update({key:rec[key] for key in ('node_name','window_start','window_end',
                                        'eligible_for_normal_review','workload_key','pod_uid','container_name',
                                        'workload_revision','cgroup_id')})
                                    decision.update(run_id=cfg['run_id'],capture_segment=segment.name,
                                        preview_emitted_at=time.time(),interval_ms=500)
                                    decisions.write(json.dumps(decision,separators=(',',':'),allow_nan=False)+'\n')
                                    state['scored_rows']+=decision['status']=='candidate-raw-score-only'
                                    state['preview_positive']+=decision.get('candidate_alert_preview') is True
                            state['feature_rows']+=len(records);state['frames']+=1;pending=[]
                            # Frame flush makes each preview available without waiting for later windows.
                            features.flush();decisions.flush();raw.flush()
                        except (ValueError,KeyError,TypeError,OverflowError) as exc:
                            issue(str(exc));pending=[];stream.builders.clear();stream.previous.clear()
                            runtime.history.histories.clear();previous.clear();last=None
                    if time.monotonic()-checkpoint>=5:
                        state.update(state='running',updated_at_unix=time.time(),current_segment=segment.name,
                                     node_name=platform.node(),model_hash=cfg['model_hash'],policy_hash=cfg['policy_hash'])
                        atomic_json(state_path,state);checkpoint=time.monotonic()
                        if (time.monotonic()-segment_begin>=1800 or
                            os.statvfs(root).f_bavail*os.statvfs(root).f_frsize<cfg['minimum_free_bytes']):break
            finally:
                if child is not None:
                    child.terminate()
                    try:child.wait(timeout=5)
                    except subprocess.TimeoutExpired:child.kill();child.wait()
                for sink in (raw,features,decisions,issues):
                    sink.flush()
                    if not isinstance(sink,NullSink):os.fsync(sink.fileno())
                atomic_json(segment/'TERMINAL.json',dict(finished_at_unix=time.time(),
                    trailing_bytes=len(buffer),trailing_snapshots=len(pending),
                    seals={p.name:sha256_file(p) for p in segment.iterdir() if p.is_file()}))
                state.update(state='segment_closed',updated_at_unix=time.time());atomic_json(state_path,state)
        if not stop and state['completed_seconds']<cfg['seconds']:time.sleep(2)
    if not stop:
        state.update(state='completed_capture',finished_at_unix=time.time(),automatic_promotion=False)
        atomic_json(state_path,state);atomic_json(root/'TERMINAL.json',state)
    else:raise SystemExit(1)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--config',type=Path,required=True)
    run(parser.parse_args().config)
