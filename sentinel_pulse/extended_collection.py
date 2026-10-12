"""Boot-persistent bounded observational capture, not a model/soak PASS gate."""
from __future__ import annotations
import argparse
import fcntl
import json
import math
import os
from pathlib import Path
import select
import signal
import subprocess
import time

from .extended_capture import ExtendedFeatureStream,CONTRACT,IDLE_CONTRACT
from .integrity import sha256_file
from .recovery_worker_probe import clean_source
from .run_500ms_blind_matrix import atomic_json


def collect(source,build,root,seconds=7200,maximum_bytes=4*1024**3,
            minimum_free_bytes=2*1024**3,proof=None,include_idle=False):
    if maximum_bytes < 1024**3 or minimum_free_bytes < 1024**3:
        raise ValueError('storage guards are below safe minimums')
    commit,files=clean_source(source)
    artifacts={name:sha256_file(build/name) for name in ['pulse_counter_extended_loader','pulse_counter_extended.bpf.o']}
    if proof is None:raise ValueError('integrated collector proof is required')
    proof_start=json.loads((proof/'START.json').read_text())
    proof_result=json.loads((proof/'RESULTS.json').read_text())
    import platform
    if (proof_result.get('valid') is not True or proof_start.get('kernel')!=platform.release()
            or any(proof_start.get('artifact_sha256',{}).get(k)!=v for k,v in artifacts.items())):
        raise ValueError('proof validity, kernel or compiled artifacts differ')
    binding=dict(schema='pulse-extended-collection-start-v1',source_commit=commit,source_files=files,
        artifacts=artifacts,telemetry_contract=IDLE_CONTRACT if include_idle else CONTRACT,interval_ms=500,
        raw_telemetry_contract=CONTRACT,include_idle_windows=include_idle,rolling_windows=10,
        kernel=platform.release(),proof_start_sha256=sha256_file(proof/'START.json'),
        proof_result_sha256=sha256_file(proof/'RESULTS.json'),
        requested_boundary_observation_seconds=seconds,maximum_bytes=maximum_bytes,
        minimum_free_bytes=minimum_free_bytes,
        normal_label='unadjudicated_observation',fit_or_promotion=False,
        frozen_v1_models_compatible=False,stops_on_alert_or_quality_gate=False)
    start=root/'START.json'
    if start.exists():
        previous=json.loads(start.read_text())
        if any(previous.get(k)!=v for k,v in binding.items()):raise ValueError('extended collection registration changed')
    else:
        atomic_json(start,dict(binding,started_at_unix=time.time()));start.chmod(0o444)
    status_path=root/'STATUS.json'
    start_sha=sha256_file(start)
    status=json.loads(status_path.read_text()) if status_path.exists() else dict(
        schema='pulse-extended-collection-status-v1',start_sha256=start_sha,
        boundary_observation_seconds=0,feature_rows=0,
        eligible_for_normal_review_rows=0,errors=0,segments=0,rows_by_workload={},skip_delta_by_workload={})
    if status.get('start_sha256')!=start_sha:raise ValueError('checkpoint registration binding differs')
    status.setdefault('capacity_pause_seconds',0.0)
    status.setdefault('capacity_pause_count',0)
    status.setdefault('maximum_bytes',maximum_bytes)
    status.setdefault('effective_maximum_bytes',maximum_bytes)
    if (root/'TERMINAL.json').exists():
        if json.loads((root/'TERMINAL.json').read_text()).get('start_sha256')!=start_sha:
            raise ValueError('terminal registration binding differs')
        return
    stopping=False
    capacity_wait_started=status.get('capacity_wait_started_at_unix')
    capacity_events=root/'capacity_events.jsonl'
    def capacity_event(event,available,at,**details):
        row=dict(event=event,at_unix=at,available_bytes=available,minimum_free_bytes=minimum_free_bytes,
                 not_normal=True,counts_toward_observation=False,**details)
        fd=os.open(capacity_events,os.O_WRONLY|os.O_CREAT|os.O_APPEND,0o640)
        try:
            os.write(fd,(json.dumps(row,separators=(',',':'))+'\n').encode())
            os.fsync(fd)
        finally:os.close(fd)
    def stop(*_):
        nonlocal stopping
        stopping=True
    signal.signal(signal.SIGTERM,stop);signal.signal(signal.SIGINT,stop)
    while not stopping and status['boundary_observation_seconds']<seconds:
        fs=os.statvfs(root);available=fs.f_bavail*fs.f_frsize
        used=sum(p.stat().st_size for p in root.rglob('*') if p.is_file())
        effective_maximum=int(status['effective_maximum_bytes'])
        if available<=minimum_free_bytes:
            now=time.time()
            if capacity_wait_started is None:
                capacity_wait_started=now
                status['capacity_wait_started_at_unix']=now
                status['capacity_pause_count']+=1
                capacity_event('paused_low_free_space',available,now)
            status.update(state='waiting_for_critical_filesystem_recovery',updated_at_unix=time.time())
            atomic_json(status_path,status);time.sleep(30);continue
        if used>=effective_maximum:
            # The preregistered byte budget is a capacity planning threshold,
            # not a reason to terminate a valid-duration observation. Expand
            # only into currently free bytes while preserving the reserve;
            # every expansion is journaled and does not count as normal data.
            now=time.time()
            expanded_maximum=used+available-minimum_free_bytes
            if expanded_maximum<=effective_maximum:
                status.update(state='waiting_for_registered_storage_budget_recovery',
                              updated_at_unix=now)
                atomic_json(status_path,status);time.sleep(30);continue
            capacity_event('expanded_byte_budget_from_current_free_space',available,now,
                           prior_maximum_bytes=effective_maximum,
                           new_maximum_bytes=expanded_maximum)
            status.update(effective_maximum_bytes=expanded_maximum,
                          state='storage_budget_expanded',updated_at_unix=now)
            atomic_json(status_path,status)
        if capacity_wait_started is not None:
            now=time.time();paused=max(0.0,now-capacity_wait_started)
            status['capacity_pause_seconds']+=paused
            status.pop('capacity_wait_started_at_unix',None)
            capacity_event('resumed_after_free_space_recovery',available,now)
            capacity_wait_started=None
            atomic_json(status_path,status)
        directory=root/'segments'/f"s{status['segments']+1:04d}"
        while directory.exists():status['segments']+=1;directory=root/'segments'/f"s{status['segments']+1:04d}"
        directory.mkdir(parents=True);status['segments']+=1
        stream=ExtendedFeatureStream(include_idle=include_idle);metadata={};mtime=None;buffer=b'';pending=[];last=None;checkpoint=time.monotonic()
        with (directory/'raw.jsonl').open('a') as raw,(directory/'features.jsonl').open('a') as features,\
                (directory/'observations.jsonl').open('a') as observations,(directory/'loader.stderr').open('ab') as err:
            proc=subprocess.Popen([str(build/'pulse_counter_extended_loader'),'--object',str(build/'pulse_counter_extended.bpf.o'),
                '--allow-cgroup-file','/run/sentinel-pulse/allowed-cgroups','--interval-ms','500'],stdout=subprocess.PIPE,stderr=err)
            reason='unknown';last_data=time.monotonic();schemas=set()
            def observation(row):
                observations.write(json.dumps(row,separators=(',',':'))+'\n');observations.flush()
            try:
                while not stopping and status['boundary_observation_seconds']<seconds:
                    if not select.select([proc.stdout],[],[],1)[0]:
                        if time.monotonic()-last_data>30:reason='loader_no_data_30s; restart this segment';break
                        continue
                    chunk=os.read(proc.stdout.fileno(),65536)
                    if not chunk:reason='loader_exited; restart this segment';break
                    last_data=time.monotonic();buffer+=chunk
                    if len(buffer)>4*1024**2:reason='oversized_loader_buffer; preserve segment and restart';break
                    while b'\n' in buffer:
                        line,buffer=buffer.split(b'\n',1);raw.write(line.decode()+'\n')
                        try:
                            row=json.loads(line)
                            if row['type']=='cgroup_snapshot_extended':pending.append(row);continue
                            if row['type']=='stat':stream.stats[row['name']]=int(row['cumulative']);continue
                            if row['type']!='snapshot_end':raise ValueError('unexpected loader record contract')
                            boundary=float(row['observed_at']);received=time.time()
                            if not math.isfinite(boundary):raise ValueError('nonfinite snapshot boundary')
                            if last is not None:
                                gap=boundary-last
                                if .35<=gap<=.8:status['boundary_observation_seconds']+=gap
                                else:observation(dict(event='cadence_gap',seconds=gap,not_normal=True,observed_at=boundary))
                            last=boundary
                            meta_path=Path('/run/sentinel-pulse/cgroups.json')
                            try:
                                updated=meta_path.stat().st_mtime_ns
                                if updated!=mtime:
                                    doc=json.loads(meta_path.read_text());metadata=doc['cgroups'];mtime=updated
                                    observation(dict(event='resolver_generation',observed_at=boundary,metadata=doc))
                                    known={int(k) for k in metadata}
                                    stream.builders={k:v for k,v in stream.builders.items() if k[-1] in known}
                                    stream.previous={k:v for k,v in stream.previous.items() if k[-1] in known}
                            except (OSError,ValueError,KeyError) as exc:
                                metadata={};mtime=None
                                observation(dict(event='resolver_unavailable',error=str(exc),not_normal=True))
                            if len(pending)!=int(row['targets']) or len(pending)!=int(row['snapshots']):
                                raise ValueError('extended target snapshot count mismatch')
                            if len({int(p['cgroup_id']) for p in pending})!=len(pending):
                                raise ValueError('duplicate cgroup snapshot at boundary')
                            for snapshot in pending:
                                try:
                                    result=stream.snapshot(snapshot,boundary,metadata,received)
                                    if result is None:continue
                                    record,schema=result
                                    if schema['feature_schema_sha256'] not in schemas:
                                        features.write(json.dumps(schema,separators=(',',':'))+'\n');schemas.add(schema['feature_schema_sha256'])
                                    features.write(json.dumps(record,separators=(',',':'))+'\n')
                                    status['feature_rows']+=1
                                    status['eligible_for_normal_review_rows']+=int(record['eligible_for_normal_review'])
                                    key=record['workload_key'];status['rows_by_workload'][key]=status['rows_by_workload'].get(key,0)+1
                                    # Explicit slot renamed by schema, never inferred as attack.
                                    from .encoding import decode_vector
                                    skipped=int(decode_vector(record)[schema['columns'].index('seccomp_skipped_or_emulated')])
                                    status['skip_delta_by_workload'][key]=status['skip_delta_by_workload'].get(key,0)+skipped
                                except (ValueError,KeyError,TypeError,OverflowError) as exc:
                                    status['errors']+=1;stream.builders.clear();stream.previous.clear()
                                    observation(dict(event='snapshot_ineligible',error=str(exc),not_normal=True))
                            pending=[]
                        except (ValueError,KeyError,TypeError,OverflowError) as exc:
                            status['errors']+=1;pending=[];stream.builders.clear();stream.previous.clear()
                            observation(dict(event='record_ineligible',error=str(exc),not_normal=True))
                    if time.monotonic()-checkpoint>=5:
                        raw.flush();features.flush();observations.flush()
                        os.fsync(raw.fileno());os.fsync(features.fileno());os.fsync(observations.fileno())
                        status.update(state='collecting',updated_at_unix=time.time(),current_segment=directory.name)
                        atomic_json(status_path,status);checkpoint=time.monotonic()
                        used=sum(p.stat().st_size for p in root.rglob('*') if p.is_file())
                        fs=os.statvfs(root)
                        if (used>=int(status['effective_maximum_bytes'])
                                or fs.f_bavail*fs.f_frsize<=minimum_free_bytes):
                            reason='capacity_guard; retain data and reassess';break
                else:reason='target_reached' if not stopping else 'system_stop_checkpoint_retained'
            finally:
                proc.terminate()
                try:proc.wait(timeout=5)
                except subprocess.TimeoutExpired:proc.kill();proc.wait()
                raw.flush();features.flush();observations.flush()
                os.fsync(raw.fileno());os.fsync(features.fileno());os.fsync(observations.fileno())
                status.update(state='segment_closed',updated_at_unix=time.time())
                atomic_json(status_path,status)
                atomic_json(directory/'TERMINAL.json',dict(reason=reason,loader_exit_status=proc.returncode,
                    raw_sha256=sha256_file(directory/'raw.jsonl'),features_sha256=sha256_file(directory/'features.jsonl')))
        if not stopping and status['boundary_observation_seconds']<seconds:time.sleep(5)
    if not stopping:
        atomic_json(root/'TERMINAL.json',dict(status,state='completed_observation',automatic_promotion=False,
            capacity_events_sha256=sha256_file(capacity_events) if capacity_events.exists() else None,
            normal_training_admission=False,finished_at_unix=time.time()))
    else:raise SystemExit(1)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('source','build','root','proof'):p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--seconds',type=int,default=7200)
    p.add_argument('--maximum-bytes',type=int,default=4*1024**3,
                   help='per-run hard storage budget; reaching it is recorded as capacity-limited')
    p.add_argument('--minimum-free-bytes',type=int,default=2*1024**3,
                   help='pause collection without closing the run when filesystem free space falls below this value')
    p.add_argument('--idle-aware',action='store_true');a=p.parse_args()
    if not 60<=a.seconds<=86400:raise ValueError('invalid observation duration')
    a.root.mkdir(parents=True,exist_ok=True)
    with (a.root/'collection.lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        try:collect(a.source,a.build,a.root,a.seconds,maximum_bytes=a.maximum_bytes,
                    minimum_free_bytes=a.minimum_free_bytes,proof=a.proof,include_idle=a.idle_aware)
        except ValueError as exc:
            atomic_json(a.root/'BLOCKED.json',dict(error=str(exc),automatic_promotion=False));raise SystemExit(65) from exc


if __name__=='__main__':main()
