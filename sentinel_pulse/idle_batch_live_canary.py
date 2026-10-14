"""Bounded live timing canary for the frozen model and workload batching.

Consumes complete 500 ms kernel-counter frames directly. Keeps raw/features/
decisions; measures feature-window-end to score, not kernel-to-alert.
"""
from __future__ import annotations

import argparse
from collections import Counter
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import select
import signal
import subprocess
import time
import warnings

import numpy as np
from sklearn.exceptions import InconsistentVersionWarning

from .candidate_policy import CandidatePreviewPolicy
from .extended_capture import ExtendedFeatureStream
from .idle_batch import IdleBatchRuntime
from .idle_candidate import IdleCandidateScorer
from .integrity import sha256_file, verify_sha256
from .syscall_histogram_pilot import atomic_json


def percentiles(values):
    return None if not values else dict(samples=len(values), p50=float(np.percentile(values,50)),
        p95=float(np.percentile(values,95)), p99=float(np.percentile(values,99)), maximum=max(values), minimum=min(values))


def run(source, frozen_source, build, proof, candidate, model_hash, policy_path, policy_hash, benchmark, output, seconds=300):
    verified=json.loads((benchmark/'TERMINAL.json').read_text())
    if (verified['state']!='completed_equivalence_benchmark'
            or verified['binding']['model_manifest_sha256']!=model_hash
            or verified['binding']['batch_source_sha256']!=sha256_file(source/'sentinel_pulse/idle_batch.py')):
        raise ValueError('completed matching scalar/batch equivalence required')
    if output.exists(): raise FileExistsError('canary already has evidence')
    verify_sha256(candidate/'CANDIDATE_MANIFEST.json',model_hash);verify_sha256(policy_path,policy_hash)
    manifest=json.loads((candidate/'CANDIDATE_MANIFEST.json').read_text())
    software=dict(python=platform.python_version(),numpy=np.__version__,sklearn=importlib.metadata.version('scikit-learn'))
    if software!=manifest['software']:raise ValueError('runtime software differs from frozen model')
    core={}
    for name in ('model.py','features.py','extended_capture.py','idle_candidate.py','candidate_shadow.py',
                 'candidate_policy.py','support_model.py','encoding.py','extended_reference_experiment.py'):
        core[name]=sha256_file(source/'sentinel_pulse'/name)
        if core[name]!=sha256_file(frozen_source/'sentinel_pulse'/name):raise ValueError('frozen core differs: '+name)
    proof_start=json.loads((proof/'START.json').read_text());proof_result=json.loads((proof/'RESULTS.json').read_text())
    artifacts={name:sha256_file(build/name) for name in ('pulse_counter_extended_loader','pulse_counter_extended.bpf.o')}
    if (not proof_result.get('valid') or proof_start['kernel']!=platform.release()
            or any(proof_start['artifact_sha256'].get(k)!=v for k,v in artifacts.items())):
        raise ValueError('kernel/BPF proof differs')
    with warnings.catch_warnings():
        warnings.simplefilter('error',InconsistentVersionWarning)
        scorer=IdleCandidateScorer(candidate,model_hash)
    policy=CandidatePreviewPolicy.load(policy_path,scorer);runtime=IdleBatchRuntime(scorer,policy)
    stream=ExtendedFeatureStream(include_idle=True)
    output.mkdir(parents=True)
    atomic_json(output/'START.json',dict(schema='pulse-idle-batch-timing-canary-v1',registered_at_unix=time.time(),
        seconds=seconds,interval_ms=500,model_manifest_sha256=model_hash,policy_sha256=policy_hash,
        benchmark_terminal_sha256=sha256_file(benchmark/'TERMINAL.json'),software=software,unchanged_core_sha256=core,
        artifacts=artifacts,runtime_sha256=sha256_file(Path(__file__)),batch_source_sha256=sha256_file(source/'sentinel_pulse/idle_batch.py'),
        output_mode='shadow_preview_only',attack_injection=False,model_or_threshold_changed=False,
        accuracy_claim=False,kernel_to_alert=None,automatic_promotion=False))
    statuses,issues=Counter(),Counter();ages=[];frame_times=[];batch_times=[];contexts=Counter();previews=Counter()
    stopping=False
    def stop(*_):
        nonlocal stopping
        stopping=True
    for sig in (signal.SIGTERM,signal.SIGINT):signal.signal(sig,stop)
    child=None;started=time.monotonic();frames=0;state='interrupted_timing_canary';pending=[];buffer=b'';previous=None
    raw_path=output/'raw.jsonl';feature_path=output/'features.jsonl';decision_path=output/'decisions.jsonl'
    issue_path=output/'issues.jsonl'
    with raw_path.open('x') as raw, feature_path.open('x') as features, decision_path.open('x') as decisions, \
            (output/'loader.log').open('x') as log, issue_path.open('x') as issue_log:
        try:
            child=subprocess.Popen([str(build/'pulse_counter_extended_loader'),'--object',str(build/'pulse_counter_extended.bpf.o'),
                '--allow-cgroup-file','/run/sentinel-pulse/allowed-cgroups','--interval-ms','500'],stdout=subprocess.PIPE,stderr=log)
            schemas=set();metadata={};mtime=None;last_data=time.monotonic()
            while not stopping and time.monotonic()-started<seconds:
                if sum(p.stat().st_size for p in (raw_path,feature_path,decision_path))>1024**3:
                    issues['registered_one_gib_budget_reached']+=1;break
                if not select.select([child.stdout],[],[],.5)[0]:
                    if child.poll() is not None:issues['loader_exited']+=1;break
                    if time.monotonic()-last_data>30:issues['loader_no_data_30s']+=1;break
                    continue
                chunk=os.read(child.stdout.fileno(),65536)
                if not chunk:issues['loader_eof']+=1;break
                last_data=time.monotonic();buffer+=chunk
                if len(buffer)>4*1024**2:issues['oversized_raw_buffer']+=1;break
                while b'\n' in buffer:
                    line,buffer=buffer.split(b'\n',1);raw.write(line.decode()+'\n')
                    try:
                        row=json.loads(line)
                        if row['type']=='cgroup_snapshot_extended':pending.append(row);continue
                        if row['type']=='stat':stream.stats[row['name']]=int(row['cumulative']);continue
                        if row['type']!='snapshot_end':raise ValueError('unsupported raw record')
                        boundary=float(row['observed_at']);received=time.time();begin=time.perf_counter()
                        if previous is not None and not .35<=boundary-previous<=.8:issues['collector_cadence_gap']+=1
                        previous=boundary;frames+=1
                        path=Path('/run/sentinel-pulse/cgroups.json');observed_mtime=path.stat().st_mtime_ns
                        if observed_mtime!=mtime:metadata=json.loads(path.read_text())['cgroups'];mtime=observed_mtime
                        if len(pending)!=int(row['targets']) or len(pending)!=int(row['snapshots']):
                            raise ValueError('raw frame target count mismatch')
                        if len({int(p['cgroup_id']) for p in pending})!=len(pending):raise ValueError('duplicate target snapshot')
                        records=[]
                        for snapshot in pending:
                            result=stream.snapshot(snapshot,boundary,metadata,received)
                            if result is None:continue
                            record,schema=result;records.append(record)
                            if schema['feature_schema_sha256'] not in schemas:
                                features.write(json.dumps(schema,separators=(',',':'))+'\n');schemas.add(schema['feature_schema_sha256'])
                            features.write(json.dumps(record,separators=(',',':'))+'\n')
                        for start in range(0,len(records),256):
                            for decision in runtime.observe_many(records[start:start+256]):
                                decision['run_id']='pulse-idle-batch-canary-b1-20261014'
                                statuses[decision['status']]+=1
                                if decision['status']=='candidate-raw-score-only':
                                    ages.append(decision['feature_event_age_seconds']);batch_times.append(decision['batch_inference_ms'])
                                    contexts[str(decision['batch_contexts'])]+=1
                                    if decision.get('candidate_alert_preview'):previews[decision['workload_key']]+=1
                                decisions.write(json.dumps(decision,separators=(',',':'),allow_nan=False)+'\n')
                        frame_times.append((time.perf_counter()-begin)*1000);pending=[]
                        for sink in (raw,features,decisions):sink.flush()
                        if frames%10==0:
                            atomic_json(output/'STATUS.json',dict(state='running',frames=frames,statuses=dict(statuses),
                                issues=dict(issues),elapsed_seconds=time.monotonic()-started,updated_at_unix=time.time()))
                    except (ValueError,KeyError,TypeError,OverflowError,OSError) as exc:
                        issues['raw_frame_or_feature_ineligible']+=1;pending=[]
                        issue_log.write(json.dumps(dict(observed_at_unix=time.time(),frame=frames,
                            exception=type(exc).__name__,message=str(exc)[:1000]))+'\n');issue_log.flush()
                        stream.builders.clear();stream.previous.clear();runtime.history.histories.clear()
            if not stopping and time.monotonic()-started>=seconds:state='completed_timing_canary'
        finally:
            if child is not None:
                child.terminate()
                try:child.wait(timeout=5)
                except subprocess.TimeoutExpired:child.kill();child.wait()
            for sink in (raw,features,decisions,issue_log):sink.flush();os.fsync(sink.fileno())
    result=dict(state=state,finished_at_unix=time.time(),elapsed_seconds=time.monotonic()-started,frames=frames,
        statuses=dict(statuses),issues=dict(issues),preview_positive_pending_adjudication=dict(previews),
        feature_window_end_to_score_seconds=percentiles(ages),pipeline_frame_processing_ms=percentiles(frame_times),
        batch_call_ms_repeated_per_scored_row=percentiles(batch_times),scored_rows_by_batch_size=dict(contexts),
        kernel_to_alert=None,precision=None,recall=None,automatic_promotion=False,
        incomplete_trailing_snapshots=len(pending),incomplete_trailing_bytes=len(buffer),
        start_sha256=sha256_file(output/'START.json'),
        seals={p.name:sha256_file(p) for p in (raw_path,feature_path,decision_path,issue_path,output/'loader.log')})
    atomic_json(output/'STATUS.json',result);atomic_json(output/'TERMINAL.json',result)
    return result


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('source','frozen-source','build','proof','candidate','policy','benchmark','output'):
        p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--model-sha256',required=True);p.add_argument('--policy-sha256',required=True)
    a=p.parse_args()
    run(a.source,a.frozen_source,a.build,a.proof,a.candidate,a.model_sha256,a.policy,a.policy_sha256,a.benchmark,a.output)


if __name__=='__main__':main()
