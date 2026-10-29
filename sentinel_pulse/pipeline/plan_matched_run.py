"""Create a prospective matched run; the resulting JSON is immutable input.

Profiles pin the candidate, preview policy, attack fixture and run length:
``pulse-soak-baseline`` is the original 48 h frozen-candidate run, ``pulse-live-recalibrated`` the
recalibrated candidate + policy-1win-a3 with benign-exec controls; ``custom`` takes every value from the command line.
"""
import argparse
import json
from pathlib import Path
import random
import re
import subprocess
import time

from ..integrity import sha256_file

PROFILES={
    'pulse-soak-baseline':dict(candidate='/mnt/sentinel-pulse-archive/runtime-f95867d-20261012/model-bundle',
        model_hash='747c4eed2a9a74321d0ac3b716c201c449f946665252baa1ca314b1f18278a08',
        policy='sentinel_pulse/protocol/idle-aware-candidate-preview-policy-c1.json',
        policy_hash='fd0be94a4ca7f2cd64b97bf5c7dc074763405f821ab346e8e19bb5975d10f401',
        fixture='testbed/attack/runtime_attack_blind_b1.c',seconds=172800,
        benign_exec_control=False,write_raw_frames=True,fast_scoring=False),
    # 24 h without raw.jsonl: the 48 h pulse-soak-baseline layout (~4.9 GB/h) no longer fits the NFS share.
    'pulse-live-recalibrated':dict(candidate='/mnt/sentinel-pulse-archive/runtime-recal-c1-20261018/model-bundle',
        model_hash='ec72d9ea22af7d84ac2e8567e19205f121498ad11e48a9b2ef673697f5843cd4',
        policy='sentinel_pulse/protocol/policy-1win-a3.json',
        policy_hash='f61073512035dad4177b0fcce518f6a4b452322250b28b8a563605c2f0a8c9cb',
        fixture='testbed/attack/runtime_attack_with_benign_control.c',seconds=86400,
        benign_exec_control=True,write_raw_frames=False,fast_scoring=False),
}
WORKERS={'10.1.16.237':'k8s-worker1.local','10.1.16.238':'k8s-worker4.local','10.1.16.239':'k8s-worker3.local'}


PEER_PORT = 9479


def plan(source,root,run_id,smoke=False,profile='pulse-soak-baseline',frozen_source=None,custom=None,rates=(6,12,24),
         final_system=None,recalibration=None):
    if not re.fullmatch('[a-z0-9-]{3,60}',run_id):raise ValueError('unsafe run id')
    # custom: every pinned value comes from the command line (later runs need no code change)
    spec=dict(custom) if profile=='custom' else PROFILES[profile]
    candidate=Path(spec['candidate'])
    policy=source/spec['policy']
    exec_policy=source/'testbed/k8s/tetragon-sentinel-pulse-exec-provenance.yaml'
    if sha256_file(candidate/'CANDIDATE_MANIFEST.json')!=spec['model_hash'] or sha256_file(policy)!=spec['policy_hash']:
        raise ValueError('candidate or preview policy differs')
    keys=sorted(json.loads((candidate/'CANDIDATE_MANIFEST.json').read_text())['workloads'])
    if len(keys)!=21:raise ValueError('expected 21 frozen workload keys')
    root.mkdir(parents=True,exist_ok=False)
    binary=root/'runtime-attack-development'
    subprocess.run(['gcc','-O2','-Wall','-Wextra','-Werror','-static',
        str(source/spec['fixture']),'-o',str(binary)],check=True)
    binary.chmod(0o555)
    header=Path('/usr/include/x86_64-linux-gnu/asm/unistd_64.h')
    native=[int(value) for value in re.findall(r'^#define __NR_\w+\s+(\d+)$',header.read_text(),re.M)]
    cfg=dict(run_id=run_id,profile=profile,source=str(source),
        frozen_source=str(frozen_source or '/mnt/sentinel-pulse-archive/runtime-2c1a72d-20261013/source'),
        candidate=str(candidate),model_hash=spec['model_hash'],policy=str(policy),policy_hash=spec['policy_hash'],
        exec_provenance_policy=str(exec_policy),exec_provenance_policy_sha256=sha256_file(exec_policy),
        seconds=90 if smoke else spec['seconds'],minimum_free_bytes=4*1024**3,workload_keys=keys,
        campaign_output=str(root/'pulse-development-matrix'),study_output=str(root/'syscall-matched-study'),
        traffic_output=str(root/'traffic'),binary=str(binary),binary_hash=sha256_file(binary),
        fixture_source=spec['fixture'],benign_exec_control=spec['benign_exec_control'],
        write_raw_frames=spec['write_raw_frames'],fast_scoring=spec.get('fast_scoring',False),
        native_syscall_ids=sorted(set(native)),native_syscall_header=dict(path=str(header),sha256=sha256_file(header)),
        created_at=time.time(),source_commit=subprocess.check_output(['git','-C',str(source),'rev-parse','HEAD'],text=True).strip(),
        matched_observable='500ms full-ID + 249 baseline + transitions + rolling10 + history3 + tree/support',
        fresh_blind=False,automatic_promotion=False,quality_expectations=dict(precision=.95,recall=.95,
        control_positive_rate=.05,kernel_to_preview_p95_seconds=2.,expected_only=True),
        zero_alert_gate=False,stop_on_miss=False,stop_on_false_positive=False)
    start=time.time()+180
    cfg.update(selection_start=start,selection_seconds=5400,selection_end=start+5400,
               attack_not_before=start+5400+120)
    cfg['workers']={host:dict(node_name=node,output=str(root/'workers'/node),
        loader='/home/dat/pulse-matched-20261015/build/pulse_counter_extended_loader',
        object='/home/dat/pulse-matched-20261015/build/pulse_counter_extended.bpf.o',
        proof='/home/dat/pulse-matched-20261015/proof') for host,node in WORKERS.items()}
    # evidence discount (policy rule key evidence_discount): every worker serves its window masks on PEER_PORT and
    # follows the other workers (pipeline/peer_exchange.py)
    if json.loads(policy.read_text())['rule'].get('evidence_discount'):
        for host,worker in cfg['workers'].items():
            worker['peer_exchange']=dict(listen=[host,PEER_PORT],peers=[[other,PEER_PORT] for other in WORKERS if other!=host])
    # final system (ML + tripwire A1, owner 25/10): tripwire in the worker with the run's selection span as reference,
    # shared-storage writes off the scoring loop, decisions also on the worker's local disk for the alert bridge, RCA
    # and campaign, and the benign-exec control from its own file name
    if final_system:
        if not all('peer_exchange' in w for w in cfg['workers'].values()):
            raise ValueError('tripwire needs the peer exchange of the evidence discount')
        exec_set=Path(final_system['exec_set'])
        cfg['tripwire']=dict(exec_set=str(exec_set),exec_set_sha256=sha256_file(exec_set),
                             reference_span=[cfg['selection_start'],cfg['selection_end']],grace_seconds=60.)
        cfg['async_shared_writes']=True
        cfg['benign_binary_distinct']=True
        for worker in cfg['workers'].values():
            worker['stream_root']=str(Path(final_system['stream_root'])/run_id)
    # rolling calibration in the worker (pipeline/live_recalibration.py): score buffer on the worker's local disk,
    # finished hours copied under the run root for the other workers; the campaign's intervals optionally left out
    if recalibration:
        if not final_system:raise ValueError('live recalibration needs the local stream root of the final system')
        cfg['recalibration']=dict(shared=str(root/'score-buffer-shared'),window_hours=recalibration['window_hours'],
            refresh_hours=recalibration['refresh_hours'],publish_delay_seconds=60,refresh_delay_seconds=300,
            minimum_examples=1200,keep_shared_hours=48,**({'exclude_intervals':cfg['campaign_output']+'/INTERVALS.jsonl'}
                                     if recalibration.get('exclude_campaign') else {}))
        for worker in cfg['workers'].values():
            worker['score_buffer']=dict(path=worker['stream_root']+'/score-buffer',retention_hours=recalibration['window_hours']+2)
    scenarios=['anonymous_mprotect_churn','child_ptrace_handshake','invalid_setns_burst',
               'seccomp_api_probe','execveat_resolution_probe']
    cfg['schedule']=[dict(workload_key=key,workload_controller=key.split('/',1)[1].split(':')[0],
                         scenario=scenario,rate_per_second=rate,seed=seed)
        for key in keys for scenario in scenarios for rate in rates for seed in (61501,)]   # G4: --attack-rates 1,3,6
    random.Random(20261015).shuffle(cfg['schedule'])
    cfg['traffic_schedule']=[]
    t=start
    for seconds in (756,324):
        for regime in ('steady','toolmix','peak','burst','recovery'):
            cfg['traffic_schedule'].append(dict(start=t,end=t+seconds,regime=regime));t+=seconds
    cfg['traffic_schedule'].append(dict(start=t,end=t+86400,regime='steady'))
    config=root/'CONFIG.json'
    config.write_text(json.dumps(cfg,indent=2)+'\n');config.chmod(0o444)
    print(config)


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for key in ('source','root'):p.add_argument('--'+key,type=Path,required=True)
    p.add_argument('--run-id',required=True);p.add_argument('--smoke',action='store_true')
    p.add_argument('--profile',choices=sorted(PROFILES)+['custom'],default='pulse-soak-baseline')
    p.add_argument('--frozen-source',type=Path,help='source snapshot whose scorer bytes the worker must match')
    for key in ('candidate','model-hash','policy','policy-hash','fixture'):p.add_argument('--'+key)
    p.add_argument('--seconds',type=int,default=86400)
    for key in ('benign-exec-control','no-raw-frames','fast-scoring'):p.add_argument('--'+key,action='store_true')
    p.add_argument('--attack-rates',default='6,12,24',help='fixture attack rates per second (1-100), comma-separated')
    p.add_argument('--tripwire-exec-set',type=Path,help='final system: tripwire A1 in the worker with this frozen exec set')
    p.add_argument('--stream-root',default='/var/lib/sentinel-pulse-live',help='final system: local decision copy on each worker')
    p.add_argument('--recalibration',help='rolling-W-R: every R hours recalibrate on the preceding W hours of all workers')
    p.add_argument('--recalibration-exclude-campaign',action='store_true',help="leave the campaign's intervals out of it")
    a=p.parse_args()
    rates=tuple(int(x) for x in a.attack_rates.split(','))
    if not rates or not all(1<=r<=100 for r in rates):p.error('attack rates must be 1-100 per second')
    custom=None
    if a.profile=='custom':
        if not all((a.candidate,a.model_hash,a.policy,a.policy_hash,a.fixture)):
            p.error('custom profile needs --candidate --model-hash --policy --policy-hash --fixture')
        custom=dict(candidate=a.candidate,model_hash=a.model_hash,policy=a.policy,policy_hash=a.policy_hash,
                    fixture=a.fixture,seconds=a.seconds,benign_exec_control=a.benign_exec_control,
                    write_raw_frames=not a.no_raw_frames,fast_scoring=a.fast_scoring)
    final=dict(exec_set=a.tripwire_exec_set,stream_root=a.stream_root) if a.tripwire_exec_set else None
    recal=None
    if a.recalibration:
        m=re.fullmatch(r'rolling-(\d+)-(\d+)',a.recalibration)
        if not m:p.error('recalibration must be rolling-W-R')
        recal=dict(window_hours=int(m[1]),refresh_hours=int(m[2]),exclude_campaign=a.recalibration_exclude_campaign)
    plan(a.source,a.root,a.run_id,a.smoke,a.profile,a.frozen_source,custom,rates,final,recal)
