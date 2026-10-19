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


def plan(source,root,run_id,smoke=False,profile='pulse-soak-baseline',frozen_source=None,custom=None):
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
    scenarios=['anonymous_mprotect_churn','child_ptrace_handshake','invalid_setns_burst',
               'seccomp_api_probe','execveat_resolution_probe']
    cfg['schedule']=[dict(workload_key=key,workload_controller=key.split('/',1)[1].split(':')[0],
                         scenario=scenario,rate_per_second=rate,seed=seed)
        for key in keys for scenario in scenarios for rate in (6,12,24) for seed in (61501,)]
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
    a=p.parse_args()
    custom=None
    if a.profile=='custom':
        if not all((a.candidate,a.model_hash,a.policy,a.policy_hash,a.fixture)):
            p.error('custom profile needs --candidate --model-hash --policy --policy-hash --fixture')
        custom=dict(candidate=a.candidate,model_hash=a.model_hash,policy=a.policy,policy_hash=a.policy_hash,
                    fixture=a.fixture,seconds=a.seconds,benign_exec_control=a.benign_exec_control,
                    write_raw_frames=not a.no_raw_frames,fast_scoring=a.fast_scoring)
    plan(a.source,a.root,a.run_id,a.smoke,a.profile,a.frozen_source,custom)
