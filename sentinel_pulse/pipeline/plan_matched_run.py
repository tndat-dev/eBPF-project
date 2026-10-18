"""Create a prospective matched run; the resulting JSON is immutable input."""
import argparse
import json
from pathlib import Path
import random
import re
import subprocess
import time

from ..integrity import sha256_file

MODEL_HASH='747c4eed2a9a74321d0ac3b716c201c449f946665252baa1ca314b1f18278a08'
POLICY_HASH='fd0be94a4ca7f2cd64b97bf5c7dc074763405f821ab346e8e19bb5975d10f401'
WORKERS={'10.1.16.237':'k8s-worker1.local','10.1.16.238':'k8s-worker4.local','10.1.16.239':'k8s-worker3.local'}


def plan(source,root,run_id,smoke=False):
    if not re.fullmatch('[a-z0-9-]{3,60}',run_id):raise ValueError('unsafe run id')
    root.mkdir(parents=True,exist_ok=False)
    candidate=Path('/mnt/sentinel-pulse-archive/runtime-f95867d-20261012/model-bundle')
    policy=source/'sentinel_pulse/protocol/idle-aware-candidate-preview-policy-c1.json'
    exec_policy=source/'testbed/k8s/tetragon-sentinel-pulse-exec-provenance.yaml'
    if sha256_file(candidate/'CANDIDATE_MANIFEST.json')!=MODEL_HASH or sha256_file(policy)!=POLICY_HASH:
        raise ValueError('candidate or preview policy differs')
    keys=sorted(json.loads((candidate/'CANDIDATE_MANIFEST.json').read_text())['workloads'])
    if len(keys)!=21:raise ValueError('expected 21 frozen workload keys')
    binary=root/'runtime-attack-development'
    subprocess.run(['gcc','-O2','-Wall','-Wextra','-Werror','-static',
        str(source/'testbed/attack/runtime_attack_blind_b1.c'),'-o',str(binary)],check=True)
    binary.chmod(0o555)
    header=Path('/usr/include/x86_64-linux-gnu/asm/unistd_64.h')
    native=[int(value) for value in re.findall(r'^#define __NR_\w+\s+(\d+)$',header.read_text(),re.M)]
    cfg=dict(run_id=run_id,source=str(source),frozen_source='/mnt/sentinel-pulse-archive/runtime-2c1a72d-20261013/source',
        candidate=str(candidate),model_hash=MODEL_HASH,policy=str(policy),policy_hash=POLICY_HASH,
        exec_provenance_policy=str(exec_policy),exec_provenance_policy_sha256=sha256_file(exec_policy),
        seconds=90 if smoke else 172800,minimum_free_bytes=4*1024**3,workload_keys=keys,
        campaign_output=str(root/'pulse-development-matrix'),study_output=str(root/'syscall-matched-study'),
        traffic_output=str(root/'traffic'),binary=str(binary),binary_hash=sha256_file(binary),
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
    a=p.parse_args();plan(a.source,a.root,a.run_id,a.smoke)
