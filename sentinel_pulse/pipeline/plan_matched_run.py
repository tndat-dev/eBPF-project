"""Create a prospective matched run; the resulting JSON is immutable input.

Profiles pin the candidate, preview policy, attack fixture and run length:
``pulse-soak-baseline`` is the original 48 h frozen-candidate run, ``pulse-live-recalibrated`` the
recalibrated candidate + policy-1win-a3 with benign-exec controls; ``custom`` takes every value from the command line.
"""
# ==============================================================================================================
# plan_matched_run.py — DỰNG CONFIG.json CHO MỘT LƯỢT CHẠY (bước `plan` của scripts/launch_run.sh).
# CONFIG.json là "hợp đồng" bất biến của lượt chạy (chmod 444): mọi thành phần (worker trên 3 node, campaign, bộ
# sinh tải, RCA, bridge) chỉ đọc file này. Nó ghi lại:
#   - mã nguồn (snapshot + commit), mô hình cũ (candidate) và chính sách xem trước, đều kèm SHA-256;
#   - binary tấn công được BIÊN DỊCH NGAY TẠI ĐÂY từ fixture C (gcc -static) và băm SHA-256;
#   - thời gian: bắt đầu sau 3 phút, 90 phút "selection" đầu lượt không có trial, tấn công từ selection_end + 120 s;
#   - cấu hình worker từng node (loader, object eBPF, proof), mô hình token (MODELS.json) và các tuỳ chọn campaign;
#   - LỊCH TRIAL (schedule): 21 workload × 5 kịch bản × các tốc độ (+ trial pha loãng PAD), xáo bằng seed cố định;
#   - LỊCH TẢI (traffic_schedule): các pha steady/toolmix/peak/burst/recovery rồi steady tới hết lượt.
# Các khối "final_system", "recalibration", "evidence_discount" thuộc hệ thống cũ (ML + tripwire); lượt hiện tại
# (lidds-ml-v5 chỉ token) dùng nhánh `tokens` + `local_decisions`.
# ==============================================================================================================
import argparse
import json
from pathlib import Path
import random
import re
import subprocess
import time

from ..integrity import sha256_file

# Every pinned value of a run comes from the command line (profile "custom"): the earlier named profiles pointed at model
# bundles of finished runs that are no longer on the NFS share.
# Không còn profile dựng sẵn: mọi giá trị phải truyền qua dòng lệnh (sửa 16/11 vì profile cũ trỏ tới bundle đã xoá).
PROFILES={}
# Ba worker của cụm: IP → tên node.
WORKERS={'10.1.16.237':'k8s-worker1.local','10.1.16.238':'k8s-worker4.local','10.1.16.239':'k8s-worker3.local'}


PEER_PORT = 9479


# Hàm chính. source = snapshot mã nguồn; root = thư mục lượt chạy trên NFS (phải CHƯA tồn tại); custom = các giá trị
# ghim (candidate, policy, fixture, seconds...); tokens = cấu hình probe token và mô hình; rates = các tốc độ tấn công.
def plan(source,root,run_id,smoke=False,profile='custom',frozen_source=None,custom=None,rates=(6,12,24),
         final_system=None,recalibration=None,tokens=None,local_decisions=None):
    if not re.fullmatch('[a-z0-9-]{3,60}',run_id):raise ValueError('unsafe run id')
    # custom: every pinned value comes from the command line (later runs need no code change)
    if profile!='custom' or not custom:raise ValueError('a run needs the custom profile with every pinned value')
    if not frozen_source:raise ValueError('a run needs --frozen-source (the snapshot whose scorer bytes the worker must match)')
    spec=dict(custom)
    candidate=Path(spec['candidate'])
    policy=source/spec['policy']
    exec_policy=source/'testbed/k8s/tetragon-sentinel-pulse-exec-provenance.yaml'
    if sha256_file(candidate/'CANDIDATE_MANIFEST.json')!=spec['model_hash'] or sha256_file(policy)!=spec['policy_hash']:
        raise ValueError('candidate or preview policy differs')
    keys=sorted(json.loads((candidate/'CANDIDATE_MANIFEST.json').read_text())['workloads'])
    if len(keys)!=21:raise ValueError('expected 21 frozen workload keys')
    root.mkdir(parents=True,exist_ok=False)
    # Biên dịch fixture tấn công (testbed/attack/runtime_attack_with_benign_control.c) thành binary tĩnh, chỉ đọc.
    binary=root/'runtime-attack-development'
    subprocess.run(['gcc','-O2','-Wall','-Wextra','-Werror','-static',
        str(source/spec['fixture']),'-o',str(binary)],check=True)
    binary.chmod(0o555)
    header=Path('/usr/include/x86_64-linux-gnu/asm/unistd_64.h')
    native=[int(value) for value in re.findall(r'^#define __NR_\w+\s+(\d+)$',header.read_text(),re.M)]
    cfg=dict(run_id=run_id,profile=profile,source=str(source),
        frozen_source=str(frozen_source),
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
    # Mốc thời gian của lượt: selection 90 phút (học/kiểm normal đầu lượt, không trial), tấn công sau đó 2 phút.
    start=time.time()+180
    cfg.update(selection_start=start,selection_seconds=5400,selection_end=start+5400,
               attack_not_before=start+5400+120)
    # Mặc định worker dùng build cũ (bộ đếm); khối `tokens` ngay dưới thay bằng build token của từng node.
    cfg['workers']={host:dict(node_name=node,output=str(root/'workers'/node),
        loader='/home/dat/pulse-matched-20261015/build/pulse_counter_extended_loader',
        object='/home/dat/pulse-matched-20261015/build/pulse_counter_extended.bpf.o',
        proof='/home/dat/pulse-matched-20261015/proof') for host,node in WORKERS.items()}
    # lidds-ml-v3 token probe (tokens: build, models, v3_counts): every worker runs the token build in its own
    # directory (build/ from make tokens, proof/ from scripts/token_probe_proof.py); token models and count thresholds
    # are optional (a normal capture to fit them runs without), and are checked by sha256 in the worker
    if tokens:
        build=Path(tokens['build'])
        for worker in cfg['workers'].values():
            worker.update(loader=str(build/'build'/'pulse_counter_tokens_loader'),
                          object=str(build/'build'/'pulse_counter_tokens.bpf.o'),proof=str(build/'proof'))
        cfg['tokens']=dict(mode='grams')
        if tokens.get('models'):
            cfg['tokens']['models']=json.loads(Path(tokens['models']).read_text())
            cfg['tokens']['models_document']=dict(path=str(tokens['models']),sha256=sha256_file(Path(tokens['models'])))
        if tokens.get('gate'):cfg['tokens']['gate']=json.loads(Path(tokens['gate']).read_text())
        if tokens.get('admin_control'):cfg['admin_control']=True
        if tokens.get('admin_commands'):cfg['admin_commands']=tokens['admin_commands']
        if tokens.get('random_trial_order'):cfg['random_trial_order']=True
        if tokens.get('lotl_attack'):cfg['lotl_attack']=True
        if tokens.get('eventgen'):                      # improvement-round-v1 D18: pinned event-generator binary
            cfg['eventgen_binary']=str(Path(tokens['eventgen']).resolve());cfg['eventgen_hash']=sha256_file(Path(tokens['eventgen']))
        if tokens.get('v3_counts'):
            cfg['v3_counts']=dict(path=str(tokens['v3_counts']),sha256=sha256_file(Path(tokens['v3_counts'])))
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
    # lidds-ml-v3 runs (no rules): shared-storage writes off the scoring loop and decisions on each worker's local disk
    # for the bridge, RCA and campaign, and the benign-exec control from its own file name, as the final system has
    # them, without its tripwire
    if local_decisions and not final_system:
        cfg['async_shared_writes']=True
        cfg['benign_binary_distinct']=True
        for worker in cfg['workers'].values():
            worker['stream_root']=str(Path(local_decisions)/run_id)
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
    # 5 kịch bản tấn công của fixture (đều chỉ ảnh hưởng chính process hoặc chắc chắn thất bại):
    # mprotect đổi quyền trang nhớ, ptrace(TRACEME) ở process con, setns(fd -1), seccomp thao tác sai, execveat file không có.
    scenarios=['anonymous_mprotect_churn','child_ptrace_handshake','invalid_setns_burst',
               'seccomp_api_probe','execveat_resolution_probe']
    # Lịch trial cơ bản: mỗi (workload, kịch bản, tốc độ) một trial → 21 × 5 × 5 = 525 ở lượt v5/v6.
    cfg['schedule']=[dict(workload_key=key,workload_controller=key.split('/',1)[1].split(':')[0],
                         scenario=scenario,rate_per_second=rate,seed=seed)
        for key in keys for scenario in scenarios for rate in rates for seed in (61501,)]   # G4: --attack-rates 1,3,6
    if tokens and tokens.get('dilution_pads'):
        # adaptive attacker (dilution): the same scenarios at one rate with PAD pairs of common calls after each operation
        cfg['schedule']+=[dict(workload_key=key,workload_controller=key.split('/',1)[1].split(':')[0],
                               scenario=scenario,rate_per_second=tokens['dilution_rate'],seed=61501,pad=pad)
                          for key in keys for scenario in scenarios for pad in tokens['dilution_pads']]
    if tokens and tokens.get('on_off'):
        # D12 on-off attacker: operations only in the first second of each period
        cfg['schedule']+=[dict(workload_key=key,workload_controller=key.split('/',1)[1].split(':')[0],
                               scenario=scenario,rate_per_second=tokens['on_off_rate'],seed=61501,on_off=period)
                          for key in keys for scenario in scenarios for period in tokens['on_off']]
    # Xáo thứ tự trial bằng seed cố định → lịch giống hệt nếu dựng lại, nhưng không theo thứ tự workload.
    random.Random(20261015).shuffle(cfg['schedule'])
    # Lịch tải: hai vòng 5 pha (756 s rồi 324 s mỗi pha) trong đoạn selection, rồi 'steady' tới hết lượt.
    cfg['traffic_schedule']=[]
    t=start
    for seconds in (756,324):
        for regime in ('steady','toolmix','peak','burst','recovery'):
            cfg['traffic_schedule'].append(dict(start=t,end=t+seconds,regime=regime));t+=seconds
    cfg['traffic_schedule'].append(dict(start=t,end=t+86400,regime='steady'))
    config=root/'CONFIG.json'
    config.write_text(json.dumps(cfg,indent=2)+'\n');config.chmod(0o444)
    print(config)


# Dòng lệnh: launch_run.sh truyền mọi giá trị (xem phần đầu scripts/launch_run.sh).
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for key in ('source','root'):p.add_argument('--'+key,type=Path,required=True)
    p.add_argument('--run-id',required=True);p.add_argument('--smoke',action='store_true')
    p.add_argument('--profile',choices=['custom'],default='custom')
    p.add_argument('--frozen-source',type=Path,required=True,help='source snapshot whose scorer bytes the worker must match')
    for key in ('candidate','model-hash','policy','policy-hash','fixture'):p.add_argument('--'+key)
    p.add_argument('--seconds',type=int,default=86400)
    for key in ('benign-exec-control','no-raw-frames','fast-scoring'):p.add_argument('--'+key,action='store_true')
    p.add_argument('--attack-rates',default='6,12,24',help='fixture attack rates per second (0.05-100), comma-separated')
    p.add_argument('--tripwire-exec-set',type=Path,help='final system: tripwire A1 in the worker with this frozen exec set')
    p.add_argument('--stream-root',default='/var/lib/sentinel-pulse-live',help='final system: local decision copy on each worker')
    p.add_argument('--recalibration',help='rolling-W-R: every R hours recalibrate on the preceding W hours of all workers')
    p.add_argument('--recalibration-exclude-campaign',action='store_true',help="leave the campaign's intervals out of it")
    p.add_argument('--token-build',help='lidds-ml-v3 token probe: directory with build/ and proof/ on every worker')
    p.add_argument('--token-models',type=Path,help='token branch models (MODELS.json of token_branch_fit.py)')
    p.add_argument('--v3-counts',type=Path,help='count-branch thresholds (count_branch_fit.py)')
    p.add_argument('--token-gate',type=Path,help='gate of the token branch, protocol lidds-ml-v5 (GATE.json of token_branch_fit.py)')
    p.add_argument('--admin-control',action='store_true',help='real admin commands as benign controls in every trial')
    p.add_argument('--local-decisions',action='store_true',help='async shared writes + local decision copy (--stream-root) without the tripwire')
    p.add_argument('--admin-commands',choices=['v5','v6'],help='set of admin commands (attack/preview_campaign.py ADMIN_SETS)')
    p.add_argument('--random-trial-order',action='store_true',help='shuffle admin, benign and attack within each trial (seeded)')
    p.add_argument('--lotl-attack',action='store_true',help='add a living-off-the-land attack step made of image tools')
    p.add_argument('--dilution-pads',help='adaptive attacker: comma-separated PAD values (1-10000), extra trials at --dilution-rate')
    p.add_argument('--dilution-rate',type=int,default=12)
    p.add_argument('--eventgen',help='D18: path of the Falco event-generator binary (one event-generator step per trial)')
    p.add_argument('--on-off',help='on-off attacker (improvement-round-v1 D12): comma-separated periods in s (2-60), extra trials '
                   'at --on-off-rate with operations only in the first second of each period')
    p.add_argument('--on-off-rate',type=float,default=12)
    a=p.parse_args()
    # D12: fractional rates (slow attacker, e.g. 0.5, 0.2, 0.1 per second); integers print as before (6, not 6.0)
    rates=tuple((lambda r:int(r) if r==int(r) else r)(float(x)) for x in a.attack_rates.split(','))
    if not rates or not all(0.05<=r<=100 for r in rates):p.error('attack rates must be 0.05-100 per second')
    onoff=tuple(int(x) for x in a.on_off.split(',')) if a.on_off else ()
    if not all(2<=x<=60 for x in onoff) or not 0.05<=a.on_off_rate<=100:p.error('on-off periods must be 2-60 s')
    pads=tuple(int(x) for x in a.dilution_pads.split(',')) if a.dilution_pads else ()
    if not all(1<=x<=10000 for x in pads) or not 1<=a.dilution_rate<=100:p.error('dilution pads must be 1-10000, rate 1-100')
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
    if (a.token_models or a.v3_counts) and not a.token_build:p.error('token models and count thresholds need --token-build')
    tokens=dict(build=a.token_build,models=a.token_models,v3_counts=a.v3_counts,gate=a.token_gate,admin_control=a.admin_control,
                admin_commands=a.admin_commands,random_trial_order=a.random_trial_order,lotl_attack=a.lotl_attack,
                dilution_pads=pads,dilution_rate=a.dilution_rate,on_off=onoff,eventgen=a.eventgen,
                on_off_rate=(lambda r:int(r) if r==int(r) else r)(a.on_off_rate)) if a.token_build else None
    plan(a.source,a.root,a.run_id,a.smoke,a.profile,a.frozen_source,custom,rates,final,recal,tokens,
         a.stream_root if a.local_decisions else None)
