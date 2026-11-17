"""Persistent development attack/control matrix for the frozen Pulse preview.

Previously exposed scenarios diagnose the present candidate. They are never
called a fresh blind set. No outcome changes a model, alpha or policy.
"""
# [VI] ==============================================================================================================
# [VI] preview_campaign.py — CAMPAIGN CỦA LƯỢT LIVE (unit pulse-matched-campaign-<run> trên .234).
# [VI] ------------------------------------------------------------------------------------------------------------
# [VI] Đi lần lượt qua lịch trial trong CONFIG.json. Mỗi trial ("pair") nhắm MỘT container của MỘT replica:
# [VI]   1) control: 17 s không làm gì (đo báo nhầm khi container chạy bình thường);
# [VI]   2) các bước sau, thứ tự cố định hoặc xáo có seed (step_order), mỗi bước một khoảng 15 s:
# [VI]        admin  — một lệnh quản trị thật của image qua `kubectl exec` (mẫu âm khó: process mới nhưng vô hại);
# [VI]        benign — binary vô hại của operator qua cùng đường exec (chỉ getpid + clock_nanosleep);
# [VI]        attack — binary fixture chạy một kịch bản tấn công ở tốc độ đăng ký (có thể kèm PAD pha loãng);
# [VI]        lotl   — tấn công "sống nhờ đất" chỉ bằng sh/cat/ls của image (từ lượt v6);
# [VI]   3) đọc decision của worker cho các khoảng đó, ghi kết quả từng trial vào trials/NNNN/ (EVALUATION_INPUT.json,
# [VI]      ORDER.json, CONTROL.json...), và nối INTERVALS.jsonl (mốc bắt đầu, nhãn của từng khoảng).
# [VI] Nhãn là NHÃN THEO THIẾT KẾ (khoảng attack là tấn công, còn lại là normal); phân tích chính thức đọc INTERVALS.jsonl
# [VI] + decisions (scripts/analysis/pulse_live_v4.py), không dựa vào STATUS.json của file này.
# [VI] Mọi binary tấn công là fixture tự viết (testbed/attack/...), không exploit CVE, không image có lỗ hổng.
# [VI] ==============================================================================================================
from __future__ import annotations

import argparse
import fcntl
import json
from pathlib import Path
import random
import shlex
import subprocess
import time

from ..integrity import sha256_file
from .cluster import Runtime, benign_path_for, binary_path_for_controller, select_target
from ..common import append_jsonl, atomic_json
from .preview_evaluation import evaluate_interval, summarize
from .tetragon_evidence import EXEC_PROVENANCE_POLICY, find_execve_kprobe_event


# [VI] Chạy lệnh root trên worker qua ssh + sudo (mật khẩu đọc từ file credential, truyền qua stdin, không in ra).
class PreviewRuntime(Runtime):
    def remote_sudo(self,host,command,*,payload=b'',timeout=30):
        return self.run(['sshpass','-e','ssh','-o','StrictHostKeyChecking=yes',
            '-o','UserKnownHostsFile=/home/dat/.ssh/known_hosts','-o','ConnectTimeout=8',
            f'{self.ssh_user}@{host}','sudo -k -S -p "" '+command],
            input_bytes=self.password.encode()+b'\n'+payload,timeout=timeout)


# [VI] Bộ lệnh quản trị v5 (lượt v5): mỗi trial một lệnh, lần lượt theo chỉ số trial.
ADMIN_COMMANDS=(('ls',['ls','/']),('cat',['cat','/etc/os-release']),('ps',['ps']),('env',['env']),('id',['id']),
                ('sh',['sh','-c','echo ok']),('python',['python3','-c','pass']),('date',['date']),('uname',['uname','-a']),
                ('df',['df','-h']))
# A second set of real image tools, none of them in ADMIN_COMMANDS: admin commands that no earlier run's model or rule saw.
ADMIN_COMMANDS_V6=(('head',['head','-n','1','/etc/passwd']),('wc',['wc','-l','/etc/hostname']),('hostname',['hostname']),
                   ('whoami',['whoami']),('stat',['stat','/']),('find',['find','/etc','-maxdepth','1','-name','hosts']),
                   ('grep',['grep','-c','root','/etc/group']),('printenv',['printenv','HOME']),('sleep',['sleep','1']),
                   ('ls_tmp',['ls','-l','/tmp']))
ADMIN_SETS={'v5':ADMIN_COMMANDS,'v6':ADMIN_COMMANDS_V6}
# Living off the land: attack steps made only of tools the image already has (sh, cat, ls), through kubectl exec. Each
# step reads and discards (credential access: the pod's service-account token; discovery: process list and
# environment of pid 1, network sockets, accounts) or writes a file under /tmp and removes it (persistence attempt);
# nothing leaves the container and no state outside /tmp changes. Repeated about once a second for 15 s.
# [VI] Bước lotl lặp 15 lần (~1 lần/giây): đọc token service account, /proc, socket, tài khoản → /dev/null; ghi rồi xoá một file /tmp.
LOTL_SCRIPT=('i=0; while [ $i -lt 15 ]; do '
    'cat /var/run/secrets/kubernetes.io/serviceaccount/token >/dev/null 2>&1; '
    'ls /proc >/dev/null 2>&1; cat /proc/1/cmdline /proc/1/environ >/dev/null 2>&1; '
    'cat /proc/net/tcp /proc/net/tcp6 >/dev/null 2>&1; cat /etc/passwd /etc/group >/dev/null 2>&1; '
    'echo "* * * * * true" > /tmp/.sentinel-lotl-cron 2>/dev/null; rm -f /tmp/.sentinel-lotl-cron; '
    'i=$((i+1)); sleep 1; done; echo lotl-done')
STEPS=('admin','benign','attack')


# [VI] Thứ tự các bước sau control. Xáo có seed (seed của item + chỉ số trial) → chạy lại cho đúng thứ tự cũ; dùng cho H6 (RCA).
def step_order(cfg,item,index):
    """Order of the trial's steps after its control. Fixed (admin, benign, attack, then lotl) unless the run registers
    random_trial_order: a per-pair shuffle seeded by the item's seed and the pair index, so a rerun repeats it."""
    steps=list(STEPS)+(['lotl'] if cfg.get('lotl_attack') else [])
    if cfg.get('random_trial_order'):random.Random(f"{item['seed']}:{index}").shuffle(steps)
    return steps


# [VI] Đọc decision của một container kể từ `begin` NGAY TRÊN worker (bản local), tránh cache NFS của máy khác che dòng mới.
def tail_rows(runtime,cfg,worker,begin,pod_uid,cgroup_id):
    # Read on the writer's client. A second NFS client's attribute/page cache
    # can temporarily hide appended rows even after Python flushes on worker.
    args=['/usr/bin/env','PYTHONPATH='+cfg['source'],'PYTHONDONTWRITEBYTECODE=1',
        '/opt/sentinel-pulse/runtime-venv/bin/python','-m','sentinel_pulse.attack.preview_read_tail',
        '--root',worker.get('stream_root',worker['output']),'--since',str(begin),'--pod-uid',pod_uid,'--cgroup-id',str(cgroup_id)]
    result=runtime.remote_sudo(worker['host'],shlex.join(args))
    return [json.loads(line) for line in result.stdout.splitlines()]


# [VI] Danh tính đầy đủ của container được nhắm (pod UID, cgroup, phiên bản...) — dùng để khớp decision với trial.
def target_identity(runtime,pod,container,cg,worker):
    data=runtime.kubectl_json('get','pod',pod['name'],'-n','production','-o','json')
    if data['metadata']['uid']!=pod['uid']:raise ValueError('pod changed during selection')
    status=next(s for s in data['status']['containerStatuses'] if s['name']==container)
    meta=json.loads(runtime.remote_sudo(worker['host'],'cat /run/sentinel-pulse/cgroups.json').stdout)['cgroups'][str(cg)]
    return dict(node_name=pod['node_name'],pod_uid=pod['uid'],container_name=container,
        workload_revision=meta['workload_revision'],cgroup_id=cg,container_id=status['containerID'])


# [VI] CHẠY MỘT TRIAL. Chọn container mục tiêu (select_target), đo control, "stage" binary vào container (preview_target),
# [VI] chạy các bước theo thứ tự, rồi đánh giá. Khoảng tấn công còn bật thu sự kiện exec của Tetragon để biết thời điểm kernel
# [VI] đầu tiên của tấn công (dùng tính độ trễ). Khối finally luôn dọn binary đã stage khỏi container.
def one_pair(runtime,cfg,root,item,index):
    trial_dir=root/'trials'/f'{index:04d}';trial_dir.mkdir(parents=True,exist_ok=True)
    node_workers={w['node_name']:dict(w,host=host) for host,w in cfg['workers'].items()}
    pod,worker,container,cg=select_target(runtime,item,node_workers,index)
    identity=target_identity(runtime,pod,container,cg,worker)
    identity['workload_key']=item['workload_key']
    # Capture begins well before control; require current heartbeat before dispatch.
    state=json.loads((Path(worker['output'])/'STATUS.json').read_text())
    if time.time()-state.get('updated_at_unix',0)>15:raise RuntimeError('matched worker heartbeat stale')
    control=dict(identity,label='expected_normal',start_at=time.time(),trial_id=f'{index}:control')
    append_jsonl(root/'INTERVALS.jsonl',control)
    time.sleep(17)
    ctl=evaluate_interval(tail_rows(runtime,cfg,worker,control['start_at'],pod['uid'],cg),control,cfg['model_hash'],cfg['policy_hash'])
    atomic_json(trial_dir/'CONTROL.json',ctl)
    order=step_order(cfg,item,index)
    marks=dict(order=order)
    path=binary_path_for_controller(item['workload_controller'])
    args=['--container-id',identity['container_id'],'--pod-uid',identity['pod_uid'],
          '--container-name',container,'--binary',cfg['binary'],'--sha256',cfg['binary_hash'],'--path',path]
    prefix=['/usr/bin/env','PYTHONPATH='+cfg['source'],'PYTHONDONTWRITEBYTECODE=1',
            '/opt/sentinel-pulse/runtime-venv/bin/python','-m','sentinel_pulse.attack.preview_target']
    runtime.remote_sudo(worker['host'],shlex.join([*prefix,'stage',*args]))
    sensor=None;capture=None;staged=True;injection=None;benign=None;benign_args=None;lotl=None
    benign_path=path
    if cfg.get('benign_exec_control') and cfg.get('benign_binary_distinct'):
        benign_path=benign_path_for(path)
        benign_args=[*args[:-1],benign_path]
        runtime.remote_sudo(worker['host'],shlex.join([*prefix,'stage',*benign_args]))

    def admin_step():
        if not cfg.get('admin_control'):return
        # protocol lidds-ml-v5: a real command of the image through the same kubectl exec path, as a benign class that
        # no choice of the gate has seen. A command the image lacks is recorded and left out by the analysis.
        name,command=ADMIN_SETS[cfg.get('admin_commands','v5')][index%len(ADMIN_SETS[cfg.get('admin_commands','v5')])]
        admin=dict(identity,**item,label='expected_normal',control_kind='admin_exec',admin_command=name,
                   start_at=time.time(),trial_id=f'{index}:admin',duration_seconds=15)
        append_jsonl(root/'INTERVALS.jsonl',admin)
        result=runtime.run(['kubectl','exec','-n','production',pod['name'],'-c',container,'--',*command],timeout=30,check=False)
        if result.returncode:admin['infrastructure_issue']='admin_command_failed'
        atomic_json(trial_dir/'ADMIN.json',dict(command=name,returncode=result.returncode))
        marks['admin']=admin['start_at']
        time.sleep(max(0.,admin['start_at']+20-time.time()))

    def benign_step():
        nonlocal benign
        if not cfg.get('benign_exec_control'):return
        # Same launch path and binary, attack-free body: isolates the
        # effect of "a new process ran" from attack behaviour.
        benign=dict(identity,**item,label='expected_normal',control_kind='benign_exec',
            start_at=time.time(),trial_id=f'{index}:benign',binary_path=benign_path,duration_seconds=15)
        append_jsonl(root/'INTERVALS.jsonl',benign)
        result=runtime.run(['kubectl','exec','-n','production',pod['name'],'-c',container,'--',
            benign_path,'benign_exec_control','15',str(item['rate_per_second']),str(item['seed'])],timeout=45,check=False)
        (trial_dir/'benign.stderr').write_bytes(result.stderr)
        if result.returncode or b'done' not in result.stderr:benign['infrastructure_issue']='benign_fixture_failed'
        marks['benign']=benign['start_at']
        time.sleep(5)  # keep benign windows out of the next interval's 3-window history

    def lotl_step():
        nonlocal lotl
        lotl=dict(identity,**item,label='attack_lotl',attack_kind='living_off_the_land',start_at=time.time(),
                  trial_id=f'{index}:lotl',duration_seconds=15)
        append_jsonl(root/'INTERVALS.jsonl',lotl)
        result=runtime.run(['kubectl','exec','-n','production',pod['name'],'-c',container,'--','sh','-c',LOTL_SCRIPT],
                           timeout=45,check=False)
        (trial_dir/'lotl.stderr').write_bytes(result.stderr)
        if result.returncode or b'lotl-done' not in result.stdout:lotl['infrastructure_issue']='lotl_failed'
        atomic_json(trial_dir/'LOTL.json',dict(returncode=result.returncode))
        marks['lotl']=lotl['start_at']
        time.sleep(max(0.,lotl['start_at']+20-time.time()))

    def attack_step():
        nonlocal sensor,capture,injection
        sensors=runtime.kubectl_json('get','pods','-n','kube-system','-l','app.kubernetes.io/name=tetragon','-o','json')
        sensor=next(p['metadata']['name'] for p in sensors['items'] if p['spec'].get('nodeName')==pod['node_name'])
        policies=runtime.run(['kubectl','exec','-n','kube-system',sensor,'-c','tetragon','--','tetra','tracingpolicy','list']).stdout.decode()
        if not any(EXEC_PROVENANCE_POLICY in line and 'enabled' in line for line in policies.splitlines()):
            raise RuntimeError('node-local exec provenance policy unavailable')
        with (trial_dir/'kernel.jsonl').open('wb') as out,(trial_dir/'kernel.stderr').open('wb') as err:
            # The inner timeout bounds the process inside the sensor container: the
            # outer one only kills kubectl and leaked one event client per trial.
            capture=subprocess.Popen(['timeout','23s','kubectl','exec','-n','kube-system',sensor,
                '-c','tetragon','--','timeout','24','tetra','getevents','-o','json','--policy-names',EXEC_PROVENANCE_POLICY],
                stdout=out,stderr=err,env=runtime.environment)
            time.sleep(1)
            injection=dict(identity,**item,label='attack',start_at=time.time(),trial_id=f'{index}:attack',
                injection_id=f"{cfg['run_id']}:{index:04d}",pod_name=pod['name'],binary_path=path,duration_seconds=15)
            injection['injected_at']=injection['start_at']
            append_jsonl(root/'INTERVALS.jsonl',injection)
            append_jsonl(root/'DISPATCH.jsonl',injection)
            result=runtime.run(['kubectl','exec','-n','production',pod['name'],'-c',container,'--',
                path,item['scenario'],'15',str(item['rate_per_second']),str(item['seed']),
                *([str(item['pad'])] if item.get('pad') else [])],timeout=45,check=False)
            (trial_dir/'attack.stdout').write_bytes(result.stdout);(trial_dir/'attack.stderr').write_bytes(result.stderr)
            if result.returncode or b'done' not in result.stderr:injection['infrastructure_issue']='fixture_execution_failed'
            capture.wait(timeout=12);capture=None
        marks['attack']=injection['start_at']
        time.sleep(2)
        try:
            event=find_execve_kprobe_event((trial_dir/'kernel.jsonl').read_text().splitlines(),injection,
                expected_binary=path,maximum_delay_seconds=10)
            atomic_json(trial_dir/'KERNEL_EVENT.json',event);injection['kernel_event_at']=event['kernel_event_at']
        except ValueError as exc:injection['infrastructure_issue']='kernel_provenance: '+str(exc)
        if order.index('attack')<len(order)-1:time.sleep(3)   # keep attack windows out of the next interval's history

    steps=dict(admin=admin_step,benign=benign_step,attack=attack_step,lotl=lotl_step)
    try:
        for step in order:steps[step]()
        atomic_json(trial_dir/'ORDER.json',marks)
        outcome=evaluate_interval(tail_rows(runtime,cfg,worker,injection['start_at'],pod['uid'],cg),injection,cfg['model_hash'],cfg['policy_hash'])
        # Store exact selected rows as evidence so later replay is independent of tail position.
        last=max(v for k,v in marks.items() if k!='order')
        rows=[r for r in tail_rows(runtime,cfg,worker,control['start_at'],pod['uid'],cg)
              if r.get('pod_uid')==pod['uid'] and str(r.get('cgroup_id'))==str(cg)
              and r.get('window_end',0)<=last+17]
        evidence=dict(control=control,attack=injection,decisions=rows,order=order)
        if lotl is not None:evidence['lotl']=lotl
        if benign is None:
            atomic_json(trial_dir/'EVALUATION_INPUT.json',evidence)
            return [ctl,outcome]
        evidence['benign']=benign
        atomic_json(trial_dir/'EVALUATION_INPUT.json',evidence)
        benign_outcome=evaluate_interval(rows,benign,cfg['model_hash'],cfg['policy_hash'])
        atomic_json(trial_dir/'BENIGN.json',benign_outcome)
        return [ctl,benign_outcome,outcome]
    finally:
        if capture is not None:
            capture.terminate()
            try:capture.wait(timeout=5)
            except subprocess.TimeoutExpired:capture.kill();capture.wait()
        if staged:
            runtime.remote_sudo(worker['host'],shlex.join([*prefix,'cleanup',*args]))
        if benign_args is not None:
            runtime.remote_sudo(worker['host'],shlex.join([*prefix,'cleanup',*benign_args]))


# [VI] VÒNG CAMPAIGN: kiểm binary/policy đúng SHA-256 đã đăng ký → chờ hết đoạn normal đầu lượt (attack_not_before) → với mỗi
# [VI] trial: chờ worker còn "nhịp tim" (STATUS cập nhật < 20 s), ghi ATTEMPTS.jsonl TRƯỚC khi chạy (trial bị ngắt giữa chừng
# [VI] sẽ ghi "unknown" chứ không chạy lại), chạy one_pair, lưu RESULTS.json. Hết lịch → TERMINAL.json.
def run(config,credential):
    cfg=json.loads(config.read_text());root=Path(cfg['campaign_output']);root.mkdir(parents=True,exist_ok=True)
    lock=(root/'campaign.lock').open('a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    runtime=PreviewRuntime(credential.read_text().strip())
    binding=dict(config_sha256=sha256_file(config),model_hash=cfg['model_hash'],policy_hash=cfg['policy_hash'],
        binary_sha256=sha256_file(Path(cfg['binary'])),evidence_class='development_candidate_preview',
        fresh_blind=False,automatic_promotion=False,stop_on_false_positive=False,stop_on_miss=False)
    exec_policy=Path(cfg['exec_provenance_policy'])
    binding['exec_provenance_policy_sha256']=sha256_file(exec_policy)
    if binding['exec_provenance_policy_sha256']!=cfg['exec_provenance_policy_sha256']:
        raise ValueError('Tetragon provenance policy changed after registration')
    if binding['binary_sha256']!=cfg['binary_hash']:raise ValueError('binary hash differs')
    if (root/'START.json').exists():
        if json.loads((root/'START.json').read_text())['binding']!=binding:raise ValueError('campaign registration differs')
    else:atomic_json(root/'START.json',dict(binding=binding,registered_at=time.time(),schedule=cfg['schedule']))
    # Candidate and selection branch share the same stream. Keep a clean
    # preregistered normal prefix before any generator is dispatched.
    while time.time()<cfg['attack_not_before']:
        atomic_json(root/'STATUS.json',dict(state='collecting_clean_normal_prefix',
            attack_not_before=cfg['attack_not_before'],updated_at_unix=time.time()))
        time.sleep(min(30,max(0,cfg['attack_not_before']-time.time())))
    result_path=root/'RESULTS.json'
    results=json.loads(result_path.read_text()) if result_path.exists() else dict(completed={},outcomes=[])
    # Any interrupted pair is retained unknown and never re-injected.
    attempted={int(json.loads(line)['pair']) for line in (root/'ATTEMPTS.jsonl').read_text().splitlines()} if (root/'ATTEMPTS.jsonl').exists() else set()
    for index,item in enumerate(cfg['schedule'],1):
        key=str(index)
        if key in results['completed']:continue
        if index in attempted:
            pair=[dict(label=label,outcome='unknown',reason='interrupted_pair_not_reinjected')
                  for label in ('attack','expected_normal')]
        else:
            # Wait for infrastructure recovery before consuming this pair.
            while True:
                try:
                    if any(time.time()-json.loads((Path(w['output'])/'STATUS.json').read_text()).get('updated_at_unix',0)>20
                           for w in cfg['workers'].values()):raise RuntimeError('worker heartbeat stale')
                    break
                except (OSError,ValueError,RuntimeError) as exc:
                    atomic_json(root/'STATUS.json',dict(state='waiting_for_telemetry_recovery',reason=str(exc),updated_at_unix=time.time()))
                    time.sleep(30)
            append_jsonl(root/'ATTEMPTS.jsonl',dict(pair=index,item=item,at=time.time()))
            try:pair=one_pair(runtime,cfg,root,item,index)
            except Exception as exc:
                pair=[dict(label=label,outcome='unknown',reason=type(exc).__name__+': '+str(exc),
                           trial_id=f'{index}:{label}',**item) for label in ('attack','expected_normal')]
                control=root/'trials'/f'{index:04d}'/'CONTROL.json'
                if control.exists():pair[1]=json.loads(control.read_text())
        results['completed'][key]=pair;results['outcomes'].extend(pair)
        atomic_json(result_path,results)
        atomic_json(root/'STATUS.json',dict(summarize(results['outcomes']),state='running',
            completed_pairs=len(results['completed']),expected_pairs=len(cfg['schedule']),updated_at_unix=time.time()))
    final=dict(summarize(results['outcomes']),state='completed_development_preview_matrix',
        expected_pairs=len(cfg['schedule']),completed_pairs=len(results['completed']),finished_at_unix=time.time(),binding=binding)
    atomic_json(root/'STATUS.json',final);atomic_json(root/'TERMINAL.json',final)


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--config',type=Path,required=True)
    p.add_argument('--credential',type=Path,required=True);a=p.parse_args();run(a.config,a.credential)
