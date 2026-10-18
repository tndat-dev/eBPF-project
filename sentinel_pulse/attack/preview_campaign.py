"""Persistent development attack/control matrix for the frozen Pulse preview.

Previously exposed scenarios diagnose the present candidate. They are never
called a fresh blind set. No outcome changes a model, alpha or policy.
"""
from __future__ import annotations

import argparse
import fcntl
import json
from pathlib import Path
import shlex
import subprocess
import time

from ..integrity import sha256_file
from .cluster import Runtime, binary_path_for_controller, select_target
from ..common import append_jsonl, atomic_json
from .preview_evaluation import evaluate_interval, summarize
from .tetragon_evidence import EXEC_PROVENANCE_POLICY, find_execve_kprobe_event


class PreviewRuntime(Runtime):
    def remote_sudo(self,host,command,*,payload=b'',timeout=30):
        return self.run(['sshpass','-e','ssh','-o','StrictHostKeyChecking=yes',
            '-o','UserKnownHostsFile=/home/dat/.ssh/known_hosts','-o','ConnectTimeout=8',
            f'{self.ssh_user}@{host}','sudo -k -S -p "" '+command],
            input_bytes=self.password.encode()+b'\n'+payload,timeout=timeout)


def tail_rows(runtime,cfg,worker,begin,pod_uid,cgroup_id):
    # Read on the writer's client. A second NFS client's attribute/page cache
    # can temporarily hide appended rows even after Python flushes on worker.
    args=['/usr/bin/env','PYTHONPATH='+cfg['source'],'PYTHONDONTWRITEBYTECODE=1',
        '/opt/sentinel-pulse/runtime-venv/bin/python','-m','sentinel_pulse.attack.preview_read_tail',
        '--root',worker['output'],'--since',str(begin),'--pod-uid',pod_uid,'--cgroup-id',str(cgroup_id)]
    result=runtime.remote_sudo(worker['host'],shlex.join(args))
    return [json.loads(line) for line in result.stdout.splitlines()]


def target_identity(runtime,pod,container,cg,worker):
    data=runtime.kubectl_json('get','pod',pod['name'],'-n','production','-o','json')
    if data['metadata']['uid']!=pod['uid']:raise ValueError('pod changed during selection')
    status=next(s for s in data['status']['containerStatuses'] if s['name']==container)
    meta=json.loads(runtime.remote_sudo(worker['host'],'cat /run/sentinel-pulse/cgroups.json').stdout)['cgroups'][str(cg)]
    return dict(node_name=pod['node_name'],pod_uid=pod['uid'],container_name=container,
        workload_revision=meta['workload_revision'],cgroup_id=cg,container_id=status['containerID'])


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
    path=binary_path_for_controller(item['workload_controller'])
    args=['--container-id',identity['container_id'],'--pod-uid',identity['pod_uid'],
          '--container-name',container,'--binary',cfg['binary'],'--sha256',cfg['binary_hash'],'--path',path]
    prefix=['/usr/bin/env','PYTHONPATH='+cfg['source'],'PYTHONDONTWRITEBYTECODE=1',
            '/opt/sentinel-pulse/runtime-venv/bin/python','-m','sentinel_pulse.attack.preview_target']
    runtime.remote_sudo(worker['host'],shlex.join([*prefix,'stage',*args]))
    sensor=None;capture=None;staged=True;injection=None
    try:
        sensors=runtime.kubectl_json('get','pods','-n','kube-system','-l','app.kubernetes.io/name=tetragon','-o','json')
        sensor=next(p['metadata']['name'] for p in sensors['items'] if p['spec'].get('nodeName')==pod['node_name'])
        policies=runtime.run(['kubectl','exec','-n','kube-system',sensor,'-c','tetragon','--','tetra','tracingpolicy','list']).stdout.decode()
        if not any(EXEC_PROVENANCE_POLICY in line and 'enabled' in line for line in policies.splitlines()):
            raise RuntimeError('node-local exec provenance policy unavailable')
        with (trial_dir/'kernel.jsonl').open('wb') as out,(trial_dir/'kernel.stderr').open('wb') as err:
            capture=subprocess.Popen(['timeout','23s','kubectl','exec','-n','kube-system',sensor,
                '-c','tetragon','--','tetra','getevents','-o','json','--policy-names',EXEC_PROVENANCE_POLICY],
                stdout=out,stderr=err,env=runtime.environment)
            time.sleep(1)
            injection=dict(identity,**item,label='attack',start_at=time.time(),trial_id=f'{index}:attack',
                injection_id=f"{cfg['run_id']}:{index:04d}",pod_name=pod['name'],binary_path=path,duration_seconds=15)
            injection['injected_at']=injection['start_at']
            append_jsonl(root/'INTERVALS.jsonl',injection)
            append_jsonl(root/'DISPATCH.jsonl',injection)
            result=runtime.run(['kubectl','exec','-n','production',pod['name'],'-c',container,'--',
                path,item['scenario'],'15',str(item['rate_per_second']),str(item['seed'])],timeout=45,check=False)
            (trial_dir/'attack.stdout').write_bytes(result.stdout);(trial_dir/'attack.stderr').write_bytes(result.stderr)
            if result.returncode or b'done' not in result.stderr:injection['infrastructure_issue']='fixture_execution_failed'
            capture.wait(timeout=12);capture=None
        time.sleep(2)
        try:
            event=find_execve_kprobe_event((trial_dir/'kernel.jsonl').read_text().splitlines(),injection,
                expected_binary=path,maximum_delay_seconds=10)
            atomic_json(trial_dir/'KERNEL_EVENT.json',event);injection['kernel_event_at']=event['kernel_event_at']
        except ValueError as exc:injection['infrastructure_issue']='kernel_provenance: '+str(exc)
        outcome=evaluate_interval(tail_rows(runtime,cfg,worker,injection['start_at'],pod['uid'],cg),injection,cfg['model_hash'],cfg['policy_hash'])
        # Store exact selected rows as evidence so later replay is independent of tail position.
        rows=[r for r in tail_rows(runtime,cfg,worker,control['start_at'],pod['uid'],cg)
              if r.get('pod_uid')==pod['uid'] and str(r.get('cgroup_id'))==str(cg)
              and r.get('window_end',0)<=injection['start_at']+17]
        atomic_json(trial_dir/'EVALUATION_INPUT.json',dict(control=control,attack=injection,decisions=rows))
        return [ctl,outcome]
    finally:
        if capture is not None:
            capture.terminate()
            try:capture.wait(timeout=5)
            except subprocess.TimeoutExpired:capture.kill();capture.wait()
        if staged:
            runtime.remote_sudo(worker['host'],shlex.join([*prefix,'cleanup',*args]))


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
