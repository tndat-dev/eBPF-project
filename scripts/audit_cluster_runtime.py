#!/usr/bin/env python3
"""Read-only VM process/service/resource inventory; never exports argv or env secrets."""
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import datetime as dt
import json
import os
from pathlib import Path
import shlex

import paramiko

HOSTS = [f'10.1.16.{suffix}' for suffix in range(233, 240)]

REMOTE = r'''
import collections, datetime, json, os, pathlib, re, shutil, socket, subprocess, time
P = pathlib.Path
def command(args, timeout=15):
    r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    if r.returncode: raise RuntimeError('command failed: '+args[0]+': '+r.stderr[-300:])
    return r.stdout
def json_command(args):
    return json.loads(command(args))
def read(path):
    try: return P(path).read_text().strip()
    except OSError: return None
out = dict(hostname=socket.gethostname(), inspected_at_unix=time.time(),
    boot_id=read('/proc/sys/kernel/random/boot_id'), uptime=read('/proc/uptime'),
    kernel=command(['uname','-r']).strip(), cpu_count=os.cpu_count(), errors={})
mem = {}
for line in P('/proc/meminfo').read_text().splitlines():
    k,v = line.split(':',1)
    if k in ('MemTotal','MemAvailable','MemFree','Buffers','Cached','SwapTotal','SwapFree',
             'Dirty','Writeback','Slab','SReclaimable','SUnreclaim','Unevictable','Mlocked',
             'PageTables','KernelStack','Percpu','VmallocUsed','HugePages_Total'): mem[k]=v.strip()
out['memory']=mem
out['pressure']={k:read('/proc/pressure/'+k) for k in ('cpu','memory','io')}
out['filesystems']={}
for name in ('/','/var/lib/longhorn','/mnt/sentinel-pulse-archive','/sentinel-pulse','/srv/sentinel-pulse'):
    if not P(name).exists(): continue
    s=os.statvfs(name)
    item=dict(total_bytes=s.f_blocks*s.f_frsize, available_bytes=s.f_bavail*s.f_frsize,
              used_fraction=1-s.f_bfree/max(s.f_blocks,1), inodes_free=s.f_favail)
    try: item['mount']=json_command(['findmnt','-J','-T',name,'-o','TARGET,SOURCE,FSTYPE'])
    except Exception as e: item['mount_error']=str(e)
    out['filesystems'][name]=item
processes=[]
for line in command(['ps','-eo','pid,ppid,user,comm,etimes,pcpu,pmem,rss','--no-headers']).splitlines():
    fields=line.split()
    if len(fields)!=8: continue
    pid,ppid,user,comm,age,cpu,mem,rss=fields
    row=dict(pid=int(pid),ppid=int(ppid),user=user,command=comm,age_seconds=int(age),
             cpu_percent=float(cpu),memory_percent=float(mem),rss_kib=int(rss))
    try:
        argv=P('/proc/'+pid+'/cmdline').read_bytes().decode(errors='replace').split('\0')
        if re.search(r'pulse|syscall|anomaly|sentinel|tetragon|loadgen', ' '.join(argv), re.I):
            detail=dict(cgroup=read('/proc/'+pid+'/cgroup'))
            try: detail['cwd']=os.readlink('/proc/'+pid+'/cwd')
            except OSError: pass
            if '-m' in argv:
                module=argv[argv.index('-m')+1]
                if re.fullmatch(r'[a-zA-Z0-9_.-]{1,120}',module):detail['module']=module
            scripts=[x for x in argv[:3] if x.endswith(('.py','.sh')) and '\n' not in x]
            if scripts:detail['script']=scripts[0]
            for flag in ('--config','--root','--output','--interval-ms'):
                if flag in argv:
                    i=argv.index(flag)
                    if i+1<len(argv) and len(argv[i+1])<300:detail[flag.lstrip('-')]=argv[i+1]
            try:
                environment=P('/proc/'+pid+'/environ').read_bytes().split(b'\0')
                for item in environment:
                    if item.startswith(b'PYTHONPATH='):detail['pythonpath']=item.decode(errors='replace')[11:]
            except OSError: pass
            row['project']=detail
    except (OSError,IndexError):pass
    processes.append(row)
out['processes']=processes
out['process_count']=len(processes)
out['top_cpu']=sorted(processes,key=lambda x:x['cpu_percent'],reverse=True)[:15]
out['top_rss']=sorted(processes,key=lambda x:x['rss_kib'],reverse=True)[:15]
out['top_cpu_note']='ps pcpu is lifetime average; top_cpu_5s is an interval sample; audit helpers under 10s old are excluded from the latter'
def ticks(pid):
    try:
        fields=P('/proc/'+str(pid)+'/stat').read_text().rsplit(')',1)[1].split()
        return int(fields[11])+int(fields[12])
    except (OSError,IndexError,ValueError):return None
def system_ticks():return [int(v) for v in P('/proc/stat').read_text().splitlines()[0].split()[1:9]]
before={row['pid']:ticks(row['pid']) for row in processes if row['age_seconds']>=10}
system_before=system_ticks();sample_start=time.monotonic();time.sleep(5)
elapsed=time.monotonic()-sample_start;system_after=system_ticks()
delta=[b-a for a,b in zip(system_before,system_after)];total=max(sum(delta),1)
out['cpu_5s']=dict(elapsed=elapsed,busy_percent=100*(total-delta[3]-delta[4])/total,
                   iowait_percent=100*delta[4]/total,steal_percent=100*delta[7]/total)
interval=[]
for row in processes:
    old=before.get(row['pid']);new=ticks(row['pid'])
    if old is not None and new is not None:
        interval.append(dict(pid=row['pid'],command=row['command'],
            cpu_percent=100*max(new-old,0)/os.sysconf('SC_CLK_TCK')/elapsed))
out['top_cpu_5s']=sorted(interval,key=lambda x:x['cpu_percent'],reverse=True)[:10]
if shutil.which('vmware-toolbox-cmd'):
    for metric in ('balloon','swap'):
        try:out['vmware_'+metric]=command(['vmware-toolbox-cmd','stat',metric]).strip()
        except Exception as e:out['errors']['vmware_'+metric]=str(e)
out['baseline_files']={}
for name in ('/var/lib/sentinel-pulse/features.jsonl','/var/lib/sentinel-pulse/features.jsonl.health.json'):
    try:
        st=P(name).stat();out['baseline_files'][name]=dict(size_bytes=st.st_size,mtime=st.st_mtime)
    except OSError:pass
try:out['ntp']=command(['timedatectl','show','-p','NTPSynchronized','-p','NTP']).strip()
except Exception as e:out['errors']['ntp']=str(e)
try:
    units=json_command(['systemctl','list-units','--all','--type=service','--output=json','--no-pager'])
    out['services']=[{k:u.get(k) for k in ('unit','load','active','sub')} for u in units]
    names=[u['unit'] for u in units if re.search(r'pulse|sentinel|syscall|tetragon|aims|kubelet|containerd|nfs-server',u['unit'])]
    fields=['Id','LoadState','ActiveState','SubState','MainPID','Result','NRestarts','ExecMainStatus',
        'UnitFileState','MemoryCurrent','MemoryMax','CPUUsageNSec','ActiveEnterTimestamp',
        'InactiveEnterTimestamp','Restart','FragmentPath']
    blocks=command(['systemctl','show',*names,'--property='+','.join(fields)]).strip().split('\n\n') if names else []
    out['project_services']=[dict(line.split('=',1) for line in b.splitlines() if '=' in line) for b in blocks]
    out['failed_services']=[u for u in out['services'] if u['active']=='failed']
    out['timers']=json_command(['systemctl','list-timers','--all','--output=json','--no-pager'])
except Exception as e:out['errors']['systemd']=str(e)
if socket.gethostname()=='k8s-master.local':
    archive=P('/mnt/sentinel-pulse-archive')
    out['experiments']={}
    paths=[*archive.glob('matched-parallel-20261015/workers/*/STATUS.json'),
      archive/'matched-parallel-r4-20261015/syscall-matched-study/STATUS.json',
      archive/'matched-parallel-r5-rabbit-20261015/pulse-development-matrix/STATUS.json']
    for p in paths:
        try:
            d=json.loads(p.read_text())
            item={k:d.get(k) for k in ('state','node_name','completed_seconds','issues','feature_rows',
              'scored_rows','preview_positive','updated_at_unix','started_at_unix','finished_at_unix',
              'current_segment','current_model','expected_models','completed_models','expected_pairs',
              'completed_pairs','confusion_matrix_expected_control_labels','kernel_to_preview_seconds') if k in d}
            if isinstance(d.get('completed'),dict):item['checkpoint_models']=len(d['completed'])
            if 'unknown' in d:item['unknown']=len(d['unknown']) if isinstance(d['unknown'],dict) else d['unknown']
            if d.get('updated_at_unix'):item['heartbeat_age_seconds']=time.time()-d['updated_at_unix']
            out['experiments'][str(p)]=item
        except Exception as e:out['errors'][str(p)]=str(e)
    out['git']={}
    for repo in ('/home/dat/eBPF-project-current','/home/dat/eBPF-project'):
        try:
            out['git'][repo]=dict(commit=command(['git','-C',repo,'rev-parse','HEAD']).strip(),
                changes=command(['git','-C',repo,'status','--porcelain']).splitlines())
        except Exception as e:out['errors'][repo]=str(e)
print(json.dumps(out,sort_keys=True))
'''


def inspect(host, password):
    client=paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    try:
        client.connect(host, username='dat', password=password, timeout=8,
                       allow_agent=False, look_for_keys=False)
        cmd='sudo -S -p "" python3 -c '+shlex.quote(REMOTE)
        stdin,stdout,stderr=client.exec_command(cmd, timeout=50)
        stdin.write(password+'\n');stdin.flush();stdin.channel.shutdown_write()
        data=stdout.read().decode();error=stderr.read().decode()
        if stdout.channel.recv_exit_status():raise RuntimeError(error[-500:])
        return json.loads(data)
    except Exception as error:
        return dict(error=type(error).__name__+': '+str(error),inspected_at_unix=dt.datetime.now().timestamp())
    finally:client.close()


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    result=dict(schema='pulse-readonly-runtime-audit-v1',
                inspected_at_utc=dt.datetime.now(dt.timezone.utc).isoformat(),hosts={})
    password=os.environ['PULSE_SSH_PASSWORD']
    with ThreadPoolExecutor(max_workers=7) as pool:
        futures={pool.submit(inspect,h,password):h for h in HOSTS}
        for future in as_completed(futures):
            host=futures[future];row=future.result();result['hosts'][host]=row
            print(host,row.get('hostname'),row.get('process_count'),row.get('error'),flush=True)
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(result,indent=2)+'\n')


if __name__=='__main__':main()
