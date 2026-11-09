import gzip,json,collections,math,sys,re,statistics as st
SP=sys.argv[1]; sys.path.insert(0,'.')
from sentinel_pulse.detector.token_model import CountTokenLM,strip
rows=[json.loads(l) for l in gzip.open(SP+'/trial-windows.jsonl.gz','rt')]
M=json.load(open(SP+'/lm/MODELS.json')); lms={k:CountTokenLM.load(SP+'/lm/'+v['lm'].rsplit('/',1)[1]) for k,v in M.items()}
def pooled(skip=None):
    P=CountTokenLM()
    for k,L in lms.items():
        if k==skip: continue
        # counts at the top level hold (context -> next) with c; rebuild from the longest context level plus shorter starts
        for lvl in range(len(L.count)):
            for h,ws in L.count[lvl].items():
                for w,c in ws.items(): P.count[lvl][h][w]+=c
        for n,c in L.names.items(): P.names[n]+=c
        for n,ws in L.given.items():
            for w,c in ws.items(): P.given[n][w]+=c
        P.total+=L.total
    return P.finalize()
P=pooled(); print('pool total',P.total,'names',len(P.names))
import numpy as np
names={}
for l in open('/usr/include/x86_64-linux-gnu/asm/unistd_64.h'):
    m=re.match(r'#define __NR_(\w+) (\d+)',l)
    if m: names[m.group(2)]=m.group(1)
inv={v:int(k) for k,v in names.items()}
for n in ('getpid','clock_nanosleep','nanosleep','ptrace','setns','seccomp','execveat','mprotect','keyctl','setuid','setgid','prlimit64','arch_prctl','brk','unshare','mount','capset','chmod','fork','clone','execve'):
    print(n,P.names.get(inv.get(n),0),end=' | ')
print()
rows_by=collections.defaultdict(list)
for r in rows:
    r['pool']=P.window_score(r['grams']); rows_by[r['tid']].append(r)
print('pool score of alert windows p5/50/95:',{lab:[round(np.percentile([r['pool'] for r in rows if r['label']==lab and r['alert']] or [0],q),1) for q in (5,50,95)] for lab in ('benign','attack','control')})
def trial_hit(v,gate):
    return any(r['alert'] and 0<=r['t']<=15 and r['pool']>gate for r in v)
print('gate | benign | control | attack all | primary | by scenario (all rates)')
for gate in (-1,4,6,8,10,12,14,16,18,20,24):
    b=[v for v in rows_by.values() if v[0]['label']=='benign']; c=[v for v in rows_by.values() if v[0]['label']=='control']; a=[v for v in rows_by.values() if v[0]['label']=='attack']
    pr=[v for v in a if v[0]['rate'] in (6,12,24)]
    sc={s[:7]:f"{sum(trial_hit(v,gate) for v in a if v[0]['scenario']==s)}/{sum(1 for v in a if v[0]['scenario']==s)}" for s in sorted({v[0]['scenario'] for v in a})}
    print(gate,f"{sum(trial_hit(v,gate) for v in b)}/{len(b)}",f"{sum(trial_hit(v,gate) for v in c)}/{len(c)}",f"{sum(trial_hit(v,gate) for v in a)}/{len(a)}",f"{sum(trial_hit(v,gate) for v in pr)}/{len(pr)}",sc)
