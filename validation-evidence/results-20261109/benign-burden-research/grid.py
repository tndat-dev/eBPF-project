import gzip,json,collections,math,sys,re
SP=sys.argv[1]; sys.path.insert(0,'.')
from sentinel_pulse.detector.token_model import CountTokenLM,strip,call_of
rows=[json.loads(l) for l in gzip.open(SP+'/trial-windows.jsonl.gz','rt')]
norm=[json.loads(l) for l in gzip.open(SP+'/normal-alarms.jsonl.gz','rt')]
M=json.load(open(SP+'/lm/MODELS.json')); lms={k:CountTokenLM.load(SP+'/lm/'+v['lm'].rsplit('/',1)[1]) for k,v in M.items()}
P=CountTokenLM()
for L in lms.values():
    for lvl in range(len(L.count)):
        for h,ws in L.count[lvl].items():
            for w,c in ws.items(): P.count[lvl][h][w]+=c
    for n,c in L.names.items(): P.names[n]+=c
    for n,ws in L.given.items():
        for w,c in ws.items(): P.given[n][w]+=c
    P.total+=L.total
P.finalize()
EXECVE=59
def has_exec(g): return any((int(t)>>23)==EXECVE for *x,c in g for t in [x[3]] if int(t)!=0xFFFFFFFF)
T=collections.defaultdict(list)
for r in rows:
    r['p']=P.window_score(r['grams']); r['x']=has_exec(r['grams']); T[r['tid']].append(r)
for v in T.values(): v.sort(key=lambda r:r['t'])
print('trials',collections.Counter(v[0]['label'] for v in T.values()))
bx=[any(r['x'] for r in v if -1<=r['t']<=1) for v in T.values() if v[0]['label']=='benign']; print('benign with execve token within 1 s of start',sum(bx),len(bx))
ax=[any(r['x'] for r in v if -1<=r['t']<=1) for v in T.values() if v[0]['label']=='attack']; print('attack same',sum(ax),len(ax)); cx=[any(r['x'] for r in v) for v in T.values() if v[0]['label']=='control']; print('control windows with execve (probes)',sum(cx),len(cx))
def fired(v,Tp,skip,win=0):
    last=-1e9
    for r in v:
        if r['x']: last=r['t']
        if 0<=r['t']<=15 and r['alert'] and r['p']>Tp and (skip==0 or r['t']-last>skip) : return True
    return False
lab=lambda L:[v for v in T.values() if v[0]['label']==L]; A,B,C=lab('attack'),lab('benign'),lab('control'); PR=[v for v in A if v[0]['rate'] in (6,12,24)]
scen=sorted({v[0]['scenario'] for v in A})
print('Tp skip | benign control attack_all primary | primary by scenario')
for Tp in (0,14,16,18,20):
    for skip in (0,1,2,3):
        f=lambda S:sum(fired(v,Tp,skip) for v in S)
        print(Tp,skip,'|',f"{f(B)}/{len(B)}",f"{f(C)}/{len(C)}",f"{f(A)}/{len(A)}",f"{f(PR)}/{len(PR)}",'|',{s[:6]:f"{f([v for v in PR if v[0]['scenario']==s])}/{sum(1 for v in PR if v[0]['scenario']==s)}" for s in scen})
for r in norm: r['p']=P.window_score(r['grams'])
def eps(rs):
    by=collections.defaultdict(list)
    for r in rs: by[(r['pod'],r['c'])].append(r['e'])
    return sum(1+sum(b-a>=15 for a,b in zip(sorted(v),sorted(v)[1:])) for v in by.values())
print('normal token episodes in sample by Tp',{Tp:eps([r for r in norm if r['p']>Tp]) for Tp in (0,10,12,14,16,18,20)})
