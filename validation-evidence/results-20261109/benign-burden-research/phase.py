import gzip,json,collections,math,sys
import numpy as np
SP=sys.argv[1]; sys.path.insert(0,'.'); sys.path.insert(0,'scripts/analysis')
from sentinel_pulse.detector.token_model import CountTokenLM,has_execve
rows=[json.loads(l) for l in gzip.open(SP+'/trial-windows.jsonl.gz','rt')]
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
T=collections.defaultdict(list)
for r in rows: r['p']=P.window_score(r['grams']); r['x']=has_execve(r['grams']); T[r['tid']].append(r)
for v in T.values():
    v.sort(key=lambda r:r['t']); last=-1e9
    for r in v:
        if r['x']: last=r['t']
        r['phase']=r['t']-last<=1.0
# normal = idle control intervals only (no labels of attack or benign): exec windows of the probes
N=[r for v in T.values() if v[0]['label']=='control' for r in v]
inp=np.array([r['score'] for r in N if r['phase']]); inp_p=np.array([r['p'] for r in N if r['phase']]); out=np.array([r['score'] for r in N if not r['phase']]); out_p=np.array([r['p'] for r in N if not r['phase']])
print('normal windows in phase',len(inp),'out',len(out)); q=lambda x:[round(float(np.percentile(x,p)),1) for p in (50,95,99,100)]
print('workload score in phase p50/95/99/max',q(inp),'| out',q(out)); print('pool score in phase',q(inp_p),'| out',q(out_p))
for lab in ('benign','attack'):
    W=[r for v in T.values() if v[0]['label']==lab for r in v if 0<=r['t']<=15]
    print(lab,'alert windows in phase: pool',q(np.array([r['p'] for r in W if r['phase'] and r['alert']])),'workload',q(np.array([r['score'] for r in W if r['phase'] and r['alert']])))
    print(lab,'alert windows after phase: pool',q(np.array([r['p'] for r in W if not r['phase'] and r['alert']])),'workload',q(np.array([r['score'] for r in W if not r['phase'] and r['alert']])))
def fired(v,tp_in,tp_out):
    for r in v:
        if 0<=r['t']<=15 and r['alert'] and r['p']>(tp_in if r['phase'] else tp_out): return True
    return False
lab=lambda L:[v for v in T.values() if v[0]['label']==L]; A,B,C=lab('attack'),lab('benign'),lab('control'); PR=[v for v in A if v[0]['rate'] in (6,12,24)]
print('Tin Tout | benign control attack_all primary')
for ti in (14,18,22,26,30,34,99):
    for to in (0,14,16):
        f=lambda S:sum(fired(v,ti,to) for v in S)
        print(ti,to,'|',f"{f(B)}/{len(B)}",f"{f(C)}/{len(C)}",f"{f(A)}/{len(A)}",f"{f(PR)}/{len(PR)}")
