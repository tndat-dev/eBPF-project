import gzip,json,collections,math,sys
SP=sys.argv[1]; sys.path.insert(0,'.')
from sentinel_pulse.detector.token_model import CountTokenLM,strip,TOP
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
def score(r,lam):
    L=lms[r['wk']]; vals=[]
    for *g,c in r['grams']:
        s=strip(g); vals.append((-math.log((1-lam)*L.prob(s)+lam*P.prob(s)),int(c)))
    vals.sort(reverse=True); taken=tot=0
    for nll,c in vals:
        u=min(c,TOP-taken); tot+=nll*u; taken+=u
        if taken==TOP: break
    return tot/taken if taken else 0.
T=collections.defaultdict(list)
for r in rows:
    if 0<=r['t']<=15: T[r['tid']].append(r)
import random
def auc(a,b):
    return sum((x>y)+.5*(x==y) for x in a for y in b)/(len(a)*len(b))
for lam in (0,.001,.01,.1,.5,1):
    mx={t:max(score(r,lam) for r in v) for t,v in T.items()}
    late={t:max([score(r,lam) for r in v if r['t']>=1] or [0]) for t,v in T.items()}
    lab=lambda t:T[t][0]['label']; pr=lambda t:T[t][0].get('rate') in (6,12,24)
    A=[mx[t] for t in T if lab(t)=='attack' and pr(t)]; B=[mx[t] for t in T if lab(t)=='benign']; C=[mx[t] for t in T if lab(t)=='control']
    AL=[late[t] for t in T if lab(t)=='attack' and pr(t)]; BL=[late[t] for t in T if lab(t)=='benign']; CL=[late[t] for t in T if lab(t)=='control']
    q=lambda x,p:round(sorted(x)[int(p*(len(x)-1))],1)
    print('lam',lam,'whole AUC atk-vs-benign',round(auc(A,B),3),'atk min/p50',q(A,0),q(A,.5),'benign p50/max',q(B,.5),q(B,1),'ctl max',q(C,1),'| t>=1 AUC',round(auc(AL,BL),3),'atk min',q(AL,0),'benign p50/p90',q(BL,.5),q(BL,.9),'ctl max',q(CL,1),'| normal alarms p50',q([score(r,lam) for r in norm],.5))
