import gzip,json,collections,math,sys
SP=sys.argv[1]; sys.path.insert(0,'.')
from sentinel_pulse.detector.token_model import CountTokenLM,strip
norm=sorted((json.loads(l) for l in gzip.open(SP+'/normal-alarms.jsonl.gz','rt')),key=lambda r:r['e'])
rows=[json.loads(l) for l in gzip.open(SP+'/trial-windows.jsonl.gz','rt')]
M=json.load(open(SP+'/lm/MODELS.json')); lms={k:CountTokenLM.load(SP+'/lm/'+v['lm'].rsplit('/',1)[1]) for k,v in M.items()}
def unseen_set(r):
    L=lms[r['wk']]; out=set()
    for g in r['grams']:
        s=strip(g[:4])
        if len(s)==4 and L.count[3].get(s[:3],{}).get(s[3],0)==0: out.add(s)
    return out
def episodes(rs):
    last={}; n=0
    for r in rs:
        k=(r['pod'],r['c'])
        if r['e']-last.get(k,-1e9)>=15: n+=1
        last[k]=r['e']
    return n
print('baseline episodes',episodes(norm),'windows',len(norm))
# learnt-normal memory per workload: unseen grams of past alarm windows, added `delay` s after the window when seen in >= pods distinct pods
for pods,delay in ((1,60),(1,600),(2,60),(2,600),(2,3600)):
    mem=collections.defaultdict(dict)  # wk -> gram -> (set pods, first time)
    kept=[]
    for r in norm:
        u=unseen_set(r); m=mem[r['wk']]
        known={g for g in u if g in m and len(m[g][0])>=pods and r['e']-m[g][1]>=delay}
        if u-known: kept.append(r)       # still has something new -> still alarms (approximation: alarm iff a not-yet-learnt unseen gram remains)
        for g in u:
            if g not in m: m[g]=(set(),r['e'])
            m[g][0].add(r['pod'])
    print(f'learn after {pods} pod(s), {delay} s: episodes',episodes(kept),'windows',len(kept))
# would that memory also swallow attacks? grams learnt from normal alarms vs unseen grams in attack/benign alert windows
learnt=collections.defaultdict(set)
for r in norm: learnt[r['wk']]|=unseen_set(r)
for lab in ('attack','benign'):
    T=collections.defaultdict(bool)
    for r in rows:
        if r['label']==lab and 0<=r['t']<=15 and r['alert']:
            r2=dict(r,pod=r['pod']); T[r['tid']]|=bool(unseen_set(r)-learnt[r['wk']])
    print(lab,'trials with an alert window still holding a gram outside the learnt set',sum(T.values()),len(T))
print('learnt grams total',sum(len(v) for v in learnt.values()))
