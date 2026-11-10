import gzip,json,collections,math,sys
SP=sys.argv[1]; sys.path.insert(0,'.')
from sentinel_pulse.detector.token_model import CountTokenLM,strip
rows=[json.loads(l) for l in gzip.open(SP+'/trial-windows.jsonl.gz','rt')]
norm=[json.loads(l) for l in gzip.open(SP+'/normal-alarms.jsonl.gz','rt')]
M=json.load(open(SP+'/lm/MODELS.json')); lms={k:CountTokenLM.load(SP+'/lm/'+v['lm'].rsplit('/',1)[1]) for k,v in M.items()}
def unseen(L,g):
    s=strip(g[:4])
    return len(s)==4 and L.count[3].get(s[:3],{}).get(s[3],0)==0
def per_interval(lab):
    T=collections.defaultdict(list); A=collections.defaultdict(bool)
    for r in rows:
        if r['label']==lab and 0<=r['t']<=15:
            T[r['tid']].append(sum(unseen(lms[r['wk']],g) for g in r['grams'])); A[r['tid']]|=bool(r['alert'])
    return T,A
print('rule = a window with at least k workload-unseen 4-grams; LM = the v4 token alert')
for lab in ('control','benign','attack'):
    T,A=per_interval(lab)
    print(lab,'intervals',len(T),{f'k>={k}':sum(max(v)>=k for v in T.values()) for k in (1,2,3,5,10,20)},'LM',sum(A.values()))
ctl=[r for r in rows if r['label']=='control' and 0<=r['t']<=15]
print('normal windows',len(ctl),'share with >=1 unseen 4-gram',round(sum(any(unseen(lms[r['wk']],g) for g in r['grams']) for r in ctl)/len(ctl),4),'LM alert share',round(sum(r['alert'] for r in ctl)/len(ctl),5))
sig=collections.Counter(); kinds=collections.Counter(); by=collections.defaultdict(list)
for r in sorted(norm,key=lambda r:r['e']):
    L=lms[r['wk']]
    top=max(((-math.log(L.prob(strip(g[:4]))),tuple(strip(g[:4]))) for g in r['grams']))
    kinds['has_unseen_4gram' if any(unseen(L,g) for g in r['grams']) else 'rare_only']+=1
    s=(r['wk'],top[1]); sig[s]+=1; by[(r['pod'],r['c'])].append((r['e'],s,r['wk']))
print('normal alarm windows',len(norm),dict(kinds),'distinct top-gram signatures',len(sig),'counts',[v for k,v in sig.most_common(8)])
allr=sorted((e,k,s,w) for k,v in by.items() for e,s,w in v); last={}; seen=set(); eps=collections.Counter(); new=collections.Counter()
for e,k,s,w in allr:
    if e-last.get(k,-1e9)>=15:
        eps[w.split('/')[1][:22]]+=1
        if s not in seen: new[w.split('/')[1][:22]]+=1
    last[k]=e; seen.add(s)
print('episodes',sum(eps.values()),'with a signature not seen in any earlier alarm',sum(new.values())); print(' by workload (episodes, new):',[(k,v,new[k]) for k,v in eps.most_common(8)])
