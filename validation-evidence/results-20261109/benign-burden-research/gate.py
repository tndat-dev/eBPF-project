import gzip,json,collections,math,sys,re
SP=sys.argv[1]; sys.path.insert(0,'.')
from sentinel_pulse.detector.token_model import CountTokenLM,strip
names={}
for l in open('/usr/include/x86_64-linux-gnu/asm/unistd_64.h'):
    m=re.match(r'#define __NR_(\w+) (\d+)',l)
    if m: names[int(m.group(2))]=m.group(1)
def dec(t):
    nr,k,low=t>>23,(t>>21)&3,t&0x1fffff
    n=names.get(nr,str(nr))
    return n if k==0 else f'{n}!{low&0xfff}' if k==1 else f'{n}#{low&15}' if k==2 else f'{n}:{"w" if low>>20 else "r"}:{low&0xfffff:x}'
rows=[json.loads(l) for l in gzip.open(SP+'/trial-windows.jsonl.gz','rt')]
norm=[json.loads(l) for l in gzip.open(SP+'/normal-alarms.jsonl.gz','rt')]
M=json.load(open(SP+'/lm/MODELS.json')); lms={k:CountTokenLM.load(SP+'/lm/'+v['lm'].rsplit('/',1)[1]) for k,v in M.items()}
# pooled unseen sets by n (level k holds contexts of length k -> next token)
seen=[set() for _ in range(5)]; tok=set(); 
for L in lms.values():
    for ws in L.given.values(): tok|=set(ws)
    for k in range(1,len(L.count)):
        for h,ws in L.count[k].items():
            for w in ws: seen[k+1].add(tuple(h)+(w,))
print('pool distinct tokens',len(tok),'bigrams',len(seen[2]),'tri',len(seen[3]),'4',len(seen[4]))
def unseen(grams):
    """n -> tokens/ngrams of the window never seen in any workload's normal."""
    out={1:set(),2:set(),3:set(),4:set()}
    for g in grams:
        s=strip(g[:4])
        if s[-1] not in tok: out[1].add(s[-1:])
        for n in (2,3,4):
            if len(s)>=n and tuple(s[-n:]) not in seen[n]: out[n].add(tuple(s[-n:]))
    return out
T=collections.defaultdict(list)
for r in rows:
    r['u']=unseen(r['grams']); T[r['tid']].append(r)
def hit(v,n,lo=0.0): return any(r['alert'] and lo<=r['t']<=15 and r['u'][n] for r in v)
print('gate: alert window also has something unseen across the cluster')
for n,lo in ((1,0),(2,0),(3,0),(4,0),(1,1),(2,1),(3,1),(4,1)):
    b=[v for v in T.values() if v[0]['label']=='benign']; a=[v for v in T.values() if v[0]['label']=='attack']; c=[v for v in T.values() if v[0]['label']=='control']
    pr=[v for v in a if v[0]['rate'] in (6,12,24)]
    sc={s[:7]:f"{sum(hit(v,n,lo) for v in a if v[0]['scenario']==s)}/{sum(1 for v in a if v[0]['scenario']==s)}" for s in sorted({v[0]['scenario'] for v in a})}
    print('n',n,'from_t',lo,'benign',f"{sum(hit(v,n,lo) for v in b)}/{len(b)}",'control',f"{sum(hit(v,n,lo) for v in c)}/{len(c)}",'attack',f"{sum(hit(v,n,lo) for v in a)}/{len(a)}",'primary',f"{sum(hit(v,n,lo) for v in pr)}/{len(pr)}",sc)
c1=collections.Counter()
for r in rows:
    if r['label']=='benign' and r['alert']:
        for x in r['u'][1]: c1[dec(x[0])]+=1
print('benign unseen tokens',c1.most_common(10))
c2=collections.Counter()
for r in rows:
    if r['label']=='attack' and r['alert']:
        for x in r['u'][1]: c2[(r['scenario'][:7],dec(x[0]))]+=1
print('attack unseen tokens',c2.most_common(12))
print('--- normal alarms',len(norm))
for r in norm: r['u']=unseen(r['grams'])
def eps(rs):
    by=collections.defaultdict(list)
    for r in rs: by[(r['pod'],r['c'])].append(r['e'])
    return sum(1+sum(b-a>=15 for a,b in zip(sorted(v),sorted(v)[1:])) for v in by.values())
print('episodes all',eps(norm),{f'n{n}':eps([r for r in norm if r['u'][n]]) for n in (1,2,3,4)})
print('by workload',collections.Counter(r['wk'].split('/')[1][:24] for r in norm).most_common(10))
print('episodes by workload',sorted(((eps([r for r in norm if r['wk']==k]),k.split('/')[1][:24]) for k in {r['wk'] for r in norm}),reverse=True)[:10])
top=collections.Counter()
for r in norm:
    L=lms[r['wk']]
    for nll,g in sorted(((-math.log(L.prob(strip(g[:4]))),g) for g in r['grams']),key=lambda x:-x[0])[:3]:
        top['>'.join(dec(x) for x in strip(g[:4])[-2:])]+=1
print('top surprising bigrams',top.most_common(16))
m=sorted(r['score']-r['thr'] for r in norm); print('margin p10/50/90',[round(m[int(q*len(m))],1) for q in (.1,.5,.9)])
