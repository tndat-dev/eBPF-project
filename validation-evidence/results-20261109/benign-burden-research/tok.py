import gzip,json,collections,math,sys,re,statistics as st
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
M=json.load(open(SP+'/lm/MODELS.json')); lms={}
def lm(k):
    if k not in lms:
        p=M[k]['lm'].rsplit('/',1)[1]; lms[k]=CountTokenLM.load(SP+'/lm/'+p)
    return lms[k]
T=collections.defaultdict(list)
for r in rows: T[r['tid']].append(r)
kind={}
for t,v in T.items():
    late=any(r['alert'] and r['t']>1 for r in v); kind[t]='late' if late else 'early' if any(r['alert'] and 0<=r['t']<=1 for r in v) else 'none'
print('benign late by workload',collections.Counter(v[0]['wk'].split('/')[1][:26] for t,v in T.items() if v[0]['label']=='benign' and kind[t]=='late').most_common(12))
print('benign early by workload',collections.Counter(v[0]['wk'].split('/')[1][:26] for t,v in T.items() if v[0]['label']=='benign' and kind[t]=='early').most_common(12))
print('benign late by rate',collections.Counter((T[t][0]['tid'],) and 0 for t in []))
def top(label,cond,n=12):
    c=collections.Counter(); w=0; sc=[]; thr=[]
    for r in rows:
        if r['label']!=label or not r['alert'] or not cond(r): continue
        L=lm(r['wk']); w+=1; sc.append(r['score']); thr.append(r['thr'])
        v=sorted(((-math.log(L.prob(strip(g[:4]))),int(g[4]),g) for g in r['grams']),key=lambda x:-x[0])[:6]
        seen=set()
        for nll,cnt,g in v:
            s=strip(g[:4]); toks=dec(s[-1]); ctx='>'.join(dec(x) for x in s[-3:])
            if toks not in seen: c[toks]+=1; seen.add(toks)
    print(label,'alert windows',w,'score p50',round(st.median(sc),1) if sc else None,'margin p50',round(st.median(a-b for a,b in zip(sc,thr)),1) if sc else None,'top tokens',[(k,v) for k,v in c.most_common(n)])
top('benign',lambda r:0<=r['t']<=1)
top('benign',lambda r:r['t']>1)
for s in ('anonymous_mprotect_churn','child_ptrace_handshake','execveat_resolution_probe','invalid_setns_burst','seccomp_api_probe'):
    top('attack',lambda r:r['scenario']==s and r['t']>1,8)
top('control',lambda r:True,8)
# benign late: what is the steady stream on a non-alert workload vs alert workload
ex=[t for t,v in T.items() if v[0]['label']=='benign' and kind[t]=='late'][:1]+[t for t,v in T.items() if v[0]['label']=='benign' and kind[t]=='early'][:1]
for t in ex:
    v=sorted(T[t],key=lambda r:r['t']); r=[x for x in v if x['t']>5][0]; L=lm(r['wk'])
    print(t,r['wk'],'t',r['t'],'score',round(r['score'],1),'thr',round(r['thr'],1),'events',r['events'])
    for nll,cnt,g in sorted(((-math.log(L.prob(strip(g[:4]))),int(g[4]),g) for g in r['grams']),key=lambda x:-x[0])[:5]:
        print('   ',round(nll,1),'x',cnt,'>'.join(dec(x) for x in strip(g[:4])))
