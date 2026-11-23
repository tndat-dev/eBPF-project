import json, glob, hashlib, collections
F='/mnt/sentinel-pulse-archive/pulse-live-diurnal-fit-1122'
models=json.load(open(F+'/token/MODELS.json'))
sched=json.load(open('/mnt/sentinel-pulse-archive/pulse-token-capture-diurnal-1121/CONFIG.json'))['traffic_schedule'][:-1]
def regime(t):
    for p in sched:
        if p['start']<=t<p['end']: return p['regime']
    return 'final-run tail (steady)'
tot=collections.defaultdict(lambda:[0,0])
for w,m in models.items():
    path=f"{F}/maxima/{hashlib.sha256(w.encode()).hexdigest()[:16]}.maxima.json"
    for pod,c,b,v in json.load(open(path))['blocks']:
        r=regime(b*60.0); tot[r][0]+=1; tot[r][1]+=v>m['threshold']
a=sum(v[1] for v in tot.values()); n=sum(v[0] for v in tot.values())
print('pooled',n,a,round(100*a/n,3))
for r,(n,k) in sorted(tot.items(), key=lambda kv:-kv[1][1]/kv[1][0]): print(r,n,k,round(100*k/n,3))
