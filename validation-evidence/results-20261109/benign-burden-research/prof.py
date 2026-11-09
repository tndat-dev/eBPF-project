import gzip,json,collections,statistics as st,sys
rows=[json.loads(l) for l in gzip.open(sys.argv[1],'rt')]
print(len(rows), collections.Counter(r['label'] for r in rows), sorted(rows[0].keys()))
T=collections.defaultdict(list)
for r in rows: T[r['tid']].append(r)
print('trials',len(T), collections.Counter(v[0]['label'] for v in T.values()))
def prof(lab,filt=lambda r:True):
    v=[sorted(x,key=lambda r:r['t']) for x in T.values() if x[0]['label']==lab and filt(x[0])]
    fired=[x for x in v if any(r['alert'] and 0<=r['t']<=15 for r in x)]
    first=[min(r['t'] for r in x if r['alert'] and 0<=r['t']<=15) for x in fired]
    share=[sum(1 for r in x if r['alert'] and 0<=r['t']<=15)/max(1,sum(1 for r in x if 0<=r['t']<=15)) for x in v]
    late=lambda c:sum(any(r['alert'] and r['t']>c for r in x) for x in v)
    print(lab,'n',len(v),'fired',len(fired),'first p50/p95',round(st.median(first),2) if first else None, round(sorted(first)[int(.95*len(first))],2) if first else None,'share_windows_mean',round(st.mean(share),3),'median',round(st.median(share),3),'fired after t>:',{c:late(c) for c in (1,2,3,4,5,8,12)})
prof('benign'); prof('control')
for sc in sorted({v[0]['scenario'] for v in T.values() if v[0]['label']=='attack'}):
    prof('attack',lambda r:r['scenario']==sc)
for rate in (1,3,6,12,24):
    prof('attack',lambda r:r['rate']==rate)
# when relative to start: alert count by second
for lab in ('benign','attack'):
    c=collections.Counter(int(r['t']) for r in rows if r['label']==lab and r['alert'] and r['t']>=0); n=len({r['tid'] for r in rows if r['label']==lab})
    print(lab,'alerts per trial by second',{k:round(c[k]/n,2) for k in sorted(c)})
