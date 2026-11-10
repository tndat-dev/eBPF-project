import json,collections,glob
M="/mnt/sentinel-pulse-archive/pulse-live-v4-1109/pulse-development-matrix"
A=['T','C','tree','support']
def fired(r):
    st=r.get('status'); o=set()
    if st=='token-score' and r.get('candidate_alert_preview') is True: o.add('T')
    if st=='candidate-raw-score-only':
        if r.get('v3_tree_alert'): o|={'C','tree'}
        if r.get('v3_support_alert'): o|={'C','support'}
    return o
res=collections.defaultdict(lambda:collections.defaultdict(lambda:[0,0])); lat=collections.defaultdict(list); emit=collections.defaultdict(list); ctl=collections.Counter(); ben=collections.Counter(); n=collections.Counter()
for p in sorted(glob.glob(M+"/trials/*/EVALUATION_INPUT.json")):
    e=json.load(open(p)); a=e['attack']; d=e.get('decisions') or []
    def hits(iv):
        s=iv.get('injected_at') or iv.get('start_at'); h={}
        for r in d:
            if r.get('pod_uid')==iv['pod_uid'] and r.get('container_name')==iv['container_name'] and r.get('window_end') is not None and s<=r['window_end']<=s+15:
                for b in fired(r):
                    if r['window_end']<h.get(b,(1e18,0))[0]: h[b]=(r['window_end'],r.get('preview_emitted_at') or r['window_end'])
        return h
    h=hits(a); k0=a.get('kernel_event_at') or a['injected_at']
    for key in (('rate',a['rate_per_second']),('scen',a['scenario'][:12]),('all',0))+((('primary',0),) if a['rate_per_second'] in (6,12,24) else ()):
        for b in A:
            res[key][b][1]+=1; res[key][b][0]+=b in h
    if a['rate_per_second'] in (6,12,24):
        for b in A:
            if b in h: lat[b].append(h[b][0]-k0); emit[b].append(h[b][1]-k0)
    for kind,cnt in (('control',ctl),('benign',ben)):
        iv=e.get(kind) or {}
        if iv.get('pod_uid'):
            hh=hits(iv); n[kind]+=1
            for b in A: cnt[b]+=b in hh
for key in sorted(res,key=str): print(key,{b:f"{res[key][b][0]}/{res[key][b][1]}" for b in A})
q=lambda x,p:round(sorted(x)[min(len(x)-1,int(p*len(x)))],2) if x else None
print('primary latency kernel->window end p50/p95',{b:(q(lat[b],.5),q(lat[b],.95)) for b in A}); print('primary latency kernel->decision emitted p50/p95',{b:(q(emit[b],.5),q(emit[b],.95)) for b in A})
print('idle control',dict(ctl),'of',n['control'],'| benign',dict(ben),'of',n['benign'])
