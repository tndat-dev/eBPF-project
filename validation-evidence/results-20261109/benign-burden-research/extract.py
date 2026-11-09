# Light extract on the NFS server: token windows of a few sealed segments around each trial, plain python, no numpy.
import json,sys,glob,os,gzip,collections
R='/srv/nfs/sentinel-pulse/pulse-live-v4-1109'; segs=sys.argv[1].split(','); out=sys.argv[2]
iv=[json.loads(l) for l in open(R+'/pulse-development-matrix/INTERVALS.jsonl')]
idx=collections.defaultdict(list)
for x in iv:
    lab='attack' if x['label']=='attack' else 'benign' if x.get('control_kind') else 'control'
    idx[(x['pod_uid'],x['container_name'])].append((float(x['start_at']),lab,x['trial_id'],x.get('scenario'),x.get('rate_per_second'),x['workload_key']))
for k in idx: idx[k].sort()
n=0
with gzip.open(out,'wt') as w:
    for node in ('k8s-worker1.local','k8s-worker3.local','k8s-worker4.local'):
        for s in segs:
            p=f'{R}/workers/{node}/segments/{s}/tokens.jsonl'
            if not os.path.exists(p): p+='.gz'
            if not os.path.exists(p): continue
            f=gzip.open(p,'rt') if p.endswith('gz') else open(p)
            for line in f:
                d=json.loads(line); k=(d['pod_uid'],d['container_name'])
                if k not in idx: continue
                e=d['window_end']
                for st,lab,tid,sc,rate,wl in idx[k]:
                    if st-1<=e<=st+16:
                        w.write(json.dumps(dict(tid=tid,label=lab,scenario=sc,rate=rate,wk=wl,t=round(e-st,3),score=d.get('token_score'),thr=d.get('token_threshold'),alert=d.get('token_alert'),events=d.get('events'),grams=d['grams'],pod=d['pod_uid'][:8],node=node))+'\n'); n+=1
                        break
print('windows',n)
