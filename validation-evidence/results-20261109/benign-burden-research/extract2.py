# Normal alarms: token windows with token_alert true outside every trial, from sealed segments; idle priority, plain python.
import json,sys,os,collections,gzip
R='/srv/nfs/sentinel-pulse/pulse-live-v4-1109'; segs=sys.argv[1].split(','); out=sys.argv[2]
iv=collections.defaultdict(list)
for l in open(R+'/pulse-development-matrix/INTERVALS.jsonl'):
    x=json.loads(l); iv[(x['pod_uid'],x['container_name'])].append(float(x['start_at']))
n=tot=0; span={}
with gzip.open(out,'wt') as w:
    for node in ('k8s-worker1.local','k8s-worker3.local','k8s-worker4.local'):
        for s in segs:
            p=f'{R}/workers/{node}/segments/{s}/tokens.jsonl'
            for line in open(p):
                tot+=1
                if '"token_alert":true' not in line: continue
                d=json.loads(line); e=d['window_end']
                if any(st-2<=e<=st+18 for st in iv.get((d['pod_uid'],d['container_name']),())): continue
                w.write(json.dumps(dict(wk=d['workload_key'],pod=d['pod_uid'],c=d['container_name'],e=e,score=d['token_score'],thr=d['token_threshold'],events=d.get('events'),grams=d['grams']))+'\n'); n+=1
print('normal alarms',n,'of windows',tot)
