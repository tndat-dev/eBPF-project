"""Copy small sealed results, not raw telemetry, from both experiment branches."""
import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import time

from sentinel_pulse.syscall_capture_campaign import Remote, WORKERS


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--credential',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False);remote=Remote(a.credential)
    hashes={}
    def save(name,raw):
        data=raw.encode() if isinstance(raw,str) else raw
        (a.output/name).write_bytes(data);hashes[name]=hashlib.sha256(data).hexdigest()
        return json.loads(data)
    def fetch(host):
        path='/var/lib/pulse-shadow-review/normal-a1-20261013-r2/TERMINAL.json'
        raw=remote.command(host,['python3','-c','import sys;from pathlib import Path;sys.stdout.write(Path('+repr(path)+').read_text())'])
        return host,raw
    workers={};statuses=Counter();previews=Counter();ages=Counter();inference=Counter();gaps=0;scored=0
    with ThreadPoolExecutor(max_workers=3) as pool:
        for host,raw in pool.map(fetch,WORKERS):
            d=save('pulse-review-'+host.rsplit('.',1)[-1]+'.json',raw)
            if d['state']!='completed_shadow_summary':raise ValueError('incomplete review')
            workers[host]=d;statuses.update(d['status_counts']);gaps+=d['decision_count_minus_capture_feature_rows']
            for k,w in d['workloads'].items():
                previews[k]+=w['preview_positive'];scored+=w['scored']
                ages.update(w['feature_end_to_score_age_buckets_seconds']);inference.update(w['inference_time_buckets_ms'])
    path='/home/dat/pulse-idle-batch-b1-20261014/results/TERMINAL.json'
    benchmark=save('batch-benchmark.json',remote.command('10.1.16.237',['python3','-c',
        'import sys;from pathlib import Path;sys.stdout.write(Path('+repr(path)+').read_text())']))
    campaign=Path('/mnt/sentinel-pulse-archive/syscall-capture-c3-r2')
    for name in ('TERMINAL.json','SELECTION_COHORT.json','selection-preflight-complete-20261014.json',
                 'holdout-preflight-complete-20261014.json'):
        save('c3-'+name,(campaign/name).read_bytes())
    totals=dict(checked_at_unix=time.time(),pulse=dict(status_counts=dict(statuses),scored=scored,
        preview_positive_pending_adjudication=dict(previews),decision_count_minus_capture_features=gaps,
        feature_window_end_to_score_buckets_seconds=dict(ages),inference_buckets_ms=dict(inference),
        precision=None,recall=None,false_positive_rate=None,kernel_to_alert=None),
        artifact_sha256=hashes,raw_copied=False,automatic_promotion=False)
    (a.output/'SUMMARY.json').write_text(json.dumps(totals,indent=2)+'\n')
    print(json.dumps(dict(output=str(a.output),statuses=dict(statuses),scored=scored,
        previews=sum(previews.values()),count_difference=gaps,benchmark_state=benchmark['state'])))


if __name__=='__main__':main()
