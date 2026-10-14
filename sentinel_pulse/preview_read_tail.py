"""Read recent complete decisions from the writer's own filesystem client."""
import argparse
import json
from pathlib import Path


def read(root, since, pod_uid, cgroup_id):
    for path in sorted(root.glob('segments/s*/decisions.jsonl'))[-2:]:
        with path.open('rb') as stream:
            offset=max(0,path.stat().st_size-32*1024**2);stream.seek(offset)
            if offset:stream.readline()
            for line in stream:
                if not line.endswith(b'\n'):continue
                row=json.loads(line)
                if (row.get('window_end',0)>=since and row.get('pod_uid')==pod_uid
                        and str(row.get('cgroup_id'))==str(cgroup_id)):
                    yield row


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root',type=Path,required=True);p.add_argument('--since',type=float,required=True)
    p.add_argument('--pod-uid',required=True);p.add_argument('--cgroup-id',required=True)
    a=p.parse_args()
    for row in read(a.root,a.since,a.pod_uid,a.cgroup_id):
        print(json.dumps(row,separators=(',',':')))
