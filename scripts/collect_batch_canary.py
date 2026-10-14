"""Copy sealed small canary results plus resource counters; leave raw on workers."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path

from sentinel_pulse.syscall_capture_campaign import Remote,WORKERS


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--credential',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--cohort',choices=('b1','b2'),required=True)
    a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False);remote=Remote(a.credential)
    cohort=a.cohort
    code='''from pathlib import Path
import hashlib,json,subprocess,time
p=Path('/var/lib/pulse-idle-batch-canary-COHORT-20261014')
files={name:(p/name).read_text() for name in ['START.json','TERMINAL.json']}
d=json.loads(files['TERMINAL.json']);verified={}
for name,expected in d['seals'].items():
 h=hashlib.sha256()
 with (p/name).open('rb') as f:
  for chunk in iter(lambda:f.read(1024*1024),b''):h.update(chunk)
 verified[name]=h.hexdigest()==expected
assert all(verified.values())
print(json.dumps(dict(files=files,verified_raw_seals=verified,checked_at_unix=time.time(),
 service=subprocess.check_output(['systemctl','show','pulse-idle-batch-canary-COHORT.service',
 '-p','ActiveState','-p','SubState','-p','Result','-p','CPUUsageNSec','-p','MemoryPeak','-p','NRestarts'],text=True))))
'''.replace('COHORT',cohort)
    def collect(host):return host,json.loads(remote.command(host,['python3','-c',code],timeout=60))
    hosts=['10.1.16.237'] if cohort=='b1' else list(WORKERS)
    with ThreadPoolExecutor(max_workers=3) as pool:
        for host,result in pool.map(collect,hosts):
            suffix=host.rsplit('.',1)[-1]
            for name,data in result.pop('files').items():(a.output/(suffix+'-'+name)).write_text(data)
            (a.output/(suffix+'-verification.json')).write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(dict(output=str(a.output),hosts=hosts,raw_not_copied=True)))


if __name__=='__main__':main()
