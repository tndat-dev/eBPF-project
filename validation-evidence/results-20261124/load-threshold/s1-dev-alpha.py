import sys, json
sys.path[:0]=['/home/dat/eBPF-project/scripts/analysis','/home/dat/eBPF-project']
import load_threshold_study as ls
E='/home/dat/eBPF-project/validation-evidence/results-20261101/lidds-v4'
OUT='/var/tmp/lid-ds-2019-v2/development'
for a in (0.0003, 0.00015):
    ls.ALPHA=a
    r21=ls.scored2021(OUT+'/lidds2021','g-n4',(E+'/lidds-evaluation-v2-alarms.json.gz',E+'/lidds-evaluation-v2-cbds-alarms.json.gz'),None)
    r19=ls.scored2019(OUT+'/caches',OUT+'/scores/g-n4',None)
    print(a, '2021dev', r21['detected'], r21['false_alarm_recordings'], round(r21['latency_p95'],3), 'cbds', r21['cb_detected'], r21['cb_false_alarm_recordings'], '2019dev', r19['tolerance']['detected'], r19['tolerance']['false_alarm_recordings'], round(r19['tolerance']['latency_p95'],2))
