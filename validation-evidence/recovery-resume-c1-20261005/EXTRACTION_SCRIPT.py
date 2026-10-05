import json
from collections import deque
from pathlib import Path
import socket
from sentinel_pulse.encoding import decode_vector, schema_digest
from sentinel_pulse.features import PulseFeatureBuilder
from sentinel_pulse.integrity import sha256_file

root = Path('/var/lib/sentinel-pulse-500ms/runs/pulse-recovery-resume-c1-20261005')
samples = {}
normal = None
with (root / 'decisions.jsonl').open() as stream:
    for line in stream:
        row = json.loads(line)
        if row.get('schema') != 'sentinel-pulse-decision-v1':
            continue
        if row.get('status') in {'normal', 'suppressed', 'warming', 'telemetry-degraded'}:
            samples.setdefault(row['status'], row)
        if row.get('status') == 'normal' and row.get('workload_key') == 'production/aims-rabbitmq-server:rabbitmq':
            normal = row
if normal is None:
    raise ValueError('no real RabbitMQ normal decision')
prior = deque(maxlen=13)
target = None
columns = PulseFeatureBuilder(rolling_windows=10).columns
with (root / 'features.jsonl').open() as stream:
    for line in stream:
        row = json.loads(line)
        if row.get('schema') != 'sentinel-pulse-feature-v1':
            continue
        if (str(row['cgroup_id']) == normal['cgroup_id'] and row.get('pod_uid') == normal['pod_uid']
                and row.get('workload_key') == normal['workload_key']):
            if row['window_end'] == normal['window_end']:
                target = row
                break
            prior.append(row)
if target is None or target['window_start'] != normal['window_start']:
    raise ValueError('feature and decision do not identify same window')
if schema_digest(columns) != target['feature_schema_sha256']:
    raise ValueError('example schema does not match source columns')
vector = decode_vector(target)
named = {name: float(value) for name,value in zip(columns,vector)}
history = list(prior)[-3:]
if len(history) != 3:
    raise ValueError('missing real ML history')
read_rates = [r['exact_counts']['read'] / (r['window_end'] - r['window_start']) for r in list(prior)[-10:]]
import numpy as np
assert len(read_rates) == 10
assert np.isclose(named['rolling_mean:read'], np.log1p(np.mean(read_rates)), rtol=1e-5)
assert np.isclose(named['rolling_std:read'], np.log1p(np.std(read_rates)), rtol=1e-5)
result = {'schema':'sentinel-pulse-real-flow-example-v1', 'node_name':socket.gethostname(),
    'run_id':root.name,'raw_root':str(root), 'feature':target, 'decision':normal,
    'ml_history':[{key:r.get(key) for key in ['window_start','window_end','exact_total','exact_counts','vector_f32_zlib_b64','feature_schema_sha256','vector_dim']} for r in history],
    'rolling_read_rates_before_current':read_rates, 'rolling_read_mean_raw':float(np.mean(read_rates)),
    'rolling_read_std_raw':float(np.std(read_rates)), 'features_249_by_name':named,
    'other_real_decisions':samples, 'inputs_sha256':{name:sha256_file(root/name) for name in ['features.jsonl','decisions.jsonl']},
    'example_is_live_attack':False, 'kernel_to_alert_measured':False}
print(json.dumps(result,sort_keys=True))
