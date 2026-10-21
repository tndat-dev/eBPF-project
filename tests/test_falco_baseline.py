import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location('falco_baseline', Path(__file__).parents[1]/'scripts'/'analysis'/'falco_baseline.py')
fb = importlib.util.module_from_spec(spec); spec.loader.exec_module(fb)

LINE = ('2026-10-21T06:04:34.615218902Z stdout F 06:04:34.612337206: Notice Unexpected connection to K8s API Server '
        'from container | connection=10.0.4.136:59646->10.96.0.1:443 evt_type=connect container_id=0661c06cee7f '
        'container_name=vault k8s_pod_name=vault-1 k8s_ns_name=vault')


def test_parse_reads_time_priority_rule_and_fields():
    t, priority, rule, fields = fb.parse(LINE)
    assert abs(t - (1792562674.612337206)) < 1e-3
    assert priority == 'Notice' and rule == 'Unexpected connection to K8s API Server from container'
    assert fields['container_id'] == '0661c06cee7f' and fields['k8s_ns_name'] == 'vault'
    assert fb.parse('garbage') is None


def test_event_logged_after_midnight_keeps_its_own_day():
    line = LINE.replace('2026-10-21T06:04:34.615218902Z', '2026-10-22T00:00:00.100000000Z').replace('06:04:34.612337206', '23:59:59.900000000')
    t = fb.parse(line)[0]
    assert abs(t - (1792627200.0 - 0.1)) < 1e-3    # 21/10 23:59:59.9 UTC
