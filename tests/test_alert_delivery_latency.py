import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location('alert_delivery_latency',
                                              Path(__file__).parents[1]/'scripts/analysis/alert_delivery_latency.py')
lat = importlib.util.module_from_spec(spec); spec.loader.exec_module(lat)


def attack(trial, pod, start, kernel, rate=12):
    return dict(label='attack', trial_id=trial, node_name='w1', pod_uid=pod, container_name='app', start_at=start,
                kernel_event_at=kernel, kernel_to_preview_seconds=1.0, outcome='TP', scenario='ptrace', rate_per_second=rate)


def test_trials_join_the_episode_started_inside_their_horizon_and_get_one_latency_per_path():
    outcomes = [attack('1:attack', 'a', 100.0, 100.5), attack('2:attack', 'b', 200.0, 200.4, rate=1),
                attack('3:attack', 'c', 300.0, 300.2), attack('0:attack', 'a', 10.0, 10.5),
                dict(label='expected_normal', trial_id='1:control', start_at=90.0)]
    episodes = [dict(event='start', episode='e1', node='w1', pod_uid='a', container='app', preview_emitted_at=101.5),
                dict(event='end', episode='e1', ended_at=110.0),
                dict(event='start', episode='e0', node='w1', pod_uid='c', container='app', preview_emitted_at=295.0),
                dict(event='end', episode='e0', ended_at=305.0)]
    deliveries = [dict(path='push', episode='e1', received_at=101.55), dict(path='pull-fast', episode='e1', received_at=106.0)]
    rows = {r['trial_id']: r for r in lat.join(outcomes, episodes, deliveries, since=50.0)}
    assert set(rows) == {'1:attack', '2:attack', '3:attack'}                     # before --since and controls left out
    assert rows['1:attack']['match'] == 'episode'
    assert round(rows['1:attack']['push_kernel_to_recipient_seconds'], 3) == 1.05
    assert round(rows['1:attack']['pull-fast_kernel_to_recipient_seconds'], 3) == 5.5
    assert rows['1:attack']['pull-default_kernel_to_recipient_seconds'] is None  # never delivered on that path
    assert rows['2:attack']['match'] == 'no_episode'
    assert rows['3:attack']['match'] == 'alert_already_active'                  # alert sent before the attack
    s = lat.summarize(list(rows.values()))
    assert s['push']['trials_alerted'] == 1 and round(s['push']['share_of_attack_trials'], 3) == 0.333
    assert s['match'] == {'episode': 1, 'no_episode': 1, 'alert_already_active': 1}
    assert s['push_by_rate']['1'] == dict(trials=1, alerted=0, p95=None)
