"""Arms of the live run: trial detection window, labels, episodes, burden, on a small synthetic run root."""
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts' / 'analysis'))
sys.path.insert(0, str(ROOT))

import pulse_live_v4 as m  # noqa: E402

T0 = 1000.0
P = dict(pod_uid='p', container_name='c', workload_key='w')


def token(end, alert=False):
    return dict(P, status='token-score', window_end=end, candidate_alert_preview=alert, preview_emitted_at=end + .1)


def counts(end, tree=False, support=False):
    return dict(P, status='candidate-raw-score-only', window_end=end, candidate_alert_preview=False, v3_tree_alert=tree,
                v3_support_alert=support, preview_emitted_at=end + .2)


def write_run(root, rows):
    cfg = dict(run_id='r', selection_start=T0, selection_end=T0 + 100, seconds=10000.0)
    (root / 'CONFIG.json').write_text(json.dumps(cfg))
    seg = root / 'workers' / 'n' / 'segments' / 's00001'
    seg.mkdir(parents=True)
    (seg / 'decisions.jsonl').write_text(''.join(json.dumps(r) + '\n' for r in rows))
    (root / 'workers' / 'n' / 'STATUS.json').write_text(json.dumps(dict(issues=0, segments=1)))
    camp = root / m.CAMPAIGN
    base = dict(pod_uid='p', container_name='c', workload_key='w')
    rows = [dict(base, label='expected_normal', trial_id='1:control', start_at=2000.0),
            dict(base, label='expected_normal', control_kind='benign_exec', trial_id='1:benign', start_at=2020.0),
            dict(base, label='attack', trial_id='1:attack', start_at=2040.0, rate_per_second=12, scenario='s'),
            dict(base, label='expected_normal', trial_id='2:control', start_at=2100.0),
            dict(base, label='attack', trial_id='2:attack', start_at=2140.0, rate_per_second=1, scenario='s')]
    camp.mkdir()
    (camp / 'INTERVALS.jsonl').write_text(''.join(json.dumps(r) + '\n' for r in rows))
    (camp / 'TERMINAL.json').write_text(json.dumps(dict(finished_at_unix=2200.0)))
    for pair, kernel in ((1, 2040.5), (2, 2140.5)):
        trial = camp / 'trials' / f'{pair:04d}'
        trial.mkdir(parents=True)
        (trial / 'EVALUATION_INPUT.json').write_text(json.dumps(dict(attack=dict(kernel_event_at=kernel))))


def test_arms_of_rows():
    assert set(m.arms_of(token(1, True))) == {'system', 'V4', 'T', 'T_raw'}
    assert m.arms_of(token(1)) == ()
    assert set(m.arms_of(dict(token(1), token_alert_raw=True))) == {'T_raw'}
    assert set(m.arms_of(counts(1, tree=True))) == {'tree', 'V4', 'C'}
    assert set(m.arms_of(dict(counts(1, support=True), candidate_alert_preview=True))) == {'system', 'support', 'V4', 'C'}
    assert m.arms_of(counts(1)) == ()
    assert m.arms_of(dict(status='warming', candidate_alert_preview=True)) == ()


def test_detection_window_is_start_to_start_plus_15():
    assert m.first_alarm(m.np.asarray([9.9, 10.0, 11.0]), 10.0) == 10.0
    assert m.first_alarm(m.np.asarray([9.9]), 10.0) is None
    assert m.first_alarm(m.np.asarray([25.0]), 10.0) == 25.0
    assert m.first_alarm(m.np.asarray([25.1]), 10.0) is None


def test_primary_set_labels_and_arms(tmp_path):
    rows = [token(2041.0, True),            # attack of pair 1 (rate 12), token only, 0.5 s after the kernel event
            token(2141.0),                  # attack of pair 2 (rate 1): missed
            token(2021.0, True),            # benign of pair 1
            counts(2022.0, tree=True),      # benign of pair 1, tree
            token(2001.0, True),            # idle control of pair 1
            counts(5000.0)]
    write_run(tmp_path, rows)
    out = m.analyse(tmp_path, reps=50)
    v4, t, tree = out['arms']['V4'], out['arms']['T'], out['arms']['tree']
    assert (v4['primary']['attack']['hits'], v4['primary']['attack']['n']) == (1, 1)     # only rates 6, 12, 24
    assert (v4['all_rates']['attack']['hits'], v4['all_rates']['attack']['n']) == (1, 2)
    assert (v4['primary']['control']['hits'], v4['primary']['control']['n']) == (1, 1)
    assert v4['primary']['control']['rate'] == 1.0 and v4['primary']['precision']['rate'] == .5
    assert abs(t['primary']['latency_p95'] - .5) < 1e-9
    assert tree['primary']['attack']['hits'] == 0 and tree['primary']['benign']['hits'] == 1
    assert v4['recall_by_rate']['1']['hits'] == 0 and v4['recall_by_rate']['12']['hits'] == 1
    assert out['campaign_complete'] is True


def test_burden_merges_episodes_and_leaves_out_selection_and_campaign(tmp_path):
    rows = [token(1050.0, True),            # selection span: not normal
            token(2040.0, True),            # campaign span: not normal
            token(3000.0, True), token(3010.0, True),   # one episode (< 15 s apart)
            token(3025.0, True),            # second episode (15 s apart)
            counts(3000.0), counts(3000.5)]
    write_run(tmp_path, rows)
    b = m.analyse(tmp_path, reps=50)['arms']['T']['burden']
    assert b['episodes'] == 2
    assert abs(b['replica_hours'] - 1.0 / 3600) < 1e-12
    assert abs(b['value'] - 2 * 3600) < 1e-6


def test_burden_bootstrap_is_clustered_by_workload():
    b = m.burden(dict(a=10, b=0), dict(a=3600.0, b=3600.0), reps=2000)
    assert b['value'] == 5.0 and b['ci95'][0] == 0.0 and b['ci95'][1] == 10.0
