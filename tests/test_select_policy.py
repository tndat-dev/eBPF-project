import json
from pathlib import Path

from sentinel_pulse.attack import select_policy as sp

ROOT = Path(__file__).resolve().parents[1]


def _policy(k, n, a):
    return dict(k=k, n=n, alpha_scale=a)


def _write(tmp, prefix, normal, attack):
    """normal: name -> episodes per node; attack: name -> (precision, recall, control, p95)."""
    for grid in sp.GRIDS:
        names = [n for n in normal if (n.startswith('k1of1') or grid == 'looser')]
        for node in sp.NODES:
            doc = dict(total_scored_hours=10.0,
                       policies={n: dict(total_episodes=normal[n]) for n in names})
            (tmp/f'normal-{prefix}-{grid}-{node}.json').write_text(json.dumps(doc))
        pols = {}
        for n in names:
            p, r, c, p95 = attack[n]
            k, rest = n[1:].split('of'); nn, a = rest.split('_a')
            pols[n] = dict(policy=_policy(int(k), int(nn), float(a)), precision_expected=p, recall_observed=r,
                           control_positive_rate=c, kernel_to_preview_seconds=dict(p95=p95, p99=p95 + 2),
                           benign_exec_control=dict(positive_rate=0.8))
        (tmp/f'attack-{prefix}-{grid}.json').write_text(json.dumps(dict(policies=pols)))


def test_rule_prefers_refreshed_calibration_and_fewest_episodes(tmp_path):
    attack = {'k1of1_a3': (0.89, 0.93, 0.11, 1.9), 'k2of2_a5': (0.97, 0.96, 0.03, 2.25),
              'k2of2_a10': (0.95, 0.98, 0.05, 2.2)}
    _write(tmp_path, 'asrun', {'k1of1_a3': 200, 'k2of2_a5': 90, 'k2of2_a10': 150}, attack)
    _write(tmp_path, 'refreshed', {'k1of1_a3': 100, 'k2of2_a5': 40, 'k2of2_a10': 70}, attack)
    result = sp.select(tmp_path)
    assert result['calibration'] == 'refreshed'
    assert result['policy'] == 'k2of2_a5' and result['meets_registered_expectations']
    assert abs(result['metrics']['episodes_per_hour'] - 40*3/30) < 1e-9


def test_rule_falls_back_to_lowest_p95_with_precision(tmp_path):
    attack = {'k1of1_a3': (0.89, 0.93, 0.11, 1.9), 'k2of2_a5': (0.97, 0.96, 0.03, 2.9),
              'k2of2_a10': (0.95, 0.98, 0.05, 2.6)}
    _write(tmp_path, 'asrun', {'k1of1_a3': 100, 'k2of2_a5': 40, 'k2of2_a10': 70}, attack)
    _write(tmp_path, 'refreshed', {'k1of1_a3': 120, 'k2of2_a5': 50, 'k2of2_a10': 80}, attack)
    result = sp.select(tmp_path)
    assert result['calibration'] == 'as_run'
    assert result['policy'] == 'k2of2_a10' and not result['meets_registered_expectations']


def test_written_policy_keeps_the_registered_v2_rule_form(tmp_path):
    selection = dict(policy='k2of2_a5', calibration='refreshed', meets_registered_expectations=True,
                     metrics=dict(policy=_policy(2, 2, 5.0), precision=0.97, recall=0.96, control=0.03,
                                  benign_positive_rate=0.8, p95=2.2, episodes_per_hour=4.0))
    out = tmp_path/'policy.json'
    sp.write_policy(selection, ROOT/'sentinel_pulse/protocol/policy-1win-a3.json', out, 'abc', 'cand')
    doc = json.loads(out.read_text())
    rule = dict(doc['rule']); conf = rule.pop('temporal_confirmation'); scale = rule.pop('alpha_scale')
    assert rule == {'score': 'joint_p', 'comparison': 'less_than_or_equal',
                    'threshold_source': 'per_workload_model_calibrated_alpha', 'semantic_gate': False}
    assert conf == dict(k=2, n=2, max_gap_seconds=1.0) and scale == 5.0
    assert doc['candidate_manifest_sha256'] == 'abc' and doc['schema'] == 'sentinel-pulse-candidate-preview-policy-v2'


def test_written_policy_states_known_gaps(tmp_path):
    selection = dict(policy='k2of2_a10', calibration='as_run', meets_registered_expectations=False,
                     metrics=dict(policy=_policy(2, 2, 10.0), precision=0.95, recall=0.97, control=0.05,
                                  benign_positive_rate=0.88, p95=2.43, episodes_per_hour=7.98))
    out = tmp_path/'policy.json'
    sp.write_policy(selection, ROOT/'sentinel_pulse/protocol/policy-1win-a3.json', out, 'abc', 'cand')
    gaps = json.loads(out.read_text())['selection_basis']['known_gaps']
    assert len(gaps) == 3 and '2.43 s' in gaps[0] and '~80x' in gaps[1] and '88%' in gaps[2]


def _write_v2(tmp, prefix, normal, attack):
    """normal: name -> episodes per node (10 h each); attack: name -> (precision, recall, control, p95)."""
    for node in sp.NODES:
        doc = dict(total_scored_hours=10.0, policies={n: dict(total_episodes=e) for n, e in normal.items()})
        (tmp/f'normal-{prefix}-{node}.json').write_text(json.dumps(doc))
    pols = {}
    for n, (p, r, c, p95) in attack.items():
        k, rest = n[1:].split('of'); nn, a = rest.split('_a')
        pols[n] = dict(policy=_policy(int(k), int(nn), float(a)), precision_expected=p, recall_observed=r,
                       control_positive_rate=c, kernel_to_preview_seconds=dict(p95=p95, p99=p95 + 2),
                       benign_exec_control=dict(positive_rate=0.9))
    (tmp/f'attack-{prefix}.json').write_text(json.dumps(dict(policies=pols)))


def test_v2_latency_is_hard_and_refreshed_needs_5_7b(tmp_path):
    attack = {'k2of2_a10': (0.92, 0.98, 0.08, 1.85), 'k2of3_a10': (0.96, 0.98, 0.04, 1.70), 'k2of2_a5': (0.99, 0.96, 0.01, 2.6)}
    _write_v2(tmp_path, 'asrun', {'k2of2_a10': 80, 'k2of3_a10': 90, 'k2of2_a5': 40}, attack)
    fresh = dict(attack, k2of2_a10=(0.96, 0.98, 0.04, 1.85))
    _write_v2(tmp_path, 'refreshed', {'k2of2_a10': 60, 'k2of3_a10': 70, 'k2of2_a5': 30}, fresh)
    result = sp.select_v2(tmp_path)
    assert result['calibration'] == 'refreshed'          # 60 <= 80 * 0.9, recall kept, precision >= 0.95
    # k2of2_a5 (30 episodes, p95 2.6 s) is acceptable but the < 2 s tier has eligible policies, so it wins
    assert result['policy'] == 'k2of2_a10' and result['latency_tier'] == 2.0 and 'k2of2_a5' in result['within_3s']


def test_v2_uses_the_3s_tier_when_nothing_qualifies_under_2s(tmp_path):
    attack = {'k2of2_a10': (0.92, 0.98, 0.08, 1.85), 'k2of3_a10': (0.93, 0.97, 0.07, 1.70), 'k2of2_a5': (0.99, 0.96, 0.01, 2.6),
              'k2of2_a2': (0.995, 0.96, 0.0, 3.4)}
    _write_v2(tmp_path, 'asrun', {'k2of2_a10': 80, 'k2of3_a10': 90, 'k2of2_a5': 40, 'k2of2_a2': 10}, attack)
    _write_v2(tmp_path, 'refreshed', {'k2of2_a10': 78, 'k2of3_a10': 88, 'k2of2_a5': 39, 'k2of2_a2': 9}, attack)
    result = sp.select_v2(tmp_path)
    assert result['calibration'] == 'as_run'             # only 2.5 % fewer episodes
    assert result['policy'] == 'k2of2_a5' and result['latency_tier'] == 3.0 and result['meets_registered_expectations']
    assert 'k2of2_a2' not in result['within_3s']         # 3.4 s is never chosen


def test_policy_in_both_grids_is_counted_once(tmp_path):
    attack = {'k1of1_a1': (0.95, 0.9, 0.04, 3.0), 'k1of1_a3': (0.9, 0.92, 0.1, 1.9), 'k2of2_a10': (0.95, 0.97, 0.05, 2.4)}
    _write(tmp_path, 'asrun', {'k1of1_a1': 75, 'k1of1_a3': 130, 'k2of2_a10': 80}, attack)
    _write(tmp_path, 'refreshed', {'k1of1_a1': 75, 'k1of1_a3': 130, 'k2of2_a10': 80}, attack)
    rates, hours = sp.normal_rates(tmp_path, 'asrun')
    assert abs(rates['k1of1_a1'] - 75*3/hours) < 1e-12      # not doubled although it is in both grids
