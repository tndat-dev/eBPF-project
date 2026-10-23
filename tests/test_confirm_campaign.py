import importlib.util
import json
import subprocess
import sys
from pathlib import Path

SCRIPT = Path(__file__).parents[1]/'scripts/analysis/confirm_campaign.py'
spec = importlib.util.spec_from_file_location('confirm_campaign', SCRIPT)
cc = importlib.util.module_from_spec(spec); spec.loader.exec_module(cc)


def campaign(tmp_path):
    trials, outcomes = tmp_path/'trials', []
    def trial(i, rate, workload, node, attack, control, benign):
        (trials/str(i)).mkdir(parents=True)
        (trials/str(i)/'EVALUATION_INPUT.json').write_text(json.dumps(
            dict(attack=dict(trial_id=f'{i}:attack', rate_per_second=rate, scenario='ptrace'))))
        base = dict(workload_key=workload, node_name=node)
        outcomes.extend([dict(base, trial_id=f'{i}:attack', label='attack', outcome=attack, kernel_to_preview_seconds=1.0),
                         dict(base, trial_id=f'{i}:control', label='expected_normal', outcome=control),
                         dict(base, trial_id=f'{i}:benign', label='expected_normal', control_kind='benign_exec', outcome=benign)])
    trial(1, 6, 'production/pg:postgres', 'w1', 'TP', 'FP_expected', 'FP_expected')
    trial(2, 12, 'production/pg:postgres', 'w1', 'TP', 'FP_expected', 'FP_expected')
    trial(3, 24, 'production/app:app', 'w3', 'TP', 'TN_expected', 'FP_expected')
    trial(4, 6, 'production/kafka:kafka', 'w1', 'TP', 'FP_expected', 'TN_expected')
    trial(5, 1, 'production/app:app', 'w3', 'FN', 'TN_expected', 'TN_expected')
    (tmp_path/'RESULTS.json').write_text(json.dumps(dict(outcomes=outcomes)))
    return tmp_path


def run(tmp_path, *extra):
    out = tmp_path/'out.json'
    subprocess.run([sys.executable, str(SCRIPT), '--campaign', str(campaign(tmp_path)), '--output', str(out), *extra],
                   check=True, capture_output=True)
    return json.loads(out.read_text())


def test_primary_subset_counts_control_positives_per_container(tmp_path):
    r = run(tmp_path)
    assert r['primary']['TP'] == 4 and r['primary']['control_FP'] == 3 and r['primary']['control_TN'] == 1
    assert r['primary_control_fp_by_container'] == {'production/pg:postgres@w1': 2, 'production/kafka:kafka@w1': 1}
    assert r['post_hoc'] is False and r['verdict']['confirmed'] is False
    assert r['all_rates']['FN'] == 1                                   # the 1/s trial is outside the primary subset


def test_excluding_a_container_is_marked_post_hoc(tmp_path):
    r = run(tmp_path, '--exclude-container', 'production/pg:postgres@w1')
    assert r['post_hoc'] is True and r['excluded_containers'] == ['production/pg:postgres@w1']
    assert r['primary']['TP'] == 2 and r['primary']['control_FP'] == 1 and r['primary']['control_TN'] == 1
    assert r['primary_control_fp_by_container'] == {'production/kafka:kafka@w1': 1}
