import json
from pathlib import Path

import pytest

from sentinel_pulse.integrity import sha256_file
from sentinel_pulse.normal_control import evaluate_control, recover_epochs, select_targets
from sentinel_pulse.observation_attack import schedule
from sentinel_pulse.blind_contract import load_contract
from sentinel_pulse.paired_evaluation import audit_attack, confusion, control_plan, verify_seal
from sentinel_pulse.observation_attack import result_report
from sentinel_pulse.run_500ms_blind_matrix import append_jsonl

ROOT = Path(__file__).resolve().parents[1]
ITEM = dict(control_id='n001:01', epoch=1, workload_key='production/redis:server')
TARGET = dict(pod_uid='u', node_name='n', pod_name='redis-0', cgroup_id='1')


def record(index, status='normal'):
    return dict(workload_key=ITEM['workload_key'], **TARGET, window_end=100 + index * .5,
                status=status, model_manifest_sha256='m', decision_policy_sha256='p', alerted_at=101)


def test_paired_plan_matches_each_frozen_controller_without_attack_dispatch():
    contract = load_contract(ROOT / 'sentinel_pulse/protocol/development-r10/blind-attack-contract-r10.json')
    attack = schedule(contract, 20261007)
    for row in attack:
        row['workload_key'] = 'production/' + row['workload_controller'] + ':app'
    plan = control_plan(attack)
    assert len(plan) == 475 and len({r['control_id'] for r in plan}) == 475
    assert len({r['epoch'] for r in plan}) == 25
    assert len([r for r in plan if r['epoch'] == 1]) == 19
    code = (ROOT / 'sentinel_pulse/normal_control.py').read_text()
    assert 'from .attack_trial' not in code and 'runtime_attack_blind' not in code
    assert 'start_leg' in code and 'flock' in code


@pytest.mark.parametrize('alert', [False, True])
def test_normal_controls_keep_predictions_even_nonzero_alerts(alert):
    data = [record(i) for i in range(90)]
    if alert:
        data[1]['status'] = 'alert'
    result = evaluate_control(ITEM, TARGET, data, 100, 'm', 'p', True)
    assert result['status'] == 'observed' and result['predicted_alert'] is alert
    assert result['all_alert_rows_45s'] == int(alert)


def test_late_alert_retained_but_same_15_second_prediction_horizon():
    data = [record(i) for i in range(90)]
    data[60].update(status='alert', alerted_at=131)
    result = evaluate_control(ITEM, TARGET, data, 100, 'm', 'p', True)
    assert result['all_alert_rows_45s'] == 1 and result['predicted_alert'] is False


@pytest.mark.parametrize('n', [0, 80])
def test_sparse_control_is_unknown_never_true_negative(n):
    result = evaluate_control(ITEM, TARGET, [record(i) for i in range(n)], 100, 'm', 'p', True)
    assert result['status'] == 'infrastructure_unknown' and result['predicted_alert'] is None


@pytest.mark.parametrize('mutation', ['model', 'duplicate', 'injection', 'timestamp'])
def test_bad_control_evidence_is_rejected(mutation):
    data = [record(i) for i in range(90)]
    if mutation == 'model': data[0]['model_manifest_sha256'] = 'wrong'
    if mutation == 'duplicate': data.append(data[0])
    if mutation == 'injection': data[0].update(status='alert', injection_id='attack:1')
    if mutation == 'timestamp': data[0].update(status='alert'); del data[0]['alerted_at']
    with pytest.raises(ValueError): evaluate_control(ITEM, TARGET, data, 100, 'm', 'p', True)


def test_unknown_infrastructure_context_is_not_claimed_normal_ground_truth():
    result = evaluate_control(ITEM, TARGET, [record(i) for i in range(90)], 100, 'm', 'p', False)
    report = confusion([dict(status='observed', detected=True)], [result], [ITEM])
    assert report['normal_unknown_or_uncertain'] == 1
    assert report['provisional_protocol_precision'] is None
    assert report['provisional_protocol_confusion_matrix']['TN'] is None


def test_paired_metrics_include_fp_misses_unknowns_and_separate_adjudication():
    plan = [dict(ITEM, control_id=str(i)) for i in range(3)]
    controls = [dict(plan[0], status='observed', predicted_alert=True, label_status='protocol_assumed_normal'),
                dict(plan[1], status='observed', predicted_alert=False, label_status='protocol_assumed_normal'),
                dict(plan[2], status='infrastructure_unknown', predicted_alert=None)]
    attacks = [dict(status='observed', detected=True), dict(status='observed', detected=False),
               dict(status='infrastructure_unknown', detected=False)]
    report = confusion(attacks, controls, plan)
    assert report['provisional_protocol_confusion_matrix'] == dict(TP=1, FN=1, FP=1, TN=1)
    assert report['provisional_protocol_precision'] == .5
    assert report['provisional_protocol_false_positive_rate'] == .5
    assert report['conditional_observed_attack_recall'] == .5
    assert report['attack_unknown'] == 1 and report['normal_unknown_or_uncertain'] == 1
    assert report['adjudicated_precision'] is None and not report['zero_false_positive_gate']
    with pytest.raises(ValueError): confusion(attacks, controls + controls[:1], plan)


def test_restart_preserves_interrupted_epoch_once(tmp_path):
    append_jsonl(tmp_path / 'EPOCHS.jsonl', {'items': [ITEM]})
    recover_epochs(tmp_path); recover_epochs(tmp_path)
    results = [json.loads(line) for line in (tmp_path / 'CONTROLS.jsonl').read_text().splitlines()]
    assert len(results) == 1 and results[0]['status'] == 'infrastructure_unknown'


def test_seal_verification_rejects_drift_extra_files_and_path_escape(tmp_path):
    (tmp_path / 'START.json').write_text('{}')
    (tmp_path / 'TERMINAL.json').write_text('{}')
    receipt = {p.name: sha256_file(p) for p in tmp_path.iterdir()}
    (tmp_path / 'EVIDENCE_SEAL.json').write_text(json.dumps(receipt))
    assert len(verify_seal(tmp_path)) == 64
    (tmp_path / 'unregistered.json').write_text('{}')
    with pytest.raises(ValueError): verify_seal(tmp_path)
    (tmp_path / 'unregistered.json').unlink()
    (tmp_path / 'START.json').write_text('{"changed": true}')
    with pytest.raises(ValueError): verify_seal(tmp_path)
    receipt['../outside'] = 'x'
    (tmp_path / 'EVIDENCE_SEAL.json').write_text(json.dumps(receipt))
    with pytest.raises(ValueError): verify_seal(tmp_path)


def test_resolver_filters_exact_workload_not_redis_prefix():
    def pod(name, uid):
        return dict(metadata=dict(name=name, uid=uid), status=dict(phase='Running',
            conditions=[dict(type='Ready', status='True')], containerStatuses=[dict(ready=True)]),
            spec=dict(nodeName='n', containers=[dict(name='server')]))
    pods = {'items': [pod('redis-0', 'u'), pod('redis-sentinel-0', 's')]}
    metadata = {'n': {'cgroups': {'1': dict(pod_uid='u', namespace='production', workload_name='redis',
          container_name='server', cgroup_path='/redis/server'),
          '2': dict(pod_uid='s', namespace='production', workload_name='redis-sentinel',
          container_name='server', cgroup_path='/sentinel/server')}}}
    for epoch in (1, 2, 3):
        assert select_targets(pods, metadata, [ITEM], epoch)[ITEM['control_id']]['pod_uid'] == 'u'


def test_boot_persistent_normal_control_waits_for_sealed_attack():
    unit = (ROOT / 'sentinel_pulse/systemd/sentinel-pulse-normal-control.service').read_text()
    assert 'Restart=on-failure' in unit and 'WantedBy=multi-user.target' in unit
    assert 'TimeoutStartSec=infinity' in unit and 'RestartPreventExitStatus=65' in unit


@pytest.mark.parametrize('detected', [True, False])
def test_attack_final_audit_recomputes_hits_misses_and_checks_raw_provenance(tmp_path, monkeypatch, detected):
    trial = dict(workload_controller='x', workload_key='production/x:app', scenario='s', seed=1, rate_per_second=6)
    intent = dict(trial, injection_id='r:0001', pod_uid='u', node_name='n', cgroup_id=1,
                  injected_at=100, binary_path='/tmp/attack')
    kernel = dict(injection_id='r:0001', kernel_event_at=100.1)
    outcome = dict(intent, status='observed', detected=detected, kernel_event_at=100.1)
    if detected:
        outcome['kernel_to_alert_seconds'] = 1
    (tmp_path / 'START.json').write_text(json.dumps(dict(schedule=[trial], model_manifest_sha256='m',
                                                       decision_policy_sha256='p')))
    append_jsonl(tmp_path / 'TRIALS.jsonl', outcome)
    append_jsonl(tmp_path / 'INTENTS.jsonl', intent)
    append_jsonl(tmp_path / 'kernel-events.jsonl', kernel)
    (tmp_path / 'TERMINAL.json').write_text(json.dumps(result_report([trial], [outcome])))
    raw = tmp_path / 'trials/0001'; raw.mkdir(parents=True)
    (raw / 'tetragon.jsonl').write_text('{}\n')
    (raw / 'attributed-alerts.jsonl').touch()
    if detected:
        append_jsonl(raw / 'attributed-alerts.jsonl', dict(intent, status='alert', alerted_at=101.1,
                                                        model_manifest_sha256='m', decision_policy_sha256='p'))
    (tmp_path / 'EVIDENCE_SEAL.json').write_text(json.dumps({str(p.relative_to(tmp_path)): sha256_file(p)
                            for p in tmp_path.rglob('*') if p.is_file()}))
    monkeypatch.setattr('sentinel_pulse.paired_evaluation.find_execve_kprobe_event', lambda *a, **k: kernel)
    assert audit_attack(tmp_path)[2]['observed_attack_intervals'] == 1
    monkeypatch.setattr('sentinel_pulse.paired_evaluation.find_execve_kprobe_event', lambda *a, **k: {})
    with pytest.raises(ValueError, match='raw Tetragon'): audit_attack(tmp_path)
