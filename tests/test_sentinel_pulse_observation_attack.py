import copy
import json
from pathlib import Path
import subprocess

import pytest

from sentinel_pulse.attack_admission import admit
from sentinel_pulse.attack_trial import first_alert
from sentinel_pulse.blind_contract import load_contract
from sentinel_pulse.detector_freshness import CONTRACT, CONTRACT_SHA256
from sentinel_pulse.observation_attack import recover_intents, result_report, schedule
from sentinel_pulse.recovery_deployment import bind_freshness_preregistration
from sentinel_pulse.run_500ms_blind_matrix import append_jsonl

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / 'validation-evidence/soak-completion-20261007'


def admission_fixture(tmp_path):
    start = json.loads((EVIDENCE / 'START.json').read_text())
    terminal = json.loads((EVIDENCE / 'TERMINAL.json').read_text())
    for name, data in [('START', start), ('TERMINAL', terminal)]:
        (tmp_path / (name + '.json')).write_text(json.dumps(data))
    manifest = {'workloads': {k: {'status': 'candidate'} for k in terminal['valid_seconds_per_workload']}}
    return start, terminal, manifest


@pytest.mark.parametrize('alerts', [0, 1, 1000])
@pytest.mark.parametrize('budget_met', [True, False])
def test_nonzero_alerts_and_quality_failure_do_not_block_attack_admission(tmp_path, alerts, budget_met):
    start, terminal, manifest = admission_fixture(tmp_path)
    terminal.update(all_alerts={'redis': alerts}, quality_budget_met=budget_met)
    (tmp_path / 'TERMINAL.json').write_text(json.dumps(terminal))
    result = admit(tmp_path, manifest, start['binding']['model_manifest_sha256'], start['binding']['decision_policy_sha256'])
    assert result['all_alerts']['redis'] == alerts
    assert result['zero_alert_gate'] is False and result['precision'] is None


@pytest.mark.parametrize('mutation', ['model', 'policy', 'partial', 'coverage', 'missing', 'nan', 'negative_alerts'])
def test_admission_still_enforces_candidate_and_valid_exposure(tmp_path, mutation):
    start, terminal, manifest = admission_fixture(tmp_path)
    model, policy = start['binding']['model_manifest_sha256'], start['binding']['decision_policy_sha256']
    key = next(iter(terminal['valid_seconds_per_workload']))
    if mutation == 'model': model = '0' * 64
    if mutation == 'policy': policy = '0' * 64
    if mutation == 'partial': terminal['status'] = 'running'
    if mutation == 'coverage': terminal['valid_seconds_per_workload'][key] = 1
    if mutation == 'missing': del terminal['valid_seconds_per_workload'][key]
    if mutation == 'nan': terminal['valid_seconds_per_workload'][key] = float('nan')
    if mutation == 'negative_alerts': terminal['all_alerts'][key] = -1
    (tmp_path / 'TERMINAL.json').write_text(json.dumps(terminal))
    with pytest.raises(ValueError): admit(tmp_path, manifest, model, policy)


def test_frozen_full_schedule_has_pilot_first_without_repeating_or_tuning():
    contract = load_contract(ROOT / 'sentinel_pulse/protocol/development-r10/blind-attack-contract-r10.json')
    plan = schedule(contract, 20261007)
    assert len(plan) == 475 == len({tuple(sorted(r.items())) for r in plan})
    assert {r['workload_controller'] for r in plan[:15]} == {'api-gateway', 'aims-postgres-cnpg', 'aims-kafka-dual-role'}
    assert all(r['seed'] == 53051 and r['rate_per_second'] == 12 for r in plan[:15])
    assert schedule(contract, 20261007) == plan


def test_metrics_preserve_misses_unknowns_and_do_not_invent_precision():
    plan = [dict(workload_controller='x', scenario='a', seed=i, rate_per_second=12) for i in range(4)]
    trials = [dict(plan[0], status='observed', detected=True, kernel_to_alert_seconds=1.2),
              dict(plan[1], status='observed', detected=False),
              dict(plan[2], status='infrastructure_unknown', detected=False)]
    result = result_report(plan, trials)
    assert result['conditional_observed_attack_recall'] == .5
    assert result['end_to_end_detection_fraction_on_completed_planned_trials'] == 1/3
    assert result['planned_full_matrix_detection_lower_bound'] == .25
    assert result['observed_misses'] == 1 and result['infrastructure_unknown_intervals'] == 1
    assert result['precision'] is None and result['false_positive_rate'] is None
    assert result['kernel_to_alert_seconds_detected_trials_only']['p99'] == 1.2
    assert result['confusion_matrix']['TN'] is None
    with pytest.raises(ValueError): result_report(plan, trials + trials[:1])


def test_restart_never_reinjects_an_ambiguous_committed_intent(tmp_path):
    trial = dict(workload_controller='x', scenario='a', seed=1, rate_per_second=12)
    append_jsonl(tmp_path / 'INTENTS.jsonl', dict(trial, injection_id='run:0001', injected_at=10))
    recover_intents(tmp_path, [trial]); recover_intents(tmp_path, [trial])
    saved = [json.loads(r) for r in (tmp_path / 'TRIALS.jsonl').read_text().splitlines()]
    assert len(saved) == 1 and saved[0]['detected'] is False
    assert saved[0]['status'] == 'infrastructure_unknown'


def test_only_real_alerts_with_exact_target_binding_are_detections():
    injection = dict(injection_id='r:1', injected_at=10, cgroup_id=1, workload_key='w', pod_uid='u', node_name='n')
    alert = dict(injection_id='r:1', status='alert', alerted_at=11, cgroup_id='1', workload_key='w',
                 model_manifest_sha256='m', decision_policy_sha256='p', pod_uid='u', node_name='n')
    assert first_alert([alert], injection, 'm', 'p') == alert
    assert first_alert([], injection, 'm', 'p') is None
    for field, value in [('status', 'normal'), ('pod_uid', 'other'), ('model_manifest_sha256', 'other'), ('alerted_at', 26)]:
        with pytest.raises(ValueError): first_alert([dict(alert, **{field: value})], injection, 'm', 'p')


@pytest.mark.parametrize('drift', [None, 'profile', 'contract', 'promotion', 'ambiguity'])
def test_attack_freshness_registration_cannot_be_retrofitted_or_drift(tmp_path, drift):
    feature = tmp_path / 'run1/features.jsonl'; feature.parent.mkdir(); feature.touch()
    smoke, formal, attack = [tmp_path / name for name in ('smoke', 'formal', 'attack')]
    marker = dict(schema='sentinel-pulse-attack-worker-start-v1', run_id='run1', automatic_promotion=False,
                  detector_freshness_contract=copy.deepcopy(CONTRACT), detector_freshness_contract_sha256=CONTRACT_SHA256,
                  recovery_profile_sha256='abc', campaign_start_sha256='def')
    if drift == 'profile': marker['recovery_profile_sha256'] = 'other'
    if drift == 'contract': marker['detector_freshness_contract']['maximum_age_at_processing_start_seconds'] = 10
    if drift == 'promotion': marker['automatic_promotion'] = True
    (feature.parent / 'START.json').write_text(json.dumps({'telemetry_recovery_contract': {'profile_file_sha256': 'abc'}}))
    (attack / 'run1').mkdir(parents=True); (attack / 'run1/START.json').write_text(json.dumps(marker))
    if drift == 'ambiguity':
        (smoke / 'run1').mkdir(parents=True); (smoke / 'run1/START.json').write_text('{}')
    if drift is None:
        assert bind_freshness_preregistration(feature, smoke, formal, attack) == CONTRACT
    else:
        with pytest.raises(ValueError): bind_freshness_preregistration(feature, smoke, formal, attack)


def test_vm_service_is_detached_boot_enabled_and_not_a_zero_gate():
    unit = (ROOT / 'sentinel_pulse/systemd/sentinel-pulse-observation-attack.service').read_text()
    assert 'WantedBy=multi-user.target' in unit and 'Restart=on-failure' in unit
    assert 'TimeoutStartSec=infinity' in unit and 'User=dat' in unit
    assert '--password-file ${PULSE_ATTACK_CREDENTIAL}' in unit
    assert 'SSHPASS=' not in unit


@pytest.mark.parametrize('case', ['hit', 'miss', 'kernel_missing', 'sparse', 'cleanup_failed'])
def test_trial_live_path_retains_hit_miss_and_evidence_failure(tmp_path, monkeypatch, case):
    import sentinel_pulse.attack_trial as module
    class FakeRuntime:
        environment = {}
        marker = None
        def kubectl_json(self, *args):
            if args[:2] == ('get', 'node'):
                return {'status': {'conditions': [{'type': 'Ready', 'status': 'True'}]}}
            if 'kube-system' in args:
                return {'items': [{'metadata': {'name': 'sensor'}, 'spec': {'nodeName': 'node'}}]}
            return {'items': [{'metadata': {'name': 'x-pod', 'uid': 'uid'},
                'spec': {'nodeName': 'node', 'containers': [{'name': 'app'}]},
                'status': {'phase': 'Running', 'conditions': [{'type': 'Ready', 'status': 'True'}],
                           'containerStatuses': [{'ready': True}]}}]}
        def run(self, cmd, **kwargs):
            if 'list' in cmd:
                return subprocess.CompletedProcess(cmd, 0, b'sentinel-pulse-exec-provenance enabled', b'')
            if cmd[-4:] == ['a', '1', '12', '1']:
                return subprocess.CompletedProcess(cmd, 0, b'', b'sentinel-runtime-attack start\nsentinel-runtime-attack done')
            return subprocess.CompletedProcess(cmd, 1 if case == 'cleanup_failed' and 'rm' in cmd else 0, b'', b'')
        def remote_sudo(self, host, cmd, **kwargs):
            if cmd.startswith('cat '):
                payload = json.dumps({'cgroups': {'42': {'pod_uid': 'uid', 'container_name': 'app'}}}).encode()
            elif cmd.startswith('tee '):
                self.marker = json.loads(kwargs['payload']); payload = b''
            else:
                alert = dict(schema='sentinel-pulse-decision-v1', injection_id=self.marker['injection_id'],
                    status='alert', alerted_at=self.marker['injected_at']+.1,
                    window_end=self.marker['injected_at']+.25, cgroup_id='42', workload_key='production/x:app',
                    pod_uid='uid', node_name='node', model_manifest_sha256='m', decision_policy_sha256='p')
                if cmd.startswith('grep'):
                    payload = (json.dumps(alert)+'\n').encode() if case == 'hit' else b''
                elif case == 'sparse': payload = b''
                else: payload = (json.dumps(dict(alert, status='normal'))+'\n').encode()
            return subprocess.CompletedProcess([], 0, payload, b'')
    class FakeCapture:
        def wait(self, **kwargs): return 0
        def terminate(self): pass
        def kill(self): pass
    monkeypatch.setattr(module.subprocess, 'Popen', lambda *a, **k: FakeCapture())
    monkeypatch.setattr(module.time, 'sleep', lambda *_: None)
    def kernel(lines, marker, **kwargs):
        if case == 'kernel_missing': raise ValueError('no kernel event')
        return {'exec_id': 'exec', 'kernel_event_at': marker['injected_at']+.01}
    monkeypatch.setattr(module, 'find_execve_kprobe_event', kernel)
    binary = tmp_path / 'binary'; binary.write_bytes(b'unit-test-fixture-not-a-real-binary')
    row = dict(workload_controller='x', workload_key='production/x:app', scenario='a', seed=1, rate_per_second=12)
    result = module.execute(FakeRuntime(), tmp_path, row, 'run:0001',
        {'node': {'host': 'worker', 'injections': '/var/lib/sentinel-pulse-detector/runs/leg/injections.jsonl'}},
        binary, 1, 0, 'm', 'p')
    assert result['detected'] is (case == 'hit')
    assert result['status'] == ('observed' if case in {'hit', 'miss'} else 'infrastructure_unknown')
    assert (tmp_path / 'INTENTS.jsonl').exists()
    assert result['temporary_binary_cleanup_returncode'] == (1 if case == 'cleanup_failed' else 0)
