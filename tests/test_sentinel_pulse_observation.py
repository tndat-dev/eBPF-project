import copy
import json
from pathlib import Path

import pytest

from sentinel_pulse import observation_campaign as campaign
from sentinel_pulse.observation_audit import audit
from sentinel_pulse.detector_freshness import check, complete
from sentinel_pulse.telemetry_recovery import load_profile
from test_sentinel_pulse_telemetry_recovery import make_capture

PROTOCOL = Path(__file__).resolve().parents[1] / 'sentinel_pulse/protocol/observation-campaign-v1.json'
PROFILE = PROTOCOL.with_name('telemetry-recovery-v1.json')


def test_quality_rejection_does_not_remove_completed_exposure():
    p=json.loads(PROTOCOL.read_text())
    report={'valid_intervals':{'x':[[0,100]]},'all_alerts':{'x':5},'eligible_alerts':{'x':4},'excluded_rows':{'stale':2}}
    attempts=[{'run_id':'a','workers':{'one':report},'failures':{},'terminal':{'reason':'quality rejected'}},
              {'run_id':'b','workers':{},'failures':{'two':'infra unavailable'}}]
    r=campaign.summarize(attempts,['x'],p,100)
    assert r['valid_seconds_per_workload']['x']==100
    assert r['all_alerts']=={'x':5}
    assert not r['quality_budget_met']
    assert r['confusion_matrix_measured'] is None and r['precision'] is None
    # Recovered segment adds exposure; duplicates from simultaneous replicas
    # are unioned, rather than counting worker-hours as workload-hours.
    recovered=copy.deepcopy(report);recovered['valid_intervals']={'x':[[50,200]]}
    attempts.append({'run_id':'c','workers':{'one':recovered},'failures':{}})
    assert campaign.summarize(attempts,['x'],p,200)['valid_seconds_per_workload']['x']==200


def test_exposure_completion_independent_of_alert_budget():
    p=json.loads(PROTOCOL.read_text());p.update(minimum_wall_seconds=100,target_valid_seconds_per_workload=100)
    r=campaign.summarize([{'run_id':'a','workers':{'a':{'valid_intervals':{'x':[[0,100]]},
        'all_alerts':{'x':100},'eligible_alerts':{'x':100},'excluded_rows':{}}},'failures':{}}],['x'],p,100)
    assert r['exposure_target_reached'] and not r['quality_budget_met']


def test_zero_gate_not_allowed():
    p=json.loads(PROTOCOL.read_text());p['stop_on_alert']=True
    with pytest.raises(ValueError):campaign.validate_protocol(p)


def sealed_segment(tmp_path,monkeypatch):
    profile=load_profile(PROFILE)
    capture,features=make_capture(tmp_path,monkeypatch,profile,[100+i*.5 for i in range(45)])
    capture.rename(tmp_path/'features.jsonl')
    decisions=[]
    for f in features:
        if f.get('schema')!='sentinel-pulse-feature-v1':continue
        fresh=complete(check(f,f['emitted_at']+.001),f['window_end'],f['emitted_at']+.002)
        decisions.append({**f,'status':'alert' if f['telemetry_recovery']['eligible'] else 'telemetry-degraded',
            'run_id':'r','model_manifest_sha256':'m','decision_policy_sha256':'p','detector_freshness':fresh})
    (tmp_path/'decisions.jsonl').write_text(''.join(json.dumps(r)+'\n' for r in decisions))
    (tmp_path/'alerts.jsonl').write_text(''.join(json.dumps(r)+'\n' for r in decisions if r['status']=='alert'))
    import subprocess
    result=subprocess.check_output(['sha256sum','features.jsonl','decisions.jsonl','alerts.jsonl'],cwd=tmp_path,text=True)
    (tmp_path/'FORMAL_WORKER_SHA256SUMS').write_text(result)
    marker={'started_at_unix':100,'run_id':'r','model_manifest_sha256':'m','decision_policy_sha256':'p',
            'telemetry_recovery_contract':{'profile':profile}}
    return marker


def test_sealed_prefix_keeps_alerts_in_degraded_time(tmp_path,monkeypatch):
    marker=sealed_segment(tmp_path,monkeypatch)
    health=[{'checked_at_unix':110,'fatal':[],'degraded':True},
            {'checked_at_unix':130,'fatal':[],'degraded':False}]
    r=audit(tmp_path,marker,health)
    assert r['all_alerts']['production/test:app']>0
    assert not r['eligible_alerts']
    assert r['excluded_rows']['health_degraded']>0
    assert r['precision'] is None


def test_raw_alert_tampering_rejected_even_without_quality_gate(tmp_path,monkeypatch):
    marker=sealed_segment(tmp_path,monkeypatch)
    (tmp_path/'alerts.jsonl').write_text('')
    with pytest.raises(Exception):audit(tmp_path,marker,[{'checked_at_unix':130,'fatal':[],'degraded':False}])


def test_campaign_runs_again_after_failed_segment_and_keeps_prefix(tmp_path,monkeypatch):
    p=json.loads(PROTOCOL.read_text())
    p.update(minimum_wall_seconds=180,target_valid_seconds_per_workload=180,maximum_wall_seconds=600,retry_seconds=.01)
    source=tmp_path/'source';source.mkdir()
    model=tmp_path/'model';model.mkdir();(model/'manifest.json').write_text(json.dumps({'workloads':{'x':{}}}))
    policy=tmp_path/'policy.json';policy.write_text('{}')
    cfg={'source':str(source),'model':str(model),'policy':str(policy)}
    monkeypatch.setattr('sentinel_pulse.recovery_worker_probe.clean_source',lambda _:('a'*40,{'code':'b'*64}))
    clock=[100.0];monkeypatch.setattr(campaign.time,'time',lambda:clock[0])
    launched=[]
    def run(root,*args,**kwargs):
        launched.append(root.name);root.mkdir(parents=True)
        (root/'START.json').write_text('{}');(root/'dependency-health.jsonl').write_text('')
        terminal={'reason':'telemetry fatal' if len(launched)==1 else None}
        (root/'TERMINAL.json').write_text(json.dumps(terminal));clock[0]+=100
    monkeypatch.setattr(campaign.coordinator,'run',run)
    class Remote:
        def call(self,*args,**kwargs):
            left=100 if len(launched)==1 else 200
            return {'valid_intervals':{'x':[[left,left+100]]},'all_alerts':{'x':2},'eligible_alerts':{'x':1},'excluded_rows':{}}
    r=campaign._campaign_owned(tmp_path/'campaign',cfg,Remote(),p)
    assert len(launched)==2
    assert r['status']=='completed' and r['valid_seconds_per_workload']=={'x':200}
    assert not r['quality_budget_met'] and r['all_alerts']['x']==12
    # Same registration/evidence survives a second invocation.
    assert campaign._campaign_owned(tmp_path/'campaign',cfg,Remote(),p)==r
