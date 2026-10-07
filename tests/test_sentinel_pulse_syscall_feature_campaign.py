import json
import pytest
from sentinel_pulse.syscall_feature_campaign import campaign


def test_reboot_after_completion_does_not_start_training_again(tmp_path,monkeypatch):
    attempt=tmp_path/'attempt-000001';attempt.mkdir()
    for filename in ['START.json','RESULTS.json']:(attempt/filename).write_text('{}')
    (attempt/'TERMINAL.json').write_text(json.dumps({'state':'completed','completed_fits':608}))
    monkeypatch.setattr('sentinel_pulse.syscall_feature_campaign.run',lambda *args:pytest.fail('unexpected retrain'))
    assert campaign(tmp_path/'inputs',tmp_path)['completed_fits']==608


def test_campaign_skips_partial_directory_and_resumes_latest_committed_results(tmp_path,monkeypatch):
    first=tmp_path/'attempt-000001';first.mkdir()
    (first/'START.json').write_text('{}');(first/'RESULTS.json').write_text('{}')
    incomplete=tmp_path/'attempt-000002';incomplete.mkdir();(incomplete/'START.json').write_text('{}')
    called=[]
    monkeypatch.setattr('sentinel_pulse.syscall_feature_campaign.run',lambda *args:called.append(args) or {'state':'completed'})
    campaign(tmp_path/'inputs',tmp_path)
    assert called[0][1]==tmp_path/'attempt-000003'
    assert called[0][2]==first
