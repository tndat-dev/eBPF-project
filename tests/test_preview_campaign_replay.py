import json

import pytest

from sentinel_pulse.integrity import sha256_file
from sentinel_pulse.attack.replay_preview_campaign import replay


def test_replay_preserves_dispatch_failure_and_parent_evidence(tmp_path):
    campaign=tmp_path/'parent';campaign.mkdir()
    config=tmp_path/'config.json'
    config.write_text(json.dumps(dict(campaign_output=str(campaign),model_hash='m',
        policy_hash='p',schedule=[dict(scenario='known')])))
    (campaign/'START.json').write_text(json.dumps(dict(binding=dict(
        config_sha256=sha256_file(config),model_hash='m',policy_hash='p'))))
    pair=[dict(label='attack',outcome='unknown',reason='stage_failed'),
          dict(label='expected_normal',outcome='TN_expected')]
    (campaign/'RESULTS.json').write_text(json.dumps(dict(completed={'1':pair},outcomes=pair)))
    (campaign/'TERMINAL.json').write_text('{"state":"completed"}')
    before={p.name:sha256_file(p) for p in campaign.iterdir()}
    result=replay(config,tmp_path/'replay')
    assert result['unknown']==1
    assert result['confusion_matrix_expected_control_labels']['TN']==1
    assert result['preserved_pairs_without_raw_input']==1
    assert before=={p.name:sha256_file(p) for p in campaign.iterdir()}
    assert json.loads((tmp_path/'replay/OUTCOMES.json').read_text())==pair
    with pytest.raises(FileExistsError):replay(config,tmp_path/'replay')
