"""Campaign trial order (next live run, protocol registered before it): fixed by default, seeded shuffle on request."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sentinel_pulse.attack import preview_campaign as pc  # noqa: E402

ITEM = dict(seed=61501)


def test_default_order_is_the_order_of_earlier_runs():
    assert pc.step_order({}, ITEM, 1) == ['admin', 'benign', 'attack']
    assert pc.step_order(dict(lotl_attack=True), ITEM, 1) == ['admin', 'benign', 'attack', 'lotl']


def test_random_order_is_seeded_per_pair_and_covers_every_position():
    cfg = dict(random_trial_order=True, lotl_attack=True)
    orders = [tuple(pc.step_order(cfg, ITEM, i)) for i in range(1, 201)]
    assert orders == [tuple(pc.step_order(cfg, ITEM, i)) for i in range(1, 201)]      # a rerun repeats it
    assert all(sorted(o) == ['admin', 'attack', 'benign', 'lotl'] for o in orders)
    assert {o.index('attack') for o in orders} == {0, 1, 2, 3}                        # attack first, middle, last
    first_attack = sum(o.index('attack') < o.index('benign') for o in orders)
    assert 60 < first_attack < 140                                                     # about half before the benign run


def test_new_admin_set_shares_no_tool_with_the_old_one():
    old = {name for name, _ in pc.ADMIN_COMMANDS}
    new = {name for name, _ in pc.ADMIN_COMMANDS_V6}
    assert len(new) == 10 and not old & new
    assert 'serviceaccount/token' in pc.LOTL_SCRIPT and '>/dev/null' in pc.LOTL_SCRIPT and 'lotl-done' in pc.LOTL_SCRIPT


def test_live_analysis_labels_the_lotl_interval(tmp_path):
    import json
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts' / 'analysis'))
    import pulse_live_v4 as live
    rows = [dict(label='attack_lotl', start_at=1.0, pod_uid='p', container_name='c', trial_id='3:lotl', workload_key='w'),
            dict(label='attack', start_at=2.0, pod_uid='p', container_name='c', trial_id='3:attack', workload_key='w')]
    (tmp_path / 'INTERVALS.jsonl').write_text(''.join(json.dumps(r) + '\n' for r in rows))
    labels = [t['label'] for t in live.load_trials(tmp_path)]
    assert labels == ['lotl', 'attack']


def test_dilution_trials_are_extra_items_at_one_rate():
    import re
    text = (Path(__file__).resolve().parents[1] / 'sentinel_pulse/pipeline/plan_matched_run.py').read_text()
    assert "pad=pad)" in text and "tokens.get('dilution_pads')" in text
    campaign = (Path(__file__).resolve().parents[1] / 'sentinel_pulse/attack/preview_campaign.py').read_text()
    assert "*([str(item['pad'])] if item.get('pad') else [])" in campaign      # PAD 0 keeps the earlier argv
    fixture = (Path(__file__).resolve().parents[1] / 'testbed/attack/runtime_attack_with_benign_control.c').read_text()
    assert re.search(r'int pad = argc > 5 \? atoi\(argv\[5\]\) : 0;', fixture)
