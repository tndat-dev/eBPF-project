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
    # PAD 0 without on-off keeps the earlier argv; an on-off trial passes PAD (0) and its period (improvement-round-v1 D12)
    assert "*([str(item.get('pad') or 0)] if item.get('pad') or item.get('on_off') else [])" in campaign
    assert "*([str(item['on_off'])] if item.get('on_off') else [])" in campaign
    fixture = (Path(__file__).resolve().parents[1] / 'testbed/attack/runtime_attack_with_benign_control.c').read_text()
    assert re.search(r'int pad = argc > 5 \? atoi\(argv\[5\]\) : 0;', fixture)


def test_eventgen_step_and_outcome():
    from sentinel_pulse.attack.preview_campaign import EVENTGEN_ACTIONS, eventgen_outcome, step_order
    assert len(EVENTGEN_ACTIONS) == 14 and len(set(EVENTGEN_ACTIONS)) == 14
    assert eventgen_outcome(b'INFO action executed action=syscall.X') == 'executed'
    assert eventgen_outcome(b'ERRO action error error="permission denied"') == 'error'
    assert eventgen_outcome(b'WARN action skipped reason=...') == 'skipped'
    assert 'eventgen' in step_order(dict(eventgen_binary='/x'), dict(seed=1), 3)
    assert 'eventgen' not in step_order({}, dict(seed=1), 3)


def test_rehearsal_takes_one_trial_of_each_kind():
    from sentinel_pulse.pipeline.plan_matched_run import REHEARSAL_TARGETS, rehearsal_schedule
    sched = [dict(workload_controller=c, rate_per_second=r, scenario='s', seed=1) for c in REHEARSAL_TARGETS for r in (0.1, 1, 6, 12, 24)]
    sched += [dict(workload_controller=c, rate_per_second=12, scenario='s', seed=1, pad=300) for c in REHEARSAL_TARGETS]
    sched += [dict(workload_controller=c, rate_per_second=12, scenario='s', seed=1, on_off=10) for c in REHEARSAL_TARGETS]
    out = rehearsal_schedule(sched)
    assert len(out) == 6
    assert [o['workload_controller'] for o in out] == list(REHEARSAL_TARGETS)
    assert out[1]['rate_per_second'] < 1 and out[2].get('pad') and out[3].get('on_off')
