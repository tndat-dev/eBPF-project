"""Rule layer scorer (ml-final-study-v1 part E; pulse-live-v6-v1 H4, H5): R1 downgrades image-tool alerts, which on v6
includes the living-off-the-land step (the harm side); dilution pairs are their own sets."""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts' / 'analysis'))
sys.path.insert(0, str(ROOT))

import rule_e_benefit as r  # noqa: E402


def trial(label, pair, rate=None, pad=0, command=None):
    return dict(label=label, pair=pair, rate=rate, pad=pad, command=command, workload='w')


def test_lotl_is_an_attack_that_r1_downgrades_and_pads_stay_apart():
    trials = [trial('control', 1), trial('admin', 1, 12, command='ls'), trial('benign', 1, 12), trial('lotl', 1, 12),
              trial('attack', 1, 12),
              trial('control', 2), trial('admin', 2, 12, 300, 'cat'), trial('lotl', 2, 12, 300), trial('attack', 2, 12, 300)]
    agg, per_command = r.tally(trials, {'w': ('lm', 1.0)}, lambda t: t['label'] != 'control')
    assert agg['lotl-primary'] == dict(n=1, ml=1, after_r1=0, r2_drift=0)            # flagged, then downgraded by R1
    assert agg['attack-primary']['after_r1'] == 1 and agg['attack-primary']['r2_drift'] == 1
    assert agg['control-primary']['n'] == 1                                          # rate taken from the pair
    assert agg['attack-pad300']['n'] == 1 and agg['lotl-pad300']['after_r1'] == 0 and 'attack-pad300' not in ('attack',)
    assert agg['attack']['n'] == 1 and agg['admin']['n'] == 1                        # pad pair not in the base sets
    assert set(per_command) == {'ls'}
    c = r.two_system(agg, '-primary')
    assert c['ml_only']['lotl_recall']['rate'] == 1.0 and c['ml_plus_rule']['lotl_recall']['rate'] == 0.0
    assert c['ml_plus_rule']['false_alarm_by_class']['admin']['hit'] == 0
