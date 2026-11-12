"""Parts B2/B3 of ml-final-study-v1 amendment 1: the lineage proxy and the session model."""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts' / 'analysis'))
sys.path.insert(0, str(ROOT))

import session_model as sm  # noqa: E402
from sentinel_pulse.detector.token_model import TOK_NONE, CountTokenLM  # noqa: E402

A, B, L, T, X = 1 << 23, 2 << 23, 3 << 23, 4 << 23, 5 << 23     # service A, B; launch L; tool T; attack X


def workload():
    lm = CountTokenLM()
    for _ in range(300):
        lm.learn((A, B, A, B))
        lm.learn((B, A, B, A))
    return lm.finalize()


def trial(label, pair, start, command=None, rate=12):
    return dict(label=label, start=start, key=('pod', 'c'), pair=pair, workload='w', rate=rate, scenario='s', command=command)


def test_split_sends_unseen_grams_to_the_session_side():
    lm = workload()
    native, session = sm.split(lm, [(A, B, A, B, 9), (TOK_NONE, TOK_NONE, TOK_NONE, L, 1), (L, T, T, T, 3)])
    assert native == [(A, B, A, B, 9)] and len(session) == 2


def test_known_tool_is_quiet_and_the_attack_is_not():
    lm = workload()
    service = (A, B, A, B, 40)
    tool = [(TOK_NONE, TOK_NONE, TOK_NONE, L, 1), (TOK_NONE, TOK_NONE, L, T, 1), (L, T, T, T, 20)]
    attack = tool + [(T, X, X, X, 12)]
    trials, windows, t0 = [], {('pod', 'c'): []}, 1000.0
    for pair in range(40):
        for k, (label, grams) in enumerate((('control', []), ('admin', tool), ('benign', tool), ('attack', attack))):
            start = t0 + pair * 100 + k * 20
            trials.append(trial(label, pair, start, 'ls' if label == 'admin' else None))
            windows[('pod', 'c')].append((start + 1.0, [service] + grams, None, 5.0))
    out = sm.part_b3(trials, windows, {'w': ('unused', 5.0)}, {'w': lm})
    assert out['native_arm']['admin']['k'] == 0 and out['native_arm']['attack']['k'] == 0
    assert out['known_tools']['flagged']['k'] == 0
    assert out['attack_tools_only']['all']['k'] == 40 and out['attack_program_learnt']['all']['k'] == 40
    assert out['learnt_program']['benign']['all']['k'] == 0
    assert out['decision']['build_lineage_tag'] is True
