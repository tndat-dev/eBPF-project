"""token_load.py: per-window events and distinct grams, node sums, last drain counters."""
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts' / 'analysis'))
sys.path.insert(0, str(ROOT))

import token_load as tl  # noqa: E402


def test_windows_and_drains(tmp_path):
    seg = tmp_path / 'workers' / 'w1' / 'segments' / 's00010'
    seg.mkdir(parents=True)
    rows = [dict(type='token_window', node_name='n', window=1, events=10, grams=[[1, 2, 3, 4, 6], [1, 2, 3, 5, 4]]),
            dict(type='token_window', node_name='n', window=1, events=3, grams=[[1, 2, 3, 4, 3]])]
    (seg / 'tokens.jsonl').write_text(''.join(json.dumps(r) + '\n' for r in rows))
    drain = lambda f: '{"type":"token_drain","drain_seconds":%s,"grams_cumulative":%d,"entries_cumulative":5,' \
                      '"insert_fail_cumulative":%d,"dir_fail_cumulative":0}\n' % (f, 13, 0)
    (seg / 'features.jsonl').write_text(drain(0.01) + drain(0.02))
    e, g, n = tl.windows(seg)
    assert e == [10, 3] and g == [2, 1] and n == [[13, 3]]
    last, times = tl.drains(tmp_path / 'workers' / 'w1')
    assert last['grams_cumulative'] == 13 and times == [0.01, 0.02]
