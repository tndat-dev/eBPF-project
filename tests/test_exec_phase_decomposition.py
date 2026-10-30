import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('p0', ROOT/'scripts'/'analysis'/'exec_phase_decomposition.py')
p0 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p0)


def trial(tmp, n, benign_pos, attack_pos):
    """30 windows per segment; *_pos: window indexes with a preview."""
    rows = []
    for start, pos in ((100.0, benign_pos), (200.0, attack_pos)):
        for i in range(30):
            rows.append(dict(status='candidate-raw-score-only', window_start=start + i * .5, window_end=start + (i + 1) * .5,
                             candidate_alert_preview=i in pos))
    d = dict(decisions=rows, benign=dict(start_at=100.0), attack=dict(start_at=200.0, scenario='x'))
    p = tmp/'trials'/str(n); p.mkdir(parents=True)
    (p/'EVALUATION_INPUT.json').write_text(json.dumps(d))


def test_startup_only_benign_flags_disappear_when_first_windows_are_skipped(tmp_path):
    trial(tmp_path, 1, {0, 1}, set(range(1, 30)))          # benign: only the first second; attack: throughout
    trial(tmp_path, 2, {0, 1, 10}, {2, 3})                   # benign flag at 5 s; attack only early
    r = p0.analyse([str(tmp_path)])
    b, a = r['flag_rate_if_first_k_windows_skipped']['benign'], r['flag_rate_if_first_k_windows_skipped']['attack']
    assert b['0']['rate'] == 1.0 and b['2']['rate'] == 0.5 and b['8']['rate'] == 0.5
    assert a['0']['rate'] == 1.0 and a['4']['rate'] == 0.5
    assert r['positive_rate_by_window_index']['benign'][0] == 1.0 and r['positive_rate_by_window_index']['benign'][5] == 0.0
