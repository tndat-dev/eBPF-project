

def test_map_overflow_alerts_the_heaviest_window_once():
    from sentinel_pulse.collector.token_capture import MapOverflow
    o = MapOverflow()
    w = [dict(grams=[[1, 2, 3, 4, 1]]), dict(grams=[[1, 2, 3, 4, 1]] * 5)]
    assert o.frame(dict(insert_fail_cumulative=0), w) == (None, False)          # first drain only sets the reference
    assert o.frame(dict(insert_fail_cumulative=0), w) == (None, False)
    assert o.frame(dict(insert_fail_cumulative=7), []) == (None, True)          # overflow, no window yet: waits
    assert o.frame(dict(insert_fail_cumulative=7), w) == (1, True)             # next frame with windows: the heavy one
    assert o.frame(dict(insert_fail_cumulative=7), w) == (None, False)
    assert o.frame(dict(insert_fail_cumulative=0), w) == (None, False)          # loader restart resets the reference
    assert o.frame(None, w) == (None, False)


def test_overflow_replay_names_the_stress_cgroup():
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
    import map_overflow_test as t
    lines = ['{"type":"token_drain","insert_fail_cumulative":0}', '{"type":"snapshot_end","observed_at":1.0}',
             '{"type":"token_grams","cgroup_id":7,"window_end":1.5,"grams":[[1,2,3,4,1]]}',
             '{"type":"token_grams","cgroup_id":9,"window_end":1.5,"grams":[[1,2,3,4,1],[1,2,3,5,1]]}',
             '{"type":"token_drain","insert_fail_cumulative":40}', '{"type":"snapshot_end","observed_at":1.5}']
    res = t.judge(t.frames(lines), 9)
    assert res['met'] and res['alert_cgroup'] == 9 and res['delay'] == 0.0


def test_open_sealed_reads_a_gz_path_given_directly(tmp_path):
    import gzip
    from sentinel_pulse.common import open_sealed
    (tmp_path / 'tokens.jsonl.gz').write_bytes(gzip.compress(b'{"a":1}\n'))
    with open_sealed(tmp_path / 'tokens.jsonl.gz') as f:
        assert f.read() == '{"a":1}\n'
    with open_sealed(tmp_path / 'tokens.jsonl') as f:
        assert f.read() == '{"a":1}\n'
