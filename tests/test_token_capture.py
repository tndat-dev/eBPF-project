

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
