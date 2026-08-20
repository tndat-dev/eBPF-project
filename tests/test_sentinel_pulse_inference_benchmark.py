from sentinel_pulse.benchmark_inference import distribution


def test_distribution_reports_expected_quantiles():
    report = distribution([1.0, 2.0, 3.0, 4.0])
    assert report["count"] == 4
    assert report["mean"] == 2.5
    assert report["p50"] == 2.5
    assert report["max"] == 4.0


def test_distribution_handles_empty_input():
    report = distribution([])
    assert report == {
        "count": 0,
        "mean": None,
        "p50": None,
        "p95": None,
        "p99": None,
        "max": None,
    }
