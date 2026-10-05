from pathlib import Path

from sentinel_pulse.cgroup_pressure import FILES, MAX_READ_BYTES, SERVICES, sample


def test_missing_service_cgroups_are_not_silent_zeroes(tmp_path):
    result = sample(tmp_path)
    for entry in result["services"].values():
        assert not entry["files"]
        assert set(entry["read_errors"]) == set(FILES)


def test_records_reclaim_cache_and_pressure_without_changing_limits(tmp_path):
    root = tmp_path / SERVICES[0]
    root.mkdir()
    data = {"memory.high": "536870912\n", "memory.events": "high 123\noom 0\n",
            "memory.stat": "anon 50000000\nfile 450000000\n",
            "memory.pressure": "some avg10=0.1 total=1234\n",
            "cpu.stat": "nr_throttled 73\nthrottled_usec 9935942\n"}
    for name, value in data.items():
        (root / name).write_text(value)
    result = sample(tmp_path)["services"][SERVICES[0]]
    assert result["files"]["memory.events"] == data["memory.events"].strip()
    assert result["files"]["memory.high"] == "536870912"
    assert "file 450000000" in result["files"]["memory.stat"]
    for name, value in data.items():
        assert (root / name).read_text() == value


def test_reads_bounded_explicit_fields_only(tmp_path):
    root = tmp_path / SERVICES[0]
    root.mkdir()
    (root / "io.stat").write_bytes(b"x" * (MAX_READ_BYTES + 1))
    (root / "environment").write_text("fixture secret that must not be inspected")
    result = sample(tmp_path)["services"][SERVICES[0]]
    assert "read bound" in result["read_errors"]["io.stat"]
    assert "environment" not in result["files"]


def test_pressure_probe_has_no_production_side_effects():
    text = Path("sentinel_pulse/cgroup_pressure.py").read_text()
    assert 'open("rb")' in text
    assert "subprocess" not in text
