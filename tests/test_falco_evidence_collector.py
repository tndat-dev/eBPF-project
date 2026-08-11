import importlib.util
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "ml-service" / "falco_evidence_collector.py"
if not MODULE.is_file():
    MODULE = ROOT / "falco_evidence_collector.py"
spec = importlib.util.spec_from_file_location("falco_evidence_collector", MODULE)
collector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector)


def test_parser_keeps_only_privacy_safe_aims_decision_metadata():
    line = (
        "2026-08-11T12:08:00.123456Z 12:08:00.100000: Warning "
        "Terminal shell in container | command=/bin/sh secret=do-not-store "
        "file=/etc/shadow k8s_pod_name=api-gateway-abc123 "
        "k8s_ns_name=production"
    )
    row = collector.parse_falco_line(
        line, source_pod="falco-a", source_node="worker-a", release_id="v8",
    )
    assert row is not None
    assert row["rule"] == "Terminal shell in container"
    assert row["priority"] == "Warning"
    assert row["target_pod"] == "api-gateway-abc123"
    assert row["contains_arguments_or_payloads"] is False
    assert row["raw_output_stored"] is False
    serialized = str(row)
    assert "do-not-store" not in serialized
    assert "/etc/shadow" not in serialized
    assert "command" not in serialized


def test_parser_rejects_non_aims_and_non_production_alerts():
    base = (
        "2026-08-11T12:08:00Z 12:08:00.0: Notice Rule | "
        "k8s_pod_name={pod} k8s_ns_name={namespace}"
    )
    assert collector.parse_falco_line(
        base.format(pod="strimzi-1", namespace="production"),
        source_pod="falco-a", source_node="worker", release_id="v8",
    ) is None
    assert collector.parse_falco_line(
        base.format(pod="api-gateway-1", namespace="default"),
        source_pod="falco-a", source_node="worker", release_id="v8",
    ) is None


def test_event_identity_is_deterministic():
    line = (
        "2026-08-11T12:08:00Z 12:08:00.0: Notice Rule | "
        "k8s_pod_name=cart-service-1 k8s_ns_name=production"
    )
    first = collector.parse_falco_line(
        line, source_pod="falco-a", source_node="worker", release_id="v8",
    )
    second = collector.parse_falco_line(
        line, source_pod="falco-a", source_node="worker", release_id="v8",
    )
    assert first["event_id"] == second["event_id"]


def test_log_timestamp_parser_is_timezone_safe():
    value = collector.line_timestamp(
        "2026-08-11T12:08:00.500000Z privacy-unsafe-body-is-not-retained"
    )
    assert value == 1786450080.5
    assert collector.line_timestamp("not-a-timestamp body") is None


def test_systemd_collector_is_non_privileged_and_bounded():
    unit = (ROOT / "sentinel/systemd/aims-v8-falco-evidence.service").read_text()
    assert "User=dat" in unit
    assert "NoNewPrivileges=true" in unit
    assert "CPUQuota=25%" in unit
    assert "MemoryMax=256M" in unit
    assert "--since-time 2026-08-11T12:05:59Z" in unit
    assert "v8-paired-replay-20260811" in unit
