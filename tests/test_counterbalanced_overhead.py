import importlib.util
import json
from pathlib import Path

import pytest


PATH = Path(__file__).parents[1] / "sentinel/benchmarks/aggregate_counterbalanced_overhead.py"
spec = importlib.util.spec_from_file_location("aggregate_overhead", PATH)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def _write_campaign(root: Path, count: int = 6):
    for index, order in enumerate(sorted(module.EXPECTED_ORDERS)[:count], 1):
        experiment = f"campaign-p{index:02d}"
        phases = {}
        for name, rps, latency in (
            ("no_tracing", 1000, 10),
            ("tetragon_only", 980, 11),
            ("full_pipeline", 950, 12),
        ):
            phase_root = root / f"{name}-{experiment}"
            phase_root.mkdir()
            phase_report = {
                "experiment_id": experiment,
                "phase": name,
                "runs": [{"exit_code": 0}] * 10,
                "failed_requests_total": 0,
                "quality_gate": {"passed": True},
            }
            phase_path = phase_root / "report.json"
            phase_path.write_text(json.dumps(phase_report))
            import hashlib
            phases[name] = {
                "rps_median": rps,
                "latency_p99_ms_median": latency,
                "path": str(phase_path),
                "report_sha256": hashlib.sha256(
                    phase_path.read_bytes()
                ).hexdigest(),
            }
        protocol_path = root / f"protocol-{experiment}.json"
        protocol_path.write_text(json.dumps({
            "experiment_id": experiment,
            "phase_order": order,
            "repetitions_per_phase": 10,
        }))
        environment_path = root / f"environment-{experiment}.txt"
        environment_path.write_text("frozen cluster\n")
        import hashlib
        (root / f"comparison-wrk-{experiment}.json").write_text(json.dumps({
            "experiment_id": experiment, "phases": phases,
            "protocol_sha256": hashlib.sha256(
                protocol_path.read_bytes()
            ).hexdigest(),
            "environment_sha256": hashlib.sha256(
                environment_path.read_bytes()
            ).hexdigest(),
        }))


def test_aggregate_requires_all_orders_and_uses_paired_blocks(tmp_path):
    _write_campaign(tmp_path)
    report = module.aggregate(tmp_path, "campaign")
    assert len(report["experiments"]) == 6
    effect = report["effects"]["full_pipeline_vs_no_tracing"]
    assert effect["throughput_loss"]["median_percent"] == pytest.approx(5.0)
    assert effect["p99_latency_increase"]["median_percent"] == pytest.approx(20.0)


def test_aggregate_rejects_incomplete_campaign(tmp_path):
    _write_campaign(tmp_path, count=5)
    with pytest.raises(ValueError, match="incomplete"):
        module.aggregate(tmp_path, "campaign")


def test_aggregate_resolves_remote_paths_inside_copied_bundle(tmp_path):
    _write_campaign(tmp_path)
    for comparison in tmp_path.glob("comparison-*.json"):
        payload = json.loads(comparison.read_text())
        for phase in payload["phases"].values():
            directory = Path(phase["path"]).parent.name
            phase["path"] = f"/remote/collector/evidence/{directory}/report.json"
        comparison.write_text(json.dumps(payload))
    report = module.aggregate(tmp_path, "campaign")
    assert len(report["experiments"]) == 6


def test_v8_aggregate_binds_one_portable_terminal_prerequisite(tmp_path):
    _write_campaign(tmp_path)
    prerequisite = tmp_path / "prerequisite.json"
    prerequisite.write_text(json.dumps({
        "valid": True, "release_id": "v8-paired-replay-20260811",
        "automatic_promotion": False,
    }))
    import hashlib
    digest = hashlib.sha256(prerequisite.read_bytes()).hexdigest()
    for protocol_path in tmp_path.glob("protocol-*.json"):
        protocol = json.loads(protocol_path.read_text())
        protocol["evidence_release"] = "v8"
        protocol["prerequisite"] = {
            "path": "/remote/artifacts/prerequisite.json", "sha256": digest,
        }
        protocol_path.write_text(json.dumps(protocol))
        experiment = protocol["experiment_id"]
        comparison_path = tmp_path / f"comparison-wrk-{experiment}.json"
        comparison = json.loads(comparison_path.read_text())
        comparison["protocol_sha256"] = hashlib.sha256(
            protocol_path.read_bytes()
        ).hexdigest()
        comparison_path.write_text(json.dumps(comparison))
    report = module.aggregate(tmp_path, "campaign")
    assert report["evidence_release"] == "v8"
    assert all(row["prerequisite"]["sha256"] == digest
               for row in report["experiments"])


def test_aggregate_rejects_protocol_digest_drift(tmp_path):
    _write_campaign(tmp_path)
    path = next(tmp_path.glob("protocol-*.json"))
    path.write_text(path.read_text() + "\n")
    with pytest.raises(ValueError, match="protocol digest mismatch"):
        module.aggregate(tmp_path, "campaign")
