import importlib.util
import hashlib
import json
import pickle
import sys
from pathlib import Path

import pytest

np = pytest.importorskip("numpy")


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = REPOSITORY_ROOT / "ml-service" / "build_phase_dataset.py"
if not MODULE_PATH.is_file():
    # The VM deployment intentionally flattens ml-service/ into its runtime
    # root. Keep the same artifact test runnable in both layouts.
    MODULE_PATH = REPOSITORY_ROOT / "build_phase_dataset.py"
spec = importlib.util.spec_from_file_location("build_phase_dataset", MODULE_PATH)
phase_dataset = importlib.util.module_from_spec(spec)
spec.loader.exec_module(phase_dataset)


def make_phase(path, phase_name, backpressure=0, membership_failures=0,
               coverage_failures=0, stream_failures=0, extra_syscall=None):
    path.mkdir()
    targets = {}
    for offset, pod_key in enumerate(phase_dataset.TARGETS):
        stem = pod_key.replace("/", "__")
        array = np.full((25, 4), offset / 10.0, dtype=np.float32)
        np.save(path / f"{stem}.npy", array)
        metadata = path / f"{stem}_metadata.jsonl"
        rows = []
        for index in range(25):
            counts = {"read": 120 + index}
            if extra_syscall:
                counts[extra_syscall] = 1
            rows.append(json.dumps({
                "event_count": sum(counts.values()),
                "phase": phase_name,
                "syscall_counts": counts,
            }) + "\n")
        metadata.write_text("".join(rows))
        targets[pod_key] = {"shape": [25, 4]}
    (path / "collection_manifest.json").write_text(json.dumps({
        "phase": phase_name,
        "window_seconds": 30,
        "sensor_health": {
            "backpressure_events": backpressure,
            "membership_failures": membership_failures,
            "coverage_failures": coverage_failures,
            "stream_failures": stream_failures,
            "require_full_coverage": True,
            "coverage_healthy": True,
        },
        "targets": targets,
    }))


def test_phase_builder_creates_exact_stratified_holdout(tmp_path, monkeypatch):
    phases = []
    for name in ("normal", "wrk", "high", "recovery"):
        path = tmp_path / name
        make_phase(path, name)
        phases.append(path)
    output = tmp_path / "dataset"
    monkeypatch.setattr(sys, "argv", [
        "build_phase_dataset.py", *(str(path) for path in phases),
        "--output", str(output), "--minimum-events", "100",
        "--minimum-phase-windows", "20",
    ])
    assert phase_dataset.main() == 0
    manifest = json.loads((output / "phase_dataset_manifest.json").read_text())
    assert len(manifest["source_manifests"]) == 4
    assert manifest["window_seconds"] == 30
    for target in phase_dataset.TARGETS:
        item = manifest["targets"][target]
        assert item["shape"] == [100, 4]
        assert item["train_count"] == 80
        assert item["validation_count"] == 20
        assert item["startup_grace"]["validation_count"] == 0


def test_phase_builder_preserves_verified_startup_rows_in_both_splits(
        tmp_path, monkeypatch):
    phases = []
    for name in ("normal", "lifecycle", "high", "recovery"):
        path = tmp_path / name
        make_phase(path, name)
        phases.append(path)
    lifecycle = phases[1]
    for pod_key in phase_dataset.TARGETS:
        metadata_path = lifecycle / f"{pod_key.replace('/', '__')}_metadata.jsonl"
        rows = [json.loads(line) for line in metadata_path.read_text().splitlines()]
        for index in (1, 2, 3):
            rows[index].update({
                "pod_key": f"{pod_key}-abcdef1234-x1y2z",
                "window_end": 1_000.0 + index,
                "pod_creation_timestamp": 970.0,
                "startup_age_seconds": 30.0 + index,
                "startup_grace_eligible": True,
            })
        metadata_path.write_text("".join(json.dumps(row) + "\n" for row in rows))
    output = tmp_path / "dataset"
    monkeypatch.setattr(sys, "argv", [
        "build_phase_dataset.py", *(str(path) for path in phases),
        "--output", str(output), "--minimum-events", "100",
        "--minimum-phase-windows", "20", "--startup-grace-seconds", "60",
    ])
    assert phase_dataset.main() == 0
    manifest = json.loads((output / "phase_dataset_manifest.json").read_text())
    for target in phase_dataset.TARGETS:
        startup = manifest["targets"][target]["startup_grace"]
        assert startup["train_count"] >= 1
        assert startup["validation_count"] >= 1
        assert startup["fail_closed"] is True


def test_phase_builder_rejects_unproven_startup_grace(tmp_path, monkeypatch):
    phase = tmp_path / "lifecycle"
    make_phase(phase, "lifecycle")
    stem = phase_dataset.TARGETS[0].replace("/", "__")
    metadata_path = phase / f"{stem}_metadata.jsonl"
    rows = [json.loads(line) for line in metadata_path.read_text().splitlines()]
    rows[0]["startup_grace_eligible"] = True
    metadata_path.write_text("".join(json.dumps(row) + "\n" for row in rows))
    monkeypatch.setattr(sys, "argv", [
        "build_phase_dataset.py", str(phase),
        "--output", str(tmp_path / "dataset"),
        "--minimum-phase-windows", "20",
    ])
    with pytest.raises(ValueError, match="without pod-age evidence"):
        phase_dataset.main()


def test_phase_builder_accepts_explicit_aims_workload_contract():
    targets = phase_dataset.parse_targets(
        "production/aims-backend,production/aims-frontend,production/aims-postgres"
    )
    assert targets == (
        "production/aims-backend", "production/aims-frontend",
        "production/aims-postgres",
    )
    with pytest.raises(ValueError, match="unique"):
        phase_dataset.parse_targets("production/aims-backend,production/aims-backend")


def test_phase_builder_rejects_sensor_backpressure(tmp_path, monkeypatch):
    phase = tmp_path / "bad"
    make_phase(phase, "bad", backpressure=1)
    monkeypatch.setattr(sys, "argv", [
        "build_phase_dataset.py", str(phase),
        "--output", str(tmp_path / "output"),
    ])
    with pytest.raises(ValueError, match="sensor backpressure"):
        phase_dataset.main()


def test_phase_builder_rejects_missing_continuity_counter(tmp_path, monkeypatch):
    phase = tmp_path / "legacy"
    make_phase(phase, "legacy")
    manifest_path = phase / "collection_manifest.json"
    manifest = json.loads(manifest_path.read_text())
    del manifest["sensor_health"]["stream_failures"]
    manifest_path.write_text(json.dumps(manifest))
    monkeypatch.setattr(sys, "argv", [
        "build_phase_dataset.py", str(phase),
        "--output", str(tmp_path / "output"),
    ])
    with pytest.raises(ValueError, match="sensor health schema incomplete"):
        phase_dataset.main()


@pytest.mark.parametrize(
    ("field", "message"),
    (("membership_failures", "sensor continuity failure"),
     ("coverage_failures", "sensor continuity failure"),
     ("stream_failures", "sensor continuity failure")),
)
def test_phase_builder_rejects_sensor_continuity_failures(
        tmp_path, monkeypatch, field, message):
    phase = tmp_path / "interrupted"
    kwargs = {field: 1}
    make_phase(phase, "interrupted", **kwargs)
    monkeypatch.setattr(sys, "argv", [
        "build_phase_dataset.py", str(phase),
        "--output", str(tmp_path / "output"),
    ])
    with pytest.raises(ValueError, match=message):
        phase_dataset.main()


def test_phase_builder_pads_index_preserving_policy_vocabulary(tmp_path, monkeypatch):
    phases = []
    for name in ("normal", "wrk", "high", "recovery"):
        path = tmp_path / name
        make_phase(path, name)
        phases.append(path)
    vocab_path = tmp_path / "vocab.pkl"
    source_vocab = {
        "read": 0, "write": 1, "read|read": 2, "write|write": 3,
    }
    with vocab_path.open("wb") as handle:
        pickle.dump(source_vocab, handle)
    output = tmp_path / "dataset"
    monkeypatch.setattr(sys, "argv", [
        "build_phase_dataset.py", *(str(path) for path in phases),
        "--output", str(output), "--minimum-events", "100",
        "--minimum-phase-windows", "20", "--vocab", str(vocab_path),
    ])
    assert phase_dataset.main() == 0
    with (output / "vocab.pkl").open("rb") as handle:
        expanded = pickle.load(handle)
    assert all(expanded[key] == index for key, index in source_vocab.items())
    assert {"capset", "ptrace"} <= set(expanded)
    array = np.load(output / "production__nginx.npy", allow_pickle=False)
    assert array.shape == (100, len(expanded))
    assert np.all(array[:, len(source_vocab):] == 0)


def test_phase_builder_mixes_source_and_native_expanded_captures(
        tmp_path, monkeypatch):
    phases = []
    for name in ("normal", "wrk", "high", "drift"):
        path = tmp_path / name
        make_phase(path, name)
        phases.append(path)
    vocab_path = tmp_path / "vocab.pkl"
    source_vocab = {
        "read": 0, "write": 1, "read|read": 2, "write|write": 3,
    }
    with vocab_path.open("wb") as handle:
        pickle.dump(source_vocab, handle)
    expanded = phase_dataset.expand_vocabulary(
        source_vocab, phase_dataset.POLICY_SYSCALLS
    )
    expanded_payload = pickle.dumps(expanded)
    expanded_hash = hashlib.sha256(expanded_payload).hexdigest()
    native = phases[-1]
    for pod_key in phase_dataset.TARGETS:
        stem = pod_key.replace("/", "__")
        array_path = native / f"{stem}.npy"
        source = np.load(array_path, allow_pickle=False)
        np.save(array_path, np.pad(
            source, ((0, 0), (0, len(expanded) - source.shape[1]))
        ))
    manifest_path = native / "collection_manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["vocabulary"] = {
        "sha256": expanded_hash, "size": len(expanded),
    }
    manifest_path.write_text(json.dumps(manifest))

    output = tmp_path / "dataset"
    monkeypatch.setattr(sys, "argv", [
        "build_phase_dataset.py", *(str(path) for path in phases),
        "--output", str(output), "--minimum-events", "100",
        "--minimum-phase-windows", "20", "--vocab", str(vocab_path),
    ])
    assert phase_dataset.main() == 0
    result = json.loads((output / "phase_dataset_manifest.json").read_text())
    for target in phase_dataset.TARGETS:
        modes = [row["vocabulary_mode"] for row in result["targets"][target]["phases"]]
        assert modes == [
            "source-zero-pad", "source-zero-pad", "source-zero-pad",
            "expanded-native",
        ]


def test_phase_builder_rejects_lossy_padding_for_observed_new_syscall(
        tmp_path, monkeypatch):
    phase = tmp_path / "normal"
    make_phase(phase, "normal", extra_syscall="ptrace")
    vocab_path = tmp_path / "vocab.pkl"
    with vocab_path.open("wb") as handle:
        pickle.dump({
            "read": 0, "write": 1, "read|read": 2, "write|write": 3,
        }, handle)
    monkeypatch.setattr(sys, "argv", [
        "build_phase_dataset.py", str(phase),
        "--output", str(tmp_path / "dataset"),
        "--minimum-phase-windows", "20", "--vocab", str(vocab_path),
    ])
    with pytest.raises(ValueError, match="recollect with the expanded vocabulary"):
        phase_dataset.main()
