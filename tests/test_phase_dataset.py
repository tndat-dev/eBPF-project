import importlib.util
import hashlib
import json
import pickle
import sys
from pathlib import Path

import pytest

np = pytest.importorskip("numpy")


MODULE_PATH = Path(__file__).resolve().parents[1] / "ml-service" / "build_phase_dataset.py"
spec = importlib.util.spec_from_file_location("build_phase_dataset", MODULE_PATH)
phase_dataset = importlib.util.module_from_spec(spec)
spec.loader.exec_module(phase_dataset)


def make_phase(path, phase_name, backpressure=0, extra_syscall=None):
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
        "sensor_health": {"backpressure_events": backpressure},
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
    for target in phase_dataset.TARGETS:
        item = manifest["targets"][target]
        assert item["shape"] == [100, 4]
        assert item["train_count"] == 80
        assert item["validation_count"] == 20


def test_phase_builder_rejects_sensor_backpressure(tmp_path, monkeypatch):
    phase = tmp_path / "bad"
    make_phase(phase, "bad", backpressure=1)
    monkeypatch.setattr(sys, "argv", [
        "build_phase_dataset.py", str(phase),
        "--output", str(tmp_path / "output"),
    ])
    with pytest.raises(ValueError, match="sensor backpressure"):
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
