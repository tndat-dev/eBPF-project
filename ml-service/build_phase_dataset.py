"""Build a train/holdout dataset from row-aligned real phase captures."""

import argparse
import hashlib
import json
import os
import pickle
import shutil
from datetime import datetime, timezone
from pathlib import Path

import numpy as np


TARGETS = ("default/postgres", "production/nginx", "production/redis")
POLICY_SYSCALLS = (
    "accept", "capset", "clone", "close", "connect", "execve", "mount",
    "openat", "ptrace", "read", "setgid", "setuid", "unshare", "write",
)


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_bytes(payload):
    return hashlib.sha256(payload).hexdigest()


def read_jsonl(path):
    return [json.loads(line) for line in path.read_text().splitlines() if line]


def expand_vocabulary(vocab, required_syscalls):
    """Append policy features without changing any existing feature index."""
    indexes = sorted(vocab.values())
    if indexes != list(range(len(vocab))):
        raise ValueError("vocabulary indexes must be unique and contiguous")
    expanded = dict(vocab)
    existing_unigrams = {key for key in expanded if "|" not in key}
    all_unigrams = sorted(existing_unigrams | set(required_syscalls))
    for name in sorted(set(required_syscalls) - existing_unigrams):
        expanded[name] = len(expanded)
    for first in all_unigrams:
        for second in all_unigrams:
            key = f"{first}|{second}"
            if key not in expanded:
                expanded[key] = len(expanded)
    return expanded


def allocate_validation(counts, fraction):
    total_target = max(3, int(round(sum(counts) * fraction)))
    raw = [count * fraction for count in counts]
    allocated = [min(count - 1, max(1, int(value))) for count, value in zip(counts, raw)]
    while sum(allocated) != total_target:
        increase = sum(allocated) < total_target
        choices = [
            index for index, count in enumerate(counts)
            if (increase and allocated[index] < count - 1)
            or (not increase and allocated[index] > 1)
        ]
        if not choices:
            raise ValueError("cannot allocate requested phase-stratified holdout")
        if increase:
            index = max(choices, key=lambda i: raw[i] - allocated[i])
            allocated[index] += 1
        else:
            index = min(choices, key=lambda i: raw[i] - allocated[i])
            allocated[index] -= 1
    return allocated


def evenly_spaced_validation(count, validation_count):
    selected = sorted(set(
        int(index) for index in np.linspace(0, count - 1, validation_count)
    ))
    if len(selected) != validation_count:
        raise ValueError("duplicate deterministic validation indexes")
    selected_set = set(selected)
    train = [index for index in range(count) if index not in selected_set]
    return train, selected


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("phases", nargs="+")
    parser.add_argument("--output", required=True)
    parser.add_argument("--minimum-events", type=int, default=100)
    parser.add_argument("--minimum-phase-windows", type=int, default=20)
    parser.add_argument("--validation-fraction", type=float, default=0.20)
    parser.add_argument("--policy", default=None)
    parser.add_argument("--vocab", default=None,
                        help="Input vocabulary; an index-preserving expanded copy is emitted")
    args = parser.parse_args()

    phases = [Path(item).resolve() for item in args.phases]
    output = Path(args.output).resolve()
    if args.minimum_events < 1 or args.minimum_phase_windows < 2:
        raise ValueError("minimum event/window constraints must be positive")
    if not 0.05 <= args.validation_fraction <= 0.40:
        raise ValueError("validation fraction outside [0.05, 0.40]")
    if output.exists():
        raise FileExistsError(output)
    staging = output.with_name(f".{output.name}.staging-{os.getpid()}")
    staging.mkdir(parents=True)
    source_vocab = expanded_vocab = None
    source_vocab_digest = expanded_vocab_digest = None
    expanded_vocab_payload = None
    if args.vocab:
        vocab_path = Path(args.vocab).resolve()
        with vocab_path.open("rb") as handle:
            source_vocab = pickle.load(handle)
        expanded_vocab = expand_vocabulary(source_vocab, POLICY_SYSCALLS)
        source_vocab_digest = sha256(vocab_path)
        # Use the default pickle protocol deliberately: this is the same
        # serialization used by the existing release vocabulary, so a live
        # capture can prove it used this exact expanded mapping by SHA-256.
        expanded_vocab_payload = pickle.dumps(expanded_vocab)
        expanded_vocab_digest = sha256_bytes(expanded_vocab_payload)
    manifest = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "builder": {
            "path": str(Path(__file__).resolve()),
            "sha256": sha256(Path(__file__).resolve()),
        },
        "minimum_events": args.minimum_events,
        "minimum_phase_windows": args.minimum_phase_windows,
        "validation_fraction": args.validation_fraction,
        "phase_order": [str(path) for path in phases],
        "source_manifests": [],
        "policy": None,
        "vocabulary": None,
        "targets": {},
    }
    if args.policy:
        policy = Path(args.policy).resolve()
        manifest["policy"] = {"path": str(policy), "sha256": sha256(policy)}
    if args.vocab:
        manifest["vocabulary"] = {
            "source_path": str(vocab_path),
            "source_sha256": source_vocab_digest,
            "source_size": len(source_vocab),
            "expanded_size": len(expanded_vocab),
            "output": "vocab.pkl",
            "output_sha256": expanded_vocab_digest,
            "required_policy_syscalls": list(POLICY_SYSCALLS),
            "added_unigrams": sorted(
                set(POLICY_SYSCALLS)
                - {key for key in source_vocab if "|" not in key}
            ),
            "index_preserving": True,
        }
        # Materialize the mapping once. Its hash is then used both for capture
        # provenance checks and for the final immutable dataset manifest.
        (staging / "vocab.pkl").write_bytes(expanded_vocab_payload)

    validated_manifests = {}
    # Reject incomplete or backpressured captures before touching any arrays.
    # A model must never silently train on a phase whose sensor was unhealthy.
    for phase in phases:
        source_manifest_path = phase / "collection_manifest.json"
        source_manifest = json.loads(source_manifest_path.read_text())
        validated_manifests[phase] = source_manifest
        health = source_manifest.get("sensor_health", {})
        if health.get("backpressure_events", 0):
            raise ValueError(f"sensor backpressure in phase {phase}: {health}")
        missing = set(TARGETS) - set(source_manifest.get("targets", {}))
        if missing:
            raise ValueError(f"phase {phase} missing targets: {sorted(missing)}")
        source_vocabulary = source_manifest.get("vocabulary")
        if source_vocabulary and args.vocab:
            capture_digest = source_vocabulary.get("sha256")
            capture_size = source_vocabulary.get("size")
            allowed = {
                (source_vocab_digest, len(source_vocab)),
                (expanded_vocab_digest, len(expanded_vocab)),
            }
            if (capture_digest, capture_size) not in allowed:
                raise ValueError(
                    f"phase {phase} was captured with a different vocabulary: "
                    f"sha256={capture_digest}, size={capture_size}"
                )
        manifest["source_manifests"].append({
            "path": str(source_manifest_path),
            "sha256": sha256(source_manifest_path),
            "phase": source_manifest.get("phase"),
            "sensor_health": health,
            "vocabulary": source_vocabulary,
            "experiment_artifacts": source_manifest.get(
                "experiment_artifacts", {}
            ),
        })

    try:
        for pod_key in TARGETS:
            stem = pod_key.replace("/", "__")
            accepted_arrays, phase_rows = [], []
            for phase in phases:
                array_path = phase / f"{stem}.npy"
                metadata_path = phase / f"{stem}_metadata.jsonl"
                array = np.load(array_path, allow_pickle=False)
                metadata = read_jsonl(metadata_path)
                vocabulary_mode = None
                if source_vocab is not None:
                    if array.shape[1] == len(source_vocab):
                        vocabulary_mode = "source-zero-pad"
                    elif array.shape[1] == len(expanded_vocab):
                        vocabulary_mode = "expanded-native"
                    else:
                        raise ValueError(
                            f"feature/vocabulary mismatch: {phase} {pod_key} "
                            f"has {array.shape[1]}, expected "
                            f"{len(source_vocab)} or {len(expanded_vocab)}"
                        )
                    declared = validated_manifests[phase].get("vocabulary") or {}
                    if declared.get("size") not in (None, array.shape[1]):
                        raise ValueError(
                            f"manifest/array vocabulary size mismatch: "
                            f"{phase} {pod_key}"
                        )
                if len(array) != len(metadata):
                    raise ValueError(f"row metadata mismatch: {phase} {pod_key}")
                accepted = [
                    index for index, row in enumerate(metadata)
                    if int(row["event_count"]) >= args.minimum_events
                ]
                if len(accepted) < args.minimum_phase_windows:
                    raise ValueError(
                        f"{pod_key}: phase {phase} has {len(accepted)} windows "
                        f"with >= {args.minimum_events} events; need "
                        f"{args.minimum_phase_windows}"
                    )
                added_event_totals = {}
                if source_vocab is not None:
                    added_unigrams = manifest["vocabulary"]["added_unigrams"]
                    added_event_totals = {
                        name: sum(
                            int(metadata[index].get("syscall_counts", {}).get(name, 0))
                            for index in accepted
                        )
                        for name in added_unigrams
                    }
                    if (
                        vocabulary_mode == "source-zero-pad"
                        and any(added_event_totals.values())
                    ):
                        # Unigram counts are available, but their sequence
                        # positions are not, so the corresponding bigrams
                        # cannot be reconstructed faithfully. Require a fresh
                        # capture instead of silently creating biased rows.
                        raise ValueError(
                            f"{pod_key}: phase {phase} contains events for "
                            f"new vocabulary features {added_event_totals}; "
                            "recollect with the expanded vocabulary"
                        )
                selected = array[accepted].astype(np.float32, copy=False)
                if (
                    expanded_vocab is not None
                    and vocabulary_mode == "source-zero-pad"
                    and len(expanded_vocab) > len(source_vocab)
                ):
                    selected = np.pad(
                        selected,
                        ((0, 0), (0, len(expanded_vocab) - len(source_vocab))),
                        mode="constant",
                    )
                accepted_arrays.append(selected)
                event_counts = [int(metadata[index]["event_count"]) for index in accepted]
                phase_rows.append({
                    "phase": str(phase),
                    "captured": len(array),
                    "accepted": len(accepted),
                    "source_indexes": accepted,
                    "event_count_min": min(event_counts),
                    "event_count_median": float(np.median(event_counts)),
                    "event_count_max": max(event_counts),
                    "source_feature_dim": int(array.shape[1]),
                    "vocabulary_mode": vocabulary_mode,
                    "zero_padded_event_totals": added_event_totals,
                    "array_sha256": sha256(array_path),
                    "metadata_sha256": sha256(metadata_path),
                })
            counts = [len(array) for array in accepted_arrays]
            if sum(counts) < 30:
                raise ValueError(f"{pod_key}: only {sum(counts)} qualifying windows")
            validation_counts = allocate_validation(
                counts, args.validation_fraction
            )
            train_parts, validation_parts = [], []
            for active_row, row in enumerate(phase_rows):
                array = accepted_arrays[active_row]
                train, validation = evenly_spaced_validation(
                    len(array), validation_counts[active_row]
                )
                train_parts.append(array[train])
                validation_parts.append(array[validation])
                row["train_indexes_after_filter"] = train
                row["validation_indexes_after_filter"] = validation
            dataset = np.concatenate(train_parts + validation_parts).astype(
                np.float32, copy=False
            )
            path = staging / f"{stem}.npy"
            np.save(path, dataset)
            manifest["targets"][pod_key] = {
                "shape": list(dataset.shape),
                "train_count": int(sum(len(part) for part in train_parts)),
                "validation_count": int(sum(len(part) for part in validation_parts)),
                "phases": phase_rows,
                "sha256": sha256(path),
            }
        if expanded_vocab is not None:
            vocab_output = staging / "vocab.pkl"
            if sha256(vocab_output) != expanded_vocab_digest:
                raise RuntimeError("expanded vocabulary changed during build")
        (staging / "phase_dataset_manifest.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n"
        )
        os.replace(staging, output)
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
