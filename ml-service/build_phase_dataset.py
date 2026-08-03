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


DEFAULT_TARGETS = ("default/postgres", "production/nginx", "production/redis")
# Compatibility alias for existing artifact tests and downstream scripts. New
# candidate runs should pass their workload contract explicitly via --targets.
TARGETS = DEFAULT_TARGETS
POLICY_SYSCALLS = (
    "accept", "capset", "clone", "close", "connect", "execve", "mount",
    "openat", "ptrace", "read", "setgid", "setuid", "unshare", "write",
)
REQUIRED_SENSOR_HEALTH_FIELDS = {
    "backpressure_events", "membership_failures", "coverage_failures",
    "stream_failures", "require_full_coverage", "coverage_healthy",
}


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


def startup_grace_eligible(row, grace_seconds):
    """Validate explicit pod-age evidence and return its fail-closed mask bit."""
    declared = row.get("startup_grace_eligible", False)
    age = row.get("startup_age_seconds")
    created = row.get("pod_creation_timestamp")
    if age is None and created is None:
        if declared:
            raise ValueError("startup grace declared without pod-age evidence")
        return False
    pod_key = row.get("pod_key")
    if not isinstance(pod_key, str) or "/" not in pod_key:
        raise ValueError("startup provenance missing pod_key")
    if age is None or created is None:
        raise ValueError("partial startup provenance is not admissible")
    age = float(age)
    created = float(created)
    window_end = float(row["window_end"])
    if age < 0 or created <= 0 or abs(age - max(0.0, window_end - created)) > 0.01:
        raise ValueError("inconsistent startup-age provenance")
    computed = age < grace_seconds
    if not isinstance(declared, bool) or declared != computed:
        raise ValueError("startup grace declaration does not match pod age")
    return computed


def ensure_startup_stratification(train, validation, metadata_rows):
    """Place proven startup rows in both splits when the phase has enough."""
    flags = [bool(row["startup_grace_eligible"]) for row in metadata_rows]
    if sum(flags) < 2:
        return train, validation, False
    changed = False
    if not any(flags[index] for index in validation):
        incoming = next(index for index in train if flags[index])
        outgoing = next((index for index in validation if not flags[index]), None)
        if outgoing is None:
            raise ValueError("cannot preserve startup validation stratum")
        train = [index for index in train if index != incoming] + [outgoing]
        validation = [index for index in validation if index != outgoing] + [incoming]
        changed = True
    if not any(flags[index] for index in train):
        incoming = next(index for index in validation if flags[index])
        outgoing = next((index for index in train if not flags[index]), None)
        if outgoing is None:
            raise ValueError("cannot preserve startup training stratum")
        validation = [index for index in validation if index != incoming] + [outgoing]
        train = [index for index in train if index != outgoing] + [incoming]
        changed = True
    return sorted(train), sorted(validation), changed


def parse_targets(raw: str) -> tuple[str, ...]:
    """Validate the explicit workload contract for one candidate release."""
    targets = tuple(item.strip() for item in raw.split(",") if item.strip())
    if not targets or len(set(targets)) != len(targets):
        raise ValueError("--targets must contain one or more unique namespace/workload keys")
    if any("/" not in item for item in targets):
        raise ValueError("every --targets item must be namespace/workload")
    return targets


def phase_role_contract(contract: dict, role: str) -> tuple[list[str], set[int]]:
    """Return the exact ordered phase set allowed to enter one dataset role."""
    normal = contract.get("normal_protocol", {})
    regimes = normal.get("regimes")
    roles = normal.get("phase_roles", {})
    role_spec = roles.get(role)
    if not isinstance(regimes, list) or not regimes or not isinstance(role_spec, dict):
        raise ValueError(f"experiment contract has no valid phase role {role!r}")
    runs = role_spec.get("runs")
    if (
        not isinstance(runs, list) or not runs
        or any(not isinstance(run, int) or run < 1 for run in runs)
        or len(set(runs)) != len(runs)
    ):
        raise ValueError(f"experiment contract role {role!r} has invalid runs")
    total_runs = normal.get("independent_runs_per_regime")
    if not isinstance(total_runs, int) or total_runs < 1:
        raise ValueError("experiment contract has invalid independent run count")
    assigned: dict[int, str] = {}
    for candidate_role, candidate_spec in roles.items():
        candidate_runs = (
            candidate_spec.get("runs") if isinstance(candidate_spec, dict) else None
        )
        if not isinstance(candidate_runs, list) or not candidate_runs:
            raise ValueError(f"experiment contract role {candidate_role!r} has no runs")
        for run in candidate_runs:
            if not isinstance(run, int) or not 1 <= run <= total_runs:
                raise ValueError(
                    f"experiment contract role {candidate_role!r} has invalid run {run!r}"
                )
            if run in assigned:
                raise ValueError(
                    f"experiment run {run} belongs to both {assigned[run]!r} "
                    f"and {candidate_role!r}"
                )
            assigned[run] = candidate_role
    missing = sorted(set(range(1, total_runs + 1)) - set(assigned))
    if missing:
        raise ValueError(f"experiment contract leaves runs unassigned: {missing}")
    if normal.get("holdout_training_forbidden") is not True:
        raise ValueError("experiment contract must forbid holdout training")
    expected = [
        f"aims-{regime}-run-{run:02d}"
        for run in runs for regime in regimes
    ]
    return expected, set(runs)


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
    parser.add_argument("--targets", default=",".join(DEFAULT_TARGETS),
                        help="Comma-separated deployment keys included in this candidate")
    parser.add_argument("--startup-grace-seconds", type=float, default=60.0,
                        help="Runtime startup grace reproduced by the offline gate")
    parser.add_argument("--experiment-contract", default=None,
                        help="Frozen release contract defining run-level data roles")
    parser.add_argument("--dataset-role", default=None,
                        help="Role from normal_protocol.phase_roles")
    parser.add_argument("--parent-release-contract", default=None,
                        help="Parent collection contract bound by the split contract")
    args = parser.parse_args()
    targets = parse_targets(args.targets)

    phases = [Path(item).resolve() for item in args.phases]
    output = Path(args.output).resolve()
    experiment_contract = None
    experiment_contract_path = None
    parent_release_contract_path = None
    expected_role_phases = None
    if bool(args.experiment_contract) != bool(args.dataset_role):
        raise ValueError(
            "--experiment-contract and --dataset-role must be supplied together"
        )
    if args.experiment_contract:
        experiment_contract_path = Path(args.experiment_contract).resolve()
        experiment_contract = json.loads(experiment_contract_path.read_text())
        expected_role_phases, _ = phase_role_contract(
            experiment_contract, args.dataset_role
        )
        expected_parent_digest = experiment_contract.get(
            "parent_release_contract_sha256"
        )
        if expected_parent_digest:
            if not args.parent_release_contract:
                raise ValueError("split contract requires --parent-release-contract")
            parent_release_contract_path = Path(
                args.parent_release_contract
            ).resolve()
            observed_parent_digest = sha256(parent_release_contract_path)
            if observed_parent_digest != expected_parent_digest:
                raise ValueError(
                    "parent release contract digest does not match split contract"
                )
    if args.minimum_events < 1 or args.minimum_phase_windows < 2:
        raise ValueError("minimum event/window constraints must be positive")
    if not 0.05 <= args.validation_fraction <= 0.40:
        raise ValueError("validation fraction outside [0.05, 0.40]")
    if args.startup_grace_seconds < 0:
        raise ValueError("startup grace must be non-negative")
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
        "target_order": list(targets),
        "window_seconds": None,
        "startup_grace_seconds": args.startup_grace_seconds,
        "dataset_role": args.dataset_role,
        "split_semantics": (
            "development_calibration_not_independent_evaluation"
            if args.dataset_role == "candidate_fit" else args.dataset_role
        ),
        "experiment_contract": (
            {
                "path": str(experiment_contract_path),
                "sha256": sha256(experiment_contract_path),
                "contract_version": experiment_contract.get("contract_version"),
                "release_track": experiment_contract.get("release_track"),
                "holdout_training_forbidden": experiment_contract.get(
                    "normal_protocol", {}
                ).get("holdout_training_forbidden"),
                "parent_release_contract": (
                    str(parent_release_contract_path)
                    if parent_release_contract_path else None
                ),
                "parent_release_contract_sha256": (
                    sha256(parent_release_contract_path)
                    if parent_release_contract_path else None
                ),
            }
            if experiment_contract is not None else None
        ),
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
    capture_windows = set()
    # Reject incomplete or backpressured captures before touching any arrays.
    # A model must never silently train on a phase whose sensor was unhealthy.
    for phase in phases:
        source_manifest_path = phase / "collection_manifest.json"
        source_manifest = json.loads(source_manifest_path.read_text())
        validated_manifests[phase] = source_manifest
        window_seconds = source_manifest.get("window_seconds")
        if not isinstance(window_seconds, int) or window_seconds < 5:
            raise ValueError(
                f"phase {phase} has invalid feature window: {window_seconds!r}"
            )
        capture_windows.add(window_seconds)
        source_startup = source_manifest.get("startup_provenance")
        if source_startup is not None:
            source_grace = source_startup.get("startup_grace_seconds")
            if float(source_grace) != args.startup_grace_seconds:
                raise ValueError(
                    f"phase {phase} startup grace {source_grace!r} does not "
                    f"match dataset contract {args.startup_grace_seconds}"
                )
        health = source_manifest.get("sensor_health", {})
        missing_health = REQUIRED_SENSOR_HEALTH_FIELDS - set(health)
        if missing_health:
            raise ValueError(
                f"sensor health schema incomplete in phase {phase}: "
                f"{sorted(missing_health)}"
            )
        if health.get("backpressure_events", 0):
            raise ValueError(f"sensor backpressure in phase {phase}: {health}")
        if (
            health.get("membership_failures", 0)
            or health.get("coverage_failures", 0)
            or health.get("stream_failures", 0)
        ):
            raise ValueError(
                f"sensor continuity failure in phase {phase}: {health}"
            )
        if (
            health.get("require_full_coverage")
            and not health.get("coverage_healthy")
        ):
            raise ValueError(
                f"sensor coverage unhealthy in phase {phase}: {health}"
            )
        missing = set(targets) - set(source_manifest.get("targets", {}))
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
            "window_seconds": window_seconds,
            "sensor_health": health,
            "vocabulary": source_vocabulary,
            "experiment_artifacts": source_manifest.get(
                "experiment_artifacts", {}
            ),
            "startup_provenance": source_startup,
        })

    if expected_role_phases is not None:
        observed = [
            str(validated_manifests[phase].get("phase")) for phase in phases
        ]
        if observed != expected_role_phases:
            raise ValueError(
                f"dataset role {args.dataset_role!r} requires exact ordered phases "
                f"{expected_role_phases}, observed {observed}; refusing possible "
                "train/holdout leakage"
            )

    if len(capture_windows) != 1:
        raise ValueError(
            f"phase captures use inconsistent feature windows: {sorted(capture_windows)}"
        )
    manifest["window_seconds"] = capture_windows.pop()

    try:
        for pod_key in targets:
            stem = pod_key.replace("/", "__")
            accepted_arrays, accepted_metadata, phase_rows = [], [], []
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
                selected_metadata = []
                for filtered_index, source_index in enumerate(accepted):
                    item = dict(metadata[source_index])
                    item["source_index"] = source_index
                    item["filtered_index"] = filtered_index
                    item["startup_grace_eligible"] = startup_grace_eligible(
                        item, args.startup_grace_seconds
                    )
                    selected_metadata.append(item)
                accepted_metadata.append(selected_metadata)
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
            train_startup_mask, validation_startup_mask = [], []
            validation_event_counts = []
            validation_startup_rows = []
            for active_row, row in enumerate(phase_rows):
                array = accepted_arrays[active_row]
                metadata_rows = accepted_metadata[active_row]
                train, validation = evenly_spaced_validation(
                    len(array), validation_counts[active_row]
                )
                train, validation, startup_stratified = ensure_startup_stratification(
                    train, validation, metadata_rows
                )
                train_parts.append(array[train])
                validation_parts.append(array[validation])
                train_startup_mask.extend(
                    bool(metadata_rows[index]["startup_grace_eligible"])
                    for index in train
                )
                for index in validation:
                    item = metadata_rows[index]
                    validation_event_counts.append(int(item["event_count"]))
                    eligible = bool(item["startup_grace_eligible"])
                    validation_startup_mask.append(eligible)
                    if eligible:
                        validation_startup_rows.append({
                            "phase": row["phase"],
                            "source_index": item["source_index"],
                            "filtered_index": index,
                            "pod_key": item["pod_key"],
                            "pod_creation_timestamp": item["pod_creation_timestamp"],
                            "startup_age_seconds": item["startup_age_seconds"],
                        })
                row["train_indexes_after_filter"] = train
                row["validation_indexes_after_filter"] = validation
                row["startup_stratified"] = startup_stratified
            dataset = np.concatenate(train_parts + validation_parts).astype(
                np.float32, copy=False
            )
            path = staging / f"{stem}.npy"
            np.save(path, dataset)
            manifest["targets"][pod_key] = {
                "shape": list(dataset.shape),
                "train_count": int(sum(len(part) for part in train_parts)),
                "validation_count": int(sum(len(part) for part in validation_parts)),
                "validation_event_counts": validation_event_counts,
                "startup_grace": {
                    "seconds": args.startup_grace_seconds,
                    "fail_closed": True,
                    "train_mask": train_startup_mask,
                    "validation_mask": validation_startup_mask,
                    "train_count": int(sum(train_startup_mask)),
                    "validation_count": int(sum(validation_startup_mask)),
                    "validation_rows": validation_startup_rows,
                },
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
