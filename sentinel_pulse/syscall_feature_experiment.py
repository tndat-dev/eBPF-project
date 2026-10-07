"""Isolated normal-only syscall channel experiments, never a live deployment.

Retrains a full reference, 29 leave-one-explicit-syscall-out variants, an
aggregate-only reference, and a training-frequency proxy selection. Existing
hash bins, aggregates and policy evidence are not removed from live Pulse.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import gc
import hashlib
import json
from pathlib import Path
import pickle
import platform
import resource
import shutil
import signal
import time

import numpy as np

from .features import PulseFeatureBuilder, SENSITIVE_IDS, TRACKED_SYSCALLS
from .integrity import sha256_file, verify_sha256
from .model import PulseExtraTrees
from .observation_campaign import atomic_json
from .syscall_analysis import pvalues
from .train import load_dataset_manifest, load_sequences, source_git_provenance


CHANNELS = ("log_count", "ratio", "rolling_mean", "rolling_std")
TRAIN_FRACTION = 0.7


def explicit_channels(columns):
    if len(columns) != len(set(columns)):
        raise ValueError("duplicate feature columns")
    lookup = {name: index for index, name in enumerate(columns)}
    try:
        return {
            name: [lookup[f"{prefix}:{name}"] for prefix in CHANNELS]
            for name in TRACKED_SYSCALLS.values()
        }
    except KeyError as exc:
        raise ValueError("missing explicit syscall channel") from exc


def training_frequency_proxy(sequences, columns, history):
    """Rank only the training prefix; expm1(float32 log_count) is approximate.

    This is not a newly collected exact full-ID histogram. Calibration and
    independent held-out contexts cannot influence which channels are retained.
    """
    indices = explicit_channels(columns)
    totals = {name: 0.0 for name in indices}
    for sequence in sequences:
        if len(sequence) <= history * 2 + 2:
            continue
        split = int(len(sequence) * TRAIN_FRACTION)
        if split <= history or len(sequence) - split <= history:
            continue
        for name, slots in indices.items():
            counts = np.expm1(sequence[:split, slots[0]].astype(np.float64))
            if not np.isfinite(counts).all() or (counts < 0).any():
                raise ValueError("invalid training count proxy")
            totals[name] += float(counts.sum())
    return totals


def variant_masks(columns, proxy):
    by_name = explicit_channels(columns)
    if set(proxy) != set(by_name) or any(not np.isfinite(v) or v < 0 for v in proxy.values()):
        raise ValueError("invalid training-only ranking")
    variants = {"full": []}
    variants.update({f"drop_{name}": slots for name, slots in by_name.items()})
    variants["no_explicit_channels"] = sorted(slot for slots in by_name.values() for slot in slots)
    ranking = sorted(proxy, key=lambda name: (-proxy[name], name))
    kept = set(ranking[:16]) | {TRACKED_SYSCALLS[number] for number in SENSITIVE_IDS}
    variants["top16_plus_sensitive"] = sorted(
        slot for name, slots in by_name.items() if name not in kept for slot in slots
    )
    return variants, ranking, sorted(kept)


def masked_contexts(contexts, indices, feature_dim, history):
    contexts = np.asarray(contexts, dtype=np.float32)
    if contexts.ndim != 2 or contexts.shape[1] != feature_dim * (history + 1):
        raise ValueError("invalid held-out temporal shape")
    if not len(contexts) or not np.isfinite(contexts).all():
        raise ValueError("invalid held-out contexts")
    if any(type(i) is not int or i < 0 or i >= feature_dim for i in indices):
        raise ValueError("invalid mask slot")
    masked = contexts.copy()
    expanded = [slot + lag * feature_dim for lag in range(history + 1) for slot in indices]
    masked[:, expanded] = 0
    return masked


def verify_inputs(root):
    manifest_path = root / "manifest.json"
    checksum = (root / "manifest.sha256").read_text().split()
    if len(checksum) != 2 or checksum[1] != "manifest.json":
        raise ValueError("invalid detached manifest checksum")
    verify_sha256(manifest_path, checksum[0])
    manifest = json.loads(manifest_path.read_text())
    if manifest.get("schema") != "sentinel-pulse-model-manifest-v2":
        raise ValueError("invalid reference manifest")
    if manifest.get("capture_validation", {}).get("valid") is not True:
        raise ValueError("reference capture was not validated")
    analysis = json.loads((root / "analysis.json").read_text())
    if analysis.get("schema") != "sentinel-pulse-syscall-analysis-v1":
        raise ValueError("invalid analysis evidence")
    if analysis.get("independent_capture_hash_and_post_training_time") is not True:
        raise ValueError("independent held-out capture required")
    if analysis.get("model_manifest_sha256") != checksum[0]:
        raise ValueError("held-out model binding mismatch")
    if analysis.get("capture_sha256") == manifest.get("dataset_sha256"):
        raise ValueError("training/holdout overlap")
    dataset_manifest_path, provenance = load_dataset_manifest(root / "features.jsonl")
    verify_sha256(dataset_manifest_path, manifest["dataset_manifest_sha256"])
    verify_sha256(root / "features.jsonl", manifest["dataset_sha256"])
    verify_sha256(root / "contexts.npz", analysis["context_archive"]["sha256"])
    verify_sha256(root / "training-contract.json", manifest["training_contract_sha256"])
    if analysis["training_provenance_sha256"] != manifest["dataset_manifest_sha256"]:
        raise ValueError("held-out training provenance mismatch")
    if set(analysis["workloads"]) - set(manifest["workloads"]):
        raise ValueError("unapproved held-out workload")
    with np.load(root / "contexts.npz", allow_pickle=False) as archive:
        if set(archive.files) != set(analysis["workloads"]):
            raise ValueError("context workload coverage mismatch")
        for key in archive.files:
            context = masked_contexts(archive[key], [], len(manifest["feature_columns"]), manifest["history_windows"])
            if len(context) != analysis["workloads"][key]["normal_contexts"]:
                raise ValueError("context count mismatch")
    return manifest, analysis, provenance


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def validate_proxy_roundoff(old, current, columns):
    """Allow only float64 reduction roundoff, never a changed selection.

    The hash-bound float32 inputs are identical. SIMD/reduction implementations
    can differ by an ULP when accumulating expm1 counts across CPUs.
    """
    old_masks, old_rank, old_kept = variant_masks(columns, old)
    masks, rank, kept = variant_masks(columns, current)
    if (old_masks, old_rank, old_kept) != (masks, rank, kept):
        raise ValueError("checkpoint syscall ranking/masks changed")
    differences = []
    for name, value in current.items():
        previous = old[name]
        difference = abs(value - previous)
        bound = 8 * max(np.spacing(abs(value)), np.spacing(abs(previous)))
        if (value == 0 or previous == 0) and value != previous:
            raise ValueError("checkpoint zero count changed")
        if difference > bound:
            raise ValueError("checkpoint training counts changed beyond 8 float64 ULPs")
        if difference:
            differences.append({"syscall": name, "previous": previous, "current": value,
                                "absolute_difference": difference, "maximum_allowed_difference": float(bound)})
    return differences


def load_checkpoint(parent, start):
    """Read a stopped attempt; never rewrite its START/results/terminal.

    No ML transformation may change across attempts. The orchestration module
    may change to add recovery; the exact prior source remains in the receipt.
    """
    prior = json.loads((parent / "START.json").read_text())
    if prior.get("schema") != "sentinel-pulse-explicit-syscall-experiment-start-v1":
        raise ValueError("checkpoint START schema mismatch")
    for key in ("input_sha256", "software", "training_fraction", "history", "alpha",
                "window_seconds", "workloads", "expected_fits", "variants_per_workload"):
        if prior.get(key) != start.get(key):
            raise ValueError("checkpoint binding mismatch: " + key)
    for name in ("model.py", "features.py", "train.py", "encoding.py"):
        if prior["source_module_sha256"].get(name) != start["source_module_sha256"].get(name):
            raise ValueError("checkpoint ML source mismatch: " + name)
    result_path = parent / "RESULTS.json"
    results = json.loads(result_path.read_text()) if result_path.exists() else {"workloads": {}}
    if result_path.exists() and results.get("schema") != "sentinel-pulse-explicit-syscall-experiment-results-v1":
        raise ValueError("checkpoint results schema mismatch")
    parent_start_hash = sha256_file(parent / "START.json")
    if result_path.exists() and results.get("start_sha256") != parent_start_hash:
        raise ValueError("checkpoint results START mismatch")
    carried = {}
    for key, result in results["workloads"].items():
        if key not in start["workloads"]:
            raise ValueError("checkpoint unexpected workload")
        variants, ranking, retained = variant_masks(list(PulseFeatureBuilder().columns), result["training_count_proxy"])
        if result["training_rank"] != ranking or result["top16_plus_sensitive_retained_syscalls"] != retained:
            raise ValueError("checkpoint ranking mismatch")
        kept = {}
        for variant, record in result["variants"].items():
            if variant not in variants or record.get("status") not in ("measured", "error"):
                raise ValueError("checkpoint unexpected variant/status")
            if record["status"] == "error":
                continue  # old error stays in the parent; retry in the child
            expected_columns = [list(PulseFeatureBuilder().columns)[i] for i in variants[variant]]
            if record["masked_columns"] != expected_columns:
                raise ValueError("checkpoint mask mismatch")
            filename = record["prediction_artifact"]
            expected_name = hashlib.sha256(key.encode()).hexdigest()[:16] + "__" + variant + ".npz"
            if filename != expected_name:
                raise ValueError("checkpoint prediction path mismatch")
            artifact = parent / filename
            verify_sha256(artifact, record["prediction_sha256"])
            with np.load(artifact, allow_pickle=False) as prediction:
                score, p, anomalous = (prediction[n] for n in ("score", "conformal_p", "anomalous"))
                if (score.shape != (record["heldout_contexts"],) or p.shape != score.shape
                        or anomalous.shape != score.shape or anomalous.dtype != np.dtype(bool)
                        or not np.isfinite(score).all() or not np.isfinite(p).all()
                        or (p <= 0).any() or (p > 1).any()
                        or not np.array_equal(anomalous, p <= start["alpha"])
                        or int(anomalous.sum()) != record["raw_anomalous_contexts"]):
                    raise ValueError("checkpoint prediction content mismatch")
            kept[variant] = {**record,
                             "origin_start_sha256": record.get("origin_start_sha256", record.get("carried_from_start_sha256", parent_start_hash)),
                             "origin_source_commit": record.get("origin_source_commit", record.get("carried_from_source_commit", prior["source"]["source_git_commit"])),
                             "carried_from_start_sha256": parent_start_hash,
                             "carried_from_source_commit": prior["source"]["source_git_commit"]}
        carried[key] = {**result, "variants": kept}
    receipt = {"path": str(parent), "start_sha256": parent_start_hash,
               "results_sha256": sha256_file(result_path) if result_path.exists() else None,
               "terminal_sha256": sha256_file(parent / "TERMINAL.json") if (parent / "TERMINAL.json").exists() else None,
               "reused_fits": sum(len(v["variants"]) for v in carried.values()),
               "orchestration_source_may_differ": True,
               "timing_warning": "carried inference timings belong to the original host/quota; do not pool with new VM timings"}
    return carried, receipt


def run(inputs, output, resume_from=None):
    source = source_git_provenance(Path(__file__).resolve().parents[1])
    if not source["source_clean"]:
        raise ValueError("run experiments from a clean, frozen Git checkout")
    manifest, analysis, provenance = verify_inputs(inputs)
    software = {"python": platform.python_version(), "numpy": np.__version__}
    import sklearn
    import joblib
    software.update(scikit_learn=sklearn.__version__, joblib=joblib.__version__)
    start = {
        "schema": "sentinel-pulse-explicit-syscall-experiment-start-v1",
        "created_at": utc_now(), "source": source, "software": software,
        "execution_host": {"hostname": platform.node(), "machine": platform.machine(), "kernel": platform.release()},
        "reference_training_software": manifest["software"],
        "input_sha256": {name: sha256_file(inputs / name) for name in (
            "manifest.json", "features.jsonl", "features.jsonl.manifest.json",
            "analysis.json", "contexts.npz", "training-contract.json",
        )},
        "source_module_sha256": {name: sha256_file(Path(__file__).parent / name) for name in (
            "syscall_feature_experiment.py", "model.py", "features.py", "train.py", "encoding.py",
        )},
        "reference_model_artifacts_loaded": False,
        "reference_binding": "manifest only; every classifier including full is retrained on this host",
        "training_fraction": TRAIN_FRACTION, "history": manifest["history_windows"],
        "alpha": manifest["alpha"], "window_seconds": manifest["window_seconds"],
        "variants_per_workload": 32,
        "workloads": sorted(analysis["workloads"]),
        "missing_holdout_workloads": sorted(set(manifest["workloads"]) - set(analysis["workloads"])),
        "expected_fits": len(analysis["workloads"]) * 32,
        "heldout_already_inspected": True,
        "evidence_class": "exploratory_independent_normal_only",
        "deploy_from_holdout_ranking": False, "automatic_promotion": False,
        "live_soak_modified": False, "collector_attached": False,
        "scope": "explicit channels only; bins/aggregates retained; policy and attack recall not evaluated",
        "top16_selection": "training-prefix expm1(log_count) approximation plus fixed sensitive whitelist; never calibration/holdout ranking",
        "host_resource_limits": "set externally by systemd; inference timing is host/quota-specific, not kernel-to-alert",
        "privacy": "no production payloads or credentials collected",
    }
    carried, receipt = load_checkpoint(resume_from, start) if resume_from else ({}, None)
    output.mkdir(parents=True, exist_ok=False)
    start["resume_from"] = receipt
    for result in carried.values():
        for record in result["variants"].values():
            destination = output / record["prediction_artifact"]
            shutil.copyfile(resume_from / record["prediction_artifact"], destination)
            verify_sha256(destination, record["prediction_sha256"])
    atomic_json(output / "START.json", start)
    status = {"state": "loading_training", "completed_fits": receipt["reused_fits"] if receipt else 0,
              "reused_fits": receipt["reused_fits"] if receipt else 0, "expected_fits": start["expected_fits"], "errors": []}
    atomic_json(output / "STATUS.json", status)
    results = {"schema": "sentinel-pulse-explicit-syscall-experiment-results-v1", "start_sha256": sha256_file(output / "START.json"),
               "evidence_class": start["evidence_class"], "automatic_promotion": False,
               "precision": None, "recall": None, "kernel_to_alert_seconds": None, "workloads": carried}
    atomic_json(output / "RESULTS.json", results)
    terminal = "interrupted"
    try:
        sequences, columns = load_sequences(inputs / "features.jsonl", manifest["max_contiguous_gap_seconds"])
        if columns != list(PulseFeatureBuilder().columns) or columns != manifest["feature_columns"]:
            raise ValueError("training schema differs from reference")
        with np.load(inputs / "contexts.npz", allow_pickle=False) as archive:
            for key in start["workloads"]:
                proxy = training_frequency_proxy(sequences[key], columns, manifest["history_windows"])
                variants, ranking, retained = variant_masks(columns, proxy)
                result = results["workloads"].get(key)
                if result is not None:
                    result["resume_training_proxy_roundoff"] = validate_proxy_roundoff(result["training_count_proxy"], proxy, columns)
                result = result or {"training_count_proxy": proxy, "training_rank": ranking,
                          "top16_plus_sensitive_retained_syscalls": retained, "variants": {}}
                results["workloads"][key] = result
                for variant, indices in variants.items():
                    if result["variants"].get(variant, {}).get("status") == "measured":
                        continue
                    status.update(state="fitting", workload=key, variant=variant, updated_at=utc_now())
                    atomic_json(output / "STATUS.json", status)
                    model = None
                    try:
                        rows = [sequence.copy() for sequence in sequences[key]]
                        for row in rows:
                            row[:, indices] = 0
                        model = PulseExtraTrees(history=manifest["history_windows"], alpha=manifest["alpha"])
                        fit = model.fit_sequences(rows, train_fraction=TRAIN_FRACTION)
                        del rows
                        x = masked_contexts(archive[key], indices, len(columns), model.history)
                        score = model.estimator.predict_proba(x)[:, 1]
                        conformal = pvalues(score, model.calibration_scores)
                        anomaly = conformal <= model.alpha
                        timings = []
                        # Two warmups; then deterministic evenly spaced contexts.
                        for index in [0, 0, *np.linspace(0, len(x) - 1, min(16, len(x)), dtype=int)]:
                            context = x[index].reshape(model.history + 1, len(columns))
                            decision = model.predict(context[:-1], context[-1])
                            timings.append(decision.inference_ms)
                        timings = timings[2:]
                        evidence_name = hashlib.sha256(key.encode()).hexdigest()[:16] + "__" + variant + ".npz"
                        prediction = output / evidence_name
                        np.savez_compressed(prediction, score=score, conformal_p=conformal, anomalous=anomaly)
                        result["variants"][variant] = {
                            "status": "measured", "masked_columns": [columns[i] for i in indices],
                            "heldout_contexts": len(x), "raw_anomalous_contexts": int(anomaly.sum()),
                            "raw_anomaly_fraction": float(anomaly.mean()),
                            "host_inference_ms": {"samples": len(timings), "p50": float(np.percentile(timings, 50)),
                                                  "p95": float(np.percentile(timings, 95)), "p99": float(np.percentile(timings, 99))},
                            "fit": fit, "serialized_estimator_bytes": len(pickle.dumps(model.estimator, protocol=5)),
                            "prediction_artifact": evidence_name, "prediction_sha256": sha256_file(prediction),
                            "policy_alerts": None, "TP": None, "FP": None, "TN": None, "FN": None,
                            "precision": None, "recall": None,
                        }
                    except (ValueError, RuntimeError) as exc:
                        error = {"workload": key, "variant": variant, "exception": type(exc).__name__, "message": str(exc)}
                        status["errors"].append(error)
                        result["variants"][variant] = {"status": "error", **error}
                    finally:
                        del model
                        gc.collect()
                    status["completed_fits"] += 1
                    status["process_peak_rss_mib_cumulative"] = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024
                    atomic_json(output / "RESULTS.json", results)
                    atomic_json(output / "STATUS.json", status)
                    print(json.dumps({"workload": key, "variant": variant, "completed": status["completed_fits"],
                                      "status": result["variants"][variant]["status"]}), flush=True)
        terminal = "completed_with_errors" if status["errors"] else "completed"
    except Exception as exc:
        terminal = "failed"
        status["errors"].append({"exception": type(exc).__name__, "message": str(exc)})
        raise
    finally:
        status.update(state=terminal, updated_at=utc_now())
        atomic_json(output / "STATUS.json", status)
        atomic_json(output / "TERMINAL.json", {"state": terminal, "ended_at": utc_now(),
                    "start_sha256": sha256_file(output / "START.json"), "completed_fits": status["completed_fits"],
                    "expected_fits": status["expected_fits"], "errors": status["errors"], "automatic_promotion": False})
    return status


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inputs", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--resume-from", type=Path)
    args = parser.parse_args()
    def stop(_signal, _frame):
        raise KeyboardInterrupt("experiment stopped; live soak is unaffected")
    signal.signal(signal.SIGTERM, stop)
    run(args.inputs.resolve(), args.output.resolve(), args.resume_from.resolve() if args.resume_from else None)


if __name__ == "__main__":
    main()
