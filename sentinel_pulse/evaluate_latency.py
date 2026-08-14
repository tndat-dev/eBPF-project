"""Summarize true injection-to-alert latency and fail the preregistered gate."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np

from .integrity import sha256_file


def injection_ids(path: Path) -> set[str]:
    result = set()
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            record = json.loads(line)
            if record.get("schema") != "sentinel-pulse-injection-v1":
                continue
            injection_id = str(record["injection_id"])
            if injection_id in result:
                raise ValueError(f"duplicate injection ID at line {line_number}: {injection_id}")
            result.add(injection_id)
    if not result:
        raise ValueError("injection marker file has no valid ID")
    return result


def evaluate(
    path: Path,
    expected_injections: int | None = None,
    injection_path: Path | None = None,
) -> dict:
    by_injection = {}
    processing = []
    inference = []
    model_identities = set()
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            record = json.loads(line)
            if record.get("schema") != "sentinel-pulse-decision-v1":
                continue
            model_identities.add(str(record.get("model_manifest_sha256", "")))
            if "post_window_processing_seconds" in record:
                processing.append(float(record["post_window_processing_seconds"]))
            if "inference_ms" in record:
                inference.append(float(record["inference_ms"]))
            if "injection_id" in record and "true_detection_latency_seconds" in record:
                by_injection.setdefault(
                    str(record["injection_id"]), float(record["true_detection_latency_seconds"])
                )

    def summary(values):
        if not values:
            return {}
        return {
            "min": float(np.min(values)),
            "p50": float(np.quantile(values, 0.50)),
            "p95": float(np.quantile(values, 0.95)),
            "p99": float(np.quantile(values, 0.99)),
            "max": float(np.max(values)),
        }

    expected_ids = injection_ids(injection_path) if injection_path is not None else None
    if expected_ids is not None and expected_injections is not None and len(expected_ids) != expected_injections:
        raise ValueError("expected injection count does not match immutable marker set")
    observed_ids = set(by_injection)
    unknown_ids = sorted(observed_ids - expected_ids) if expected_ids is not None else []
    valid_ids = observed_ids & expected_ids if expected_ids is not None else observed_ids
    missing_ids = sorted(expected_ids - observed_ids) if expected_ids is not None else []
    true_latency = [by_injection[injection_id] for injection_id in sorted(valid_ids)]
    detected = len(valid_ids)
    expected = (
        len(expected_ids)
        if expected_ids is not None
        else detected if expected_injections is None else expected_injections
    )
    model_identity_gate = (
        len(model_identities) == 1
        and len(next(iter(model_identities))) == 64
        and all(character in "0123456789abcdef" for character in next(iter(model_identities)))
    )
    report = {
        "schema": "sentinel-pulse-latency-report-v1",
        "decisions_sha256": sha256_file(path),
        "injections_sha256": sha256_file(injection_path) if injection_path is not None else None,
        "expected_injections": expected,
        "detected_injections": detected,
        "missing_injection_ids": missing_ids,
        "unknown_detection_ids": unknown_ids,
        "injection_identity_gate": not unknown_ids,
        "model_manifest_sha256": (
            next(iter(model_identities)) if model_identity_gate else None
        ),
        "model_identity_gate": model_identity_gate,
        "recall": detected / expected if expected else 0.0,
        "true_detection_latency_seconds": summary(true_latency),
        "post_window_processing_seconds": summary(processing),
        "inference_ms": summary(inference),
    }
    p99 = report["true_detection_latency_seconds"].get("p99")
    report["latency_gate_p99_le_2s"] = p99 is not None and p99 <= 2.0
    report["blind_evidence_valid"] = (
        report["injection_identity_gate"]
        and report["model_identity_gate"]
        and report["latency_gate_p99_le_2s"]
    )
    return report


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--decisions", type=Path, required=True)
    parser.add_argument("--expected-injections", type=int)
    parser.add_argument("--injections", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = evaluate(args.decisions, args.expected_injections, args.injections)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    raise SystemExit(0 if report["blind_evidence_valid"] else 1)


if __name__ == "__main__":
    main()
