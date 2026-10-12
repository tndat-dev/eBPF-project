"""Validate and summarize exact syscall-ID pilot captures without ML tuning."""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import hashlib
import json
import math
from pathlib import Path
import re

from .observation_campaign import atomic_json


SCHEMA = "sentinel-pulse-syscall-id-histogram-v1"
MAX_ID = 1024
MAP_CAPACITY = 65536


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_seals(root: Path) -> dict[str, str]:
    manifest_path = root / "SHA256SUMS"
    if not manifest_path.is_file():
        raise ValueError("missing SHA256SUMS")
    entries = {}
    for line in manifest_path.read_text().splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9._/-]+)", line)
        if not match:
            raise ValueError("malformed SHA256SUMS entry")
        digest, relative = match.groups()
        path = (root / relative).resolve()
        if root.resolve() not in path.parents or relative in entries or relative == "SHA256SUMS":
            raise ValueError("unsafe or duplicate seal path")
        if not path.is_file() or sha256_file(path) != digest:
            raise ValueError(f"seal mismatch: {relative}")
        entries[relative] = digest
    required = {"START.json", "TERMINAL.json", "histogram.jsonl", "host-metrics.jsonl", "metadata-snapshots.jsonl"}
    if not required <= entries.keys():
        raise ValueError("capture is missing a required sealed artifact")
    return entries


def read_jsonl(path: Path):
    with path.open(encoding="utf-8") as stream:
        for line_no, line in enumerate(stream, 1):
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid JSON at {path.name}:{line_no}") from exc
            if not isinstance(value, dict):
                raise ValueError(f"non-object record at {path.name}:{line_no}")
            yield value


def workload_identity(cgroup_id: int, metadata_doc: dict) -> dict | None:
    item = metadata_doc.get("cgroups", {}).get(str(cgroup_id))
    if not isinstance(item, dict):
        return None
    required = ("node_name", "namespace", "pod_uid", "pod_name", "container_name", "workload_revision")
    if any(not isinstance(item.get(key), str) or not item[key] for key in required):
        return None
    return {key: item[key] for key in required} | {
        "workload_name": item.get("workload_name", item["pod_name"]),
        "role": item.get("role", "unknown"),
        "cgroup_id": cgroup_id,
    }


def load_metadata(path: Path) -> tuple[list[dict], Counter]:
    snapshots, invalid = [], Counter()
    for row in read_jsonl(path):
        observed_at = row.get("observed_at")
        if not isinstance(observed_at, (int, float)) or not math.isfinite(observed_at):
            invalid["metadata_bad_timestamp"] += 1
            continue
        if row.get("identity_match") is not True:
            invalid["metadata_identity_mismatch"] += 1
            continue
        doc = row.get("document")
        if not isinstance(doc, dict) or doc.get("schema") != "sentinel-pulse-cgroups-v1":
            invalid["metadata_invalid_document"] += 1
            continue
        snapshots.append({"observed_at": float(observed_at), "document": doc,
                          "metadata_sha256": row.get("metadata_sha256")})
    snapshots.sort(key=lambda row: row["observed_at"])
    return snapshots, invalid


def latest_metadata(snapshots: list[dict], timestamp: float, max_age: float):
    candidates = [row for row in snapshots if row["observed_at"] <= timestamp]
    if not candidates:
        return None
    selected = candidates[-1]
    if timestamp - selected["observed_at"] > max_age:
        return None
    return selected


def load_traffic_receipt(root: Path, start: dict, terminal: dict) -> tuple[list[dict], str | None]:
    expected_hash = start.get("traffic_receipt_sha256")
    receipt_path = root / "traffic-receipt.json"
    if expected_hash is None:
        if start.get("traffic_regime") != "unlabelled":
            return [], "START claims a regime without a bound traffic receipt"
        if receipt_path.exists():
            return [], "traffic receipt exists but is not bound in START"
        return [], None
    if not receipt_path.is_file() or sha256_file(receipt_path) != expected_hash:
        return [], "traffic receipt missing or hash differs from START"
    try:
        receipt = json.loads(receipt_path.read_text())
    except (OSError, json.JSONDecodeError):
        return [], "traffic receipt is unreadable"
    if not isinstance(receipt, dict):
        return [], "traffic receipt is not a JSON object"
    if receipt.get("schema") != "sentinel-pulse-traffic-receipt-v1":
        return [], "unsupported traffic receipt schema"
    if receipt.get("receipt_id") != start.get("traffic_receipt_id"):
        return [], "traffic receipt ID differs from START"
    if receipt.get("node_name") != start.get("node_name"):
        return [], "traffic receipt node differs from START"
    registered = receipt.get("registered_at_unix")
    if (not isinstance(registered, (int, float)) or not math.isfinite(registered)
            or registered > start.get("registered_wall_time", float("inf"))):
        return [], "traffic receipt was not preregistered before START"
    schedule = receipt.get("schedule")
    if not isinstance(schedule, list) or not schedule:
        return [], "traffic receipt has no schedule"
    normalized = []
    previous_end = None
    for item in schedule:
        if not isinstance(item, dict):
            return [], "malformed traffic schedule entry"
        begin, end, regime = item.get("start_unix"), item.get("end_unix"), item.get("regime")
        if (not isinstance(begin, (int, float)) or not isinstance(end, (int, float))
                or not math.isfinite(begin) or not math.isfinite(end) or begin >= end
                or not isinstance(regime, str) or not regime.strip()):
            return [], "malformed traffic schedule bounds or regime"
        if previous_end is not None and begin < previous_end:
            return [], "traffic schedule overlaps or is unordered"
        previous_end = end
        normalized.append({"start": float(begin), "end": float(end), "regime": regime})
    probe_start, probe_end = terminal.get("probe_started_at_unix"), terminal.get("probe_ended_at_unix")
    if (not isinstance(probe_start, (int, float)) or not isinstance(probe_end, (int, float))
            or not math.isfinite(probe_start) or not math.isfinite(probe_end)
            or probe_start >= probe_end):
        return [], "terminal lacks valid probe attach/detach timestamps"
    return normalized, None


def interval_regime(begin: float, end: float, schedule: list[dict]) -> str | None:
    matches = [item["regime"] for item in schedule
               if begin >= item["start"] and end <= item["end"]]
    return matches[0] if len(matches) == 1 else None


def summarize(root: Path, max_metadata_age_seconds: float = 30.0,
              max_map_fraction: float = 0.95) -> dict:
    seals = verify_seals(root)
    start = json.loads((root / "START.json").read_text())
    terminal = json.loads((root / "TERMINAL.json").read_text())
    if start.get("schema") != "sentinel-pulse-syscall-histogram-pilot-v1":
        raise ValueError("unsupported pilot START schema")
    snapshots, problems = load_metadata(root / "metadata-snapshots.jsonl")
    raw_targets = start.get("allowlist_cgroup_ids")
    expected_targets = set(raw_targets) if isinstance(raw_targets, list) and all(
        type(value) is int and value > 0 for value in raw_targets
    ) and len(set(raw_targets)) == len(raw_targets) else set()
    if not expected_targets:
        problems["invalid_start_target_allowlist"] += 1
    for snapshot in snapshots:
        try:
            snapshot_targets = {int(value) for value in snapshot["document"]["cgroups"]}
        except (KeyError, TypeError, ValueError):
            problems["metadata_target_allowlist_mismatch"] += 1
            continue
        if snapshot_targets != expected_targets:
            problems["metadata_target_allowlist_mismatch"] += 1
    schedule, receipt_error = load_traffic_receipt(root, start, terminal)
    if receipt_error:
        problems["traffic_receipt_invalid"] += 1
    intervals = defaultdict(list)
    integrity = []
    counts_by_identity = defaultdict(Counter)
    exposure = defaultdict(lambda: {"records": 0, "seconds": 0.0, "regimes": Counter()})
    unassigned = Counter()
    max_scan = 0.0
    seen = set()
    for row in read_jsonl(root / "histogram.jsonl"):
        if row.get("schema") != SCHEMA:
            raise ValueError("unsupported histogram schema")
        if row.get("type") == "integrity":
            integrity.append(row)
            continue
        if row.get("type") != "interval":
            problems["unknown_record_type"] += 1
            continue
        cg = row.get("cgroup_id")
        begin, end = row.get("window_start"), row.get("window_end")
        scan = row.get("snapshot_scan_seconds")
        counts = row.get("counts")
        if type(cg) is not int or cg <= 0 or not all(isinstance(v, (int, float)) and math.isfinite(v) for v in (begin, end, scan)):
            problems["malformed_interval"] += 1
            continue
        if end <= begin or scan < 0 or scan > end - begin or not isinstance(counts, dict):
            problems["invalid_interval_bounds"] += 1
            continue
        key = (round(float(begin), 6), round(float(end), 6), cg)
        if key in seen:
            problems["duplicate_cgroup_interval"] += 1
            continue
        seen.add(key)
        checked = {}
        for raw_id, count in counts.items():
            if not str(raw_id).isdecimal() or not 0 <= int(raw_id) < MAX_ID or type(count) is not int or count < 0:
                problems["invalid_syscall_count"] += 1
                checked = None
                break
            checked[int(raw_id)] = count
        if checked is None:
            continue
        item = {"row": row, "counts": checked, "cgroup_id": cg,
                "begin": float(begin), "end": float(end), "scan": float(scan)}
        intervals[round(float(begin), 6)].append(item)
        max_scan = max(max_scan, float(scan))

    integrity_by_begin = {}
    cadence_seconds = start.get("snapshot_interval_ms", 1000) / 1000.0
    for row in integrity:
        begin = row.get("window_start")
        if not isinstance(begin, (int, float)) or not math.isfinite(begin):
            problems["malformed_integrity_record"] += 1
            continue
        key = round(float(begin), 6)
        if key in integrity_by_begin:
            problems["duplicate_integrity_record"] += 1
        integrity_by_begin[key] = row
        elapsed = row.get("interval_seconds")
        if (not isinstance(elapsed, (int, float)) or not math.isfinite(elapsed)
                or elapsed <= 0 or not math.isfinite(cadence_seconds) or cadence_seconds <= 0):
            problems["invalid_integrity_cadence"] += 1
        elif elapsed > cadence_seconds * 1.5:
            problems["telemetry_interval_gap"] += 1

    cycle_count = 0
    for begin, rows in sorted(intervals.items()):
        cycle_count += 1
        guard = integrity_by_begin.get(begin)
        if guard is None:
            problems["missing_integrity_record"] += 1
            continue
        target_count = guard.get("target_count")
        observed_targets = {r["cgroup_id"] for r in rows}
        if (type(target_count) is not int or target_count != len(rows)
                or len(observed_targets) != len(rows)
                or observed_targets != expected_targets):
            problems["target_coverage_mismatch"] += 1
        drops, map_entries = guard.get("dropped_updates"), guard.get("map_entries")
        if type(drops) is not int or drops != 0:
            problems["dropped_updates"] += 1
        if type(map_entries) is not int or map_entries >= int(MAP_CAPACITY * max_map_fraction):
            problems["map_near_capacity_or_invalid"] += 1
        for entry in rows:
            metadata = latest_metadata(snapshots, entry["end"], max_metadata_age_seconds)
            identity = workload_identity(entry["cgroup_id"], metadata["document"]) if metadata else None
            if identity is None:
                lost = sum(entry["counts"].values())
                unassigned["missing_or_stale_workload_identity"] += lost
                problems["unassigned_histogram_counts"] += max(1, lost)
                continue
            identity_key = json.dumps(identity, sort_keys=True, separators=(",", ":"))
            counts_by_identity[identity_key].update(entry["counts"])
            seconds = max(0.0, entry["end"] - entry["begin"])
            exposure[identity_key]["records"] += 1
            exposure[identity_key]["seconds"] += seconds
            regime = interval_regime(entry["begin"], entry["end"], schedule) if schedule else None
            probe_start = terminal.get("probe_started_at_unix")
            probe_end = terminal.get("probe_ended_at_unix")
            if (isinstance(probe_start, (int, float)) and isinstance(probe_end, (int, float))
                    and (entry["begin"] < probe_start or entry["end"] > probe_end)):
                problems["interval_outside_probe_lifetime"] += 1
            if regime is None:
                exposure[identity_key]["regimes"]["unlabelled"] += 1
                if start.get("traffic_receipt_sha256"):
                    problems["interval_outside_single_registered_regime"] += 1
            else:
                exposure[identity_key]["regimes"][regime] += 1

    if len(integrity_by_begin) != cycle_count:
        problems["integrity_cycle_count_mismatch"] += abs(len(integrity_by_begin) - cycle_count)
    workloads = {}
    for identity_key, counts in sorted(counts_by_identity.items()):
        total = sum(counts.values())
        info = exposure[identity_key]
        identity = json.loads(identity_key)
        workloads[identity_key] = {
            "identity": identity,
            "syscall_total": total,
            "observed_container_seconds": info["seconds"],
            "interval_records": info["records"],
            "traffic_regimes": dict(info["regimes"]),
            "syscall_ids": [
                {"id": syscall_id, "count": count,
                 "share": count / total if total else 0.0,
                 "per_container_second": count / info["seconds"] if info["seconds"] else None}
                for syscall_id, count in counts.most_common()
            ],
        }
    valid = (terminal.get("state") == "completed" and terminal.get("exit_code") == 0
             and not problems and cycle_count > 0 and bool(schedule)
             and start.get("traffic_regime") == "registered_schedule")
    return {
        "schema": "sentinel-pulse-syscall-histogram-analysis-v1",
        "evidence_class": "selection_evidence" if valid else "engineering_pilot_or_invalid_capture",
        "capture_valid_for_feature_selection": valid,
        "selection_rank_allowed": valid,
        "run_id": start.get("run_id"),
        "start_sha256": sha256_file(root / "START.json"),
        "terminal_sha256": sha256_file(root / "TERMINAL.json"),
        "capture_sha256": seals["histogram.jsonl"],
        "metadata_sha256": seals["metadata-snapshots.jsonl"],
        "workloads": workloads,
        "integrity": {
            "terminal_state": terminal.get("state"),
            "cycles": cycle_count,
            "integrity_records": len(integrity),
            "max_snapshot_scan_seconds": max_scan,
            "metadata_snapshots_usable": len(snapshots),
            "unassigned_syscall_count": sum(unassigned.values()),
            "unassigned_reasons": dict(unassigned),
            "problems": dict(problems),
            "traffic_receipt_error": receipt_error,
        },
        "selection_restrictions": [
            "traffic regime must be preregistered and bound to a traffic receipt",
            "this output contains syscall-entry counts, not syscall success labels",
            "this output cannot establish attack recall, precision, or confusion matrix",
            "compat/x32 process ABI is not distinguished by this collector",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture-dir", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--max-metadata-age-seconds", type=float, default=30.0)
    args = parser.parse_args()
    if args.max_metadata_age_seconds <= 0:
        parser.error("metadata age must be positive")
    atomic_json(args.output, summarize(args.capture_dir, args.max_metadata_age_seconds))


if __name__ == "__main__":
    main()
