"""Separate formal recovery registration, streaming exposure and aggregation.

No legacy NORMAL_PASS, attack evaluation or automatic model promotion. The
worker capture/decision inputs must have been bound BEFORE collection starts.
"""
from __future__ import annotations

import argparse
from bisect import bisect_left, bisect_right
from collections import Counter, defaultdict, deque
import json
import math
from pathlib import Path, PurePosixPath
import re
import subprocess
import time

from .collector_contract import WORKERS
from .detector_freshness import CONTRACT, CONTRACT_SHA256, check, complete
from .integrity import sha256_file
from .operational_soak import validate_binding, observe, merge_intervals, digest as health_digest
from .recovery_deployment import contract, bind_detector
from .telemetry_recovery import digest, validate_profile, SNAPSHOT_SCHEMA, HARD_COUNTERS

SCHEMA = "sentinel-pulse-recovery-formal-start-v1"
NODE_SCHEMA = "sentinel-pulse-recovery-formal-node-report-v1"
SCORED = {"normal", "suppressed", "alert"}
COLLECTOR_TIMING = {"schema": "sentinel-pulse-collector-timing-contract-v1",
                    "anchor": "systemd-exec-main-start-monotonic",
                    "maximum_clock_pair_seconds": .05,
                    "end_slack_seconds": 1, "duration_slack_seconds": 2,
                    "automatic_bound_widening": False}


def validate_collector_timing(root: Path, marker_path: Path, host: str) -> float:
    """Bind timeout duration to actual service execution, not setup receipt IO."""
    marker = validate_marker(json.loads(marker_path.read_text()))
    receipt = json.loads((root / "COLLECTOR_RUNTIME_START.json").read_text())
    if (receipt.get("schema") != "sentinel-pulse-collector-runtime-start-v1"
            or receipt.get("unit") != "sentinel-pulse-collector-500ms-experiment.service"
            or receipt.get("run_id") != marker["run_id"] or receipt.get("worker_ip") != host
            or receipt.get("marker_sha256") != sha256_file(marker_path)
            or receipt.get("collector_registration_sha256") != sha256_file(root / "START.json")
            or not re.fullmatch(r"[0-9a-f]{32}", receipt.get("invocation_id", ""))
            or type(receipt.get("main_pid")) is not int or receipt["main_pid"] <= 0
            or receipt.get("active_state_at_observation") != "active"):
        raise ValueError("invalid collector runtime start identity")
    microseconds = receipt["exec_start_monotonic_usec"]
    if type(microseconds) is not int or microseconds <= 0:
        raise ValueError("invalid collector start monotonic timestamp")
    before, after, wall = [number(receipt["clock_pair"][name], name)
                           for name in ("monotonic_before", "monotonic_after", "realtime")]
    if not 0 <= after - before <= COLLECTOR_TIMING["maximum_clock_pair_seconds"] or microseconds / 1e6 > before:
        raise ValueError("unbounded/invalid collector clock pairing")
    actual = wall - ((before + after) / 2 - microseconds / 1e6)
    if number(receipt["exec_started_at_unix"], "actual service start") != actual:
        raise ValueError("collector start differs from independent clock replay")
    setup = number(json.loads((root / "START.json").read_text())["started_at_unix"], "collector setup")
    if not marker["started_at_unix"] <= setup <= actual <= wall <= marker["started_at_unix"] + 120:
        raise ValueError("collector service start outside preregistered startup budget")
    return actual


def record_collector_timing(root: Path, marker_path: Path, host: str) -> dict:
    marker = validate_marker(json.loads(marker_path.read_text()))
    if root.name != marker["run_id"] or host not in marker["workers"]:
        raise ValueError("collector timing run/worker differs")
    raw = subprocess.check_output(["systemctl", "show", "sentinel-pulse-collector-500ms-experiment.service",
        "-p", "ExecMainStartTimestampMonotonic", "-p", "MainPID", "-p", "InvocationID", "-p", "ActiveState"],
        text=True, timeout=5)
    values = dict(line.split("=", 1) for line in raw.splitlines() if "=" in line)
    before, wall, after = time.monotonic(), time.time(), time.monotonic()
    micros = int(values["ExecMainStartTimestampMonotonic"])
    result = {"schema": "sentinel-pulse-collector-runtime-start-v1", "run_id": root.name,
              "worker_ip": host, "unit": "sentinel-pulse-collector-500ms-experiment.service",
              "marker_sha256": sha256_file(marker_path), "collector_registration_sha256": sha256_file(root / "START.json"),
              "invocation_id": values["InvocationID"], "main_pid": int(values["MainPID"]),
              "active_state_at_observation": values["ActiveState"], "exec_start_monotonic_usec": micros,
              "clock_pair": {"monotonic_before": before, "realtime": wall, "monotonic_after": after},
              "exec_started_at_unix": wall - ((before + after) / 2 - micros / 1e6)}
    # Persist once; consumers replay all fields before using the new anchor.
    write_new(root / "COLLECTOR_RUNTIME_START.json", result)
    validate_collector_timing(root, marker_path, host)
    return result


def number(value, name):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise ValueError("invalid finite number: " + name)
    return value


def checksum(value, length=64):
    if not isinstance(value, str) or not re.fullmatch(f"[0-9a-f]{{{length}}}", value):
        raise ValueError("invalid checksum/source commit")


def validate_marker(marker: dict) -> dict:
    if marker.get("schema") != SCHEMA or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", marker.get("run_id", "")):
        raise ValueError("unsupported recovery formal marker/run ID")
    for name in ("automatic_promotion", "automatic_blind_evaluation"):
        if marker.get(name) is not False:
            raise ValueError("formal recovery must not open blind/promotion")
    if type(marker.get("diagnostic_only")) is not bool:
        raise ValueError("missing explicit diagnostic/formal classification")
    if marker.get("collector_timing_contract") != COLLECTOR_TIMING:
        raise ValueError("missing/changed actual collector timing contract")
    number(marker["started_at_unix"], "registration time")
    for name in ("model_manifest_sha256", "decision_policy_sha256", "source_files_sha256"):
        checksum(marker[name])
    checksum(marker["source_commit"], 40)
    files = marker["source_files"]
    if not files or not isinstance(files, dict) or digest(files) != marker["source_files_sha256"]:
        raise ValueError("source file binding mismatch")
    for name, sha in files.items():
        path = PurePosixPath(name)
        if path.is_absolute() or ".." in path.parts or not name.startswith("sentinel_pulse/"):
            raise ValueError("unsafe registered source path")
        checksum(sha)
    recovery = marker["telemetry_recovery_contract"]
    profile = validate_profile(recovery["profile"])
    if (recovery.get("profile_sha256") != digest(profile)
            or recovery.get("schema") != "sentinel-pulse-recovery-deployment-v1"
            or recovery.get("automatic_promotion") is not False
            or recovery.get("automatic_blind_evaluation") is not False):
        raise ValueError("recovery profile binding mismatch")
    checksum(recovery["profile_file_sha256"])
    if marker.get("detector_freshness_contract") != CONTRACT or marker.get("detector_freshness_contract_sha256") != CONTRACT_SHA256:
        raise ValueError("detector freshness contract mismatch")
    duration = marker["collector_duration_seconds"]
    if type(duration) is not int:
        raise ValueError("collector duration must be integer")
    lower, upper = (180, 1800) if marker["diagnostic_only"] else (86400, profile["maximum_wall_seconds"] - 120)
    if not lower <= duration <= upper:
        raise ValueError("duration outside registered diagnostic/formal bounds")
    binding = validate_binding(marker["operational_evaluation_contract"])
    workers = marker["workers"]
    if (set(workers) != WORKERS or len({w["node_name"] for w in workers.values()}) != 3
            or {w["node_name"] for w in workers.values()} != set(binding["worker_nodes"])):
        raise ValueError("worker IP/node mapping differs from dependency binding")
    union = set()
    for worker in workers.values():
        keys = worker["expected_workloads"]
        if not keys or len(keys) != len(set(keys)) or not set(keys) <= set(binding["expected_workloads"]):
            raise ValueError("invalid per-node workload scope")
        union.update(keys)
        for name in ("loader_sha256", "bpf_object_sha256"):
            checksum(worker[name])
    if union != set(binding["expected_workloads"]):
        raise ValueError("worker scope does not cover all frozen model keys")
    return marker


def register(run_id: str, source: Path, model: Path, policy: Path,
             recovery: Path, binding: dict, workers: dict, duration: int,
             diagnostic_only: bool = False, now: float | None = None) -> dict:
    from .finalize_candidate import verify_model_bundle
    from .decision_policy import load_decision_policy
    manifest, candidates, collect_only = verify_model_bundle(model)
    if collect_only or set(candidates) != set(binding["expected_workloads"]):
        raise ValueError("registration scope differs from complete frozen model")
    load_decision_policy(policy)
    status = subprocess.check_output(["git", "-c", "safe.directory=" + str(source), "-C", str(source),
                                      "status", "--porcelain", "--untracked-files=all"], text=True)
    if status.strip():
        raise ValueError("formal source must be a clean Git checkout")
    commit = subprocess.check_output(["git", "-c", "safe.directory=" + str(source), "-C", str(source),
                                      "rev-parse", "HEAD"], text=True).strip()
    names = subprocess.check_output(["git", "-c", "safe.directory=" + str(source), "-C", str(source),
                                     "ls-files", "sentinel_pulse"], text=True).splitlines()
    files = {name: sha256_file(source / name) for name in names}
    payload = {"schema": SCHEMA, "run_id": run_id, "source_commit": commit,
               "source_files": files, "source_files_sha256": digest(files),
               "model_manifest_sha256": sha256_file(model / "manifest.json"),
               "decision_policy_sha256": sha256_file(policy),
               "started_at_unix": time.time() if now is None else now,
               "collector_duration_seconds": duration, "diagnostic_only": diagnostic_only,
               "collector_timing_contract": dict(COLLECTOR_TIMING),
               "telemetry_recovery_contract": contract(recovery, .5, .999, 30),
               "detector_freshness_contract": CONTRACT,
               "detector_freshness_contract_sha256": CONTRACT_SHA256,
               "operational_evaluation_contract": binding, "workers": workers,
               "automatic_promotion": False, "automatic_blind_evaluation": False}
    return validate_marker(payload)


def check_resume(marker: dict, supplied: dict, terminal: bool = False):
    validate_marker(marker)
    validate_marker(supplied)
    if terminal:
        raise ValueError("terminal recovery runs cannot be resumed/relabelled")
    if {k: v for k, v in marker.items() if k != "started_at_unix"} != {
            k: v for k, v in supplied.items() if k != "started_at_unix"}:
        raise ValueError("resume source/model/policy/profile/worker contract mismatch")


def attest_worker(marker_path: Path, host: str, source: Path, model: Path, policy: Path,
                  now: float | None = None) -> dict:
    """Must run before the collector; receipt is later copied into its new run."""
    from .finalize_candidate import verify_model_bundle
    marker = validate_marker(json.loads(marker_path.read_text()))
    if host not in marker["workers"]:
        raise ValueError("unknown worker")
    registered = marker["started_at_unix"]
    attested = time.time() if now is None else number(now, "attestation clock")
    if not registered <= attested <= registered + 120:
        raise ValueError("worker attestation outside preregistered startup budget")
    args = ["git", "-c", "safe.directory=" + str(source), "-C", str(source)]
    if subprocess.check_output(args + ["rev-parse", "HEAD"], text=True).strip() != marker["source_commit"]:
        raise ValueError("worker source commit differs from registration")
    if subprocess.check_output(args + ["status", "--porcelain", "--untracked-files=all"], text=True).strip():
        raise ValueError("worker source is dirty")
    names = subprocess.check_output(args + ["ls-files", "sentinel_pulse"], text=True).splitlines()
    if {name: sha256_file(source / name) for name in names} != marker["source_files"]:
        raise ValueError("worker runtime source bytes differ from registration")
    verify_model_bundle(model)
    if (sha256_file(model / "manifest.json") != marker["model_manifest_sha256"]
            or sha256_file(policy) != marker["decision_policy_sha256"]):
        raise ValueError("worker model/policy differs from registration")
    return {"schema": "sentinel-pulse-recovery-formal-worker-start-v1", "worker_ip": host,
            "marker_sha256": sha256_file(marker_path), "source_commit": marker["source_commit"],
            "source_files_sha256": marker["source_files_sha256"], "attested_at_unix": attested}


def supervision_step(marker: dict, marker_sha: str, previous: dict | None,
                     nodes: dict, now: float) -> dict:
    """Pure fail-closed control state; it NEVER mints a formal PASS.

    The SSH/systemd adapter must persist this state and supply real node
    receipts. Unknown connectivity is degraded, not a normal ML observation.
    """
    validate_marker(marker)
    checksum(marker_sha)
    number(now, "supervisor clock")
    started = marker["started_at_unix"]
    if now < started or set(nodes) != WORKERS:
        raise ValueError("invalid supervisor time/worker scope")
    if previous is not None:
        if previous.get("marker_sha256") != marker_sha or previous.get("run_id") != marker["run_id"]:
            raise ValueError("supervisor resume binding mismatch")
        if now <= previous["checked_at_unix"]:
            raise ValueError("supervisor clock moved backwards")
        if previous["phase"] in {"rejected", "ready_to_finalize"}:
            raise ValueError("terminal supervisor phase cannot be resumed")
        if now - previous["checked_at_unix"] > 30:
            raise ValueError("supervisor observation gap exceeds audit budget")
    unknown = dict(previous["unknown_since"]) if previous else {}
    errors, degraded, finished = [], [], []
    for host, node in nodes.items():
        status = node.get("status")
        if status == "unavailable":
            unknown.setdefault(host, now)
            degraded.append(host)
            if now > started + 120 and now - max(unknown[host], started + 120) > 30:
                errors.append("worker connectivity unknown beyond bound: " + host)
            continue
        unknown.pop(host, None)
        if node.get("marker_sha256") != marker_sha or node.get("run_id") != marker["run_id"]:
            errors.append("worker live binding mismatch: " + host)
        if status == "finished":
            if node.get("collector_exit_status") != 0 or node.get("detector_restarts") != 0:
                errors.append("worker terminated abnormally: " + host)
            finished.append(host)
        elif status == "active":
            if (node.get("detector_active") is not True or node.get("detector_restarts") != 0
                    or node.get("capture_tail", {}).get("valid") is not True):
                errors.append("worker runtime/capture integrity failed: " + host)
            elif node["capture_tail"].get("profile_sha256") != marker["telemetry_recovery_contract"]["profile_sha256"]:
                errors.append("worker telemetry profile changed: " + host)
            elif node["capture_tail"].get("status") != "ready":
                degraded.append(host)
        else:
            errors.append("unsupported worker lifecycle state: " + host)
    if now > started + marker["collector_duration_seconds"] + 120 and len(finished) != 3:
        errors.append("registered lifecycle deadline exceeded")
    phase = "rejected" if errors else "ready_to_finalize" if len(finished) == 3 else "recovering" if degraded else "monitoring"
    return {"schema": "sentinel-pulse-recovery-formal-supervision-v1", "run_id": marker["run_id"],
            "marker_sha256": marker_sha, "checked_at_unix": now, "phase": phase,
            "unknown_since": unknown, "degraded_workers": degraded, "finished_workers": finished,
            "errors": errors, "formal_recovery_pass": False, "automatic_promotion": False,
            "automatic_blind_evaluation": False}


def health_exclusions(marker: dict, path: Path) -> tuple[list, dict]:
    binding = marker["operational_evaluation_contract"]
    rows = []
    with path.open() as stream:
        for line in stream:
            row = json.loads(line)
            expected = observe(binding, rows, {k: row[k] for k in ("fatal", "transient", "warnings")},
                               row["checked_at_unix"], marker["started_at_unix"])
            if row != expected:
                raise ValueError("health journal differs from independent replay")
            rows.append(row)
    if not rows:
        raise ValueError("missing dependency health observations")
    intervals = merge_intervals([r["excluded_interval"] for r in rows if r["excluded_interval"]])
    return intervals, {"valid": not any(r["fatal"] for r in rows) and not rows[-1]["degraded"],
                       "last_observation": rows[-1]["checked_at_unix"],
                       "health_log_sha256": sha256_file(path)}


def add_interval(intervals: list, start: float, end: float):
    """Online exact union: storage scales with gaps, not windows/replicas."""
    if not all(math.isfinite(v) for v in (start, end)) or start >= end:
        raise ValueError("invalid scored exposure interval")
    i = bisect_left(intervals, [start, end])
    if i and intervals[i - 1][1] >= start:
        i -= 1
    j = i
    while j < len(intervals) and intervals[j][0] <= end:
        start = min(start, intervals[j][0])
        end = max(end, intervals[j][1])
        j += 1
    intervals[i:j] = [[start, end]]


def source_key(row):
    return (row["node_name"], row["pod_uid"], row["container_name"], str(row["cgroup_id"]),
            row["window_start"], row["window_end"])


def validate_worker_start(root: Path, marker_path: Path, host: str) -> dict:
    """Reuse the same preregistration/attestation checks at install and replay."""
    marker = validate_marker(json.loads(marker_path.read_text()))
    if host not in marker["workers"] or root.name != marker["run_id"]:
        raise ValueError("worker/run scope differs from formal preregistration")
    worker = marker["workers"][host]
    receipt = json.loads((root / "FORMAL_WORKER_START.json").read_text())
    if (receipt.get("schema") != "sentinel-pulse-recovery-formal-worker-start-v1"
            or receipt.get("marker_sha256") != sha256_file(marker_path)
            or receipt.get("source_commit") != marker["source_commit"]
            or receipt.get("source_files_sha256") != marker["source_files_sha256"]
            or receipt.get("worker_ip") != host):
        raise ValueError("missing preregistered worker source/marker binding")
    collector = json.loads((root / "START.json").read_text())
    started = number(collector["started_at_unix"], "collector start")
    attested = number(receipt["attested_at_unix"], "worker attestation")
    if not marker["started_at_unix"] <= attested <= started <= marker["started_at_unix"] + 120:
        raise ValueError("registration must precede attestation/capture; startup bound exceeded")
    for field in ("loader", "bpf_object"):
        if collector["sha256"][field] != worker[field + "_sha256"]:
            raise ValueError("collector artifact differs from preregistration")
    if collector.get("collector_variant") != "projected":
        raise ValueError("formal recovery requires registered projected counter")
    if bind_detector(root / "features.jsonl", root / "telemetry-recovery-profile.json") != marker["telemetry_recovery_contract"]:
        raise ValueError("collector recovery contract mismatch")
    validate_collector_timing(root, marker_path, host)
    return marker


def evaluate_node(root: Path, marker_path: Path, host: str, model_path: Path,
                  health_path: Path) -> dict:
    """Streaming decision/feature join; never materialize a day of feature vectors."""
    from .validate_recovery_capture import validate
    marker = validate_worker_start(root, marker_path, host)
    worker = marker["workers"][host]
    started = validate_collector_timing(root, marker_path, host)
    if sha256_file(model_path) != marker["model_manifest_sha256"]:
        raise ValueError("node run/model identity mismatch")
    manifest = json.loads(model_path.read_text())
    if set(manifest["workloads"]) != set(marker["operational_evaluation_contract"]["expected_workloads"]):
        raise ValueError("manifest key scope mismatch")
    if json.loads((root / "DETECTOR_FRESHNESS_CONTRACT.json").read_text()) != CONTRACT:
        raise ValueError("missing/changed live freshness binding")
    excluded, health = health_exclusions(marker, health_path)
    excluded_ends = [b for _, b in excluded]
    profile = marker["telemetry_recovery_contract"]["profile"]
    capture = validate(root / "features.jsonl", profile)
    errors = list(capture["errors"])
    counts, scored, all_alerts, degraded_alerts = Counter(), Counter(), Counter(), Counter()
    intervals = defaultdict(list)
    histories, previous = {}, {}
    previous_checked = None
    last_end = started
    decisions_seen = 0
    with (root / "features.jsonl").open() as features, (root / "decisions.jsonl").open() as decisions, \
            (root / "alerts.jsonl").open() as alerts:
        for line in features:
            feature = json.loads(line)
            if feature["schema"] == SNAPSHOT_SCHEMA:
                if not feature["recovery"]["can_score"]:
                    histories.clear()
                continue
            if feature["schema"] == "sentinel-pulse-feature-schema-v1":
                continue
            raw = decisions.readline()
            if not raw:
                raise ValueError("unconsumed feature: formal cannot silently omit decisions")
            row = json.loads(raw)
            key = source_key(row)
            identity, begin, end = key[:4], number(key[-2], "window start"), number(key[-1], "window end")
            workload, status = row["workload_key"], row["status"]
            if (key != source_key(feature) or workload != feature["workload_key"]
                    or row.get("schema") != "sentinel-pulse-decision-v1"
                    or row.get("run_id") != root.name or key[0] != worker["node_name"]
                    or workload not in worker["expected_workloads"]
                    or row.get("model_manifest_sha256") != marker["model_manifest_sha256"]
                    or row.get("decision_policy_sha256") != marker["decision_policy_sha256"]
                    or row.get("telemetry_recovery") != feature["telemetry_recovery"]):
                raise ValueError("decision/feature/run/source/model binding mismatch")
            if begin < started or begin >= end or end > started + marker["collector_duration_seconds"] + COLLECTOR_TIMING["end_slack_seconds"]:
                raise ValueError("decision outside registered capture interval")
            if status not in SCORED | {"warming", "telemetry-degraded"}:
                raise ValueError("unknown/rebaseline workload cannot satisfy frozen formal coverage")
            approved = manifest.get("approved_workload_revisions", {}).get(workload, [])
            if not approved or row.get("workload_revision") not in approved or row.get("workload_revision") != feature.get("workload_revision"):
                raise ValueError("unapproved/mismatched workload revision")
            meta = row["detector_freshness"]
            checked = check(feature, meta["checked_at"], previous_checked)
            replay = complete(checked, end, meta["decision_completed_at"])
            if replay != meta:
                raise ValueError("detector freshness audit mismatch")
            previous_checked = meta["checked_at"]
            if end <= previous.get(identity, (-math.inf, None))[0]:
                raise ValueError("duplicate/non-monotonic decision source")
            previous_end, regime = previous.get(identity, (-math.inf, None))
            eligible = feature["telemetry_recovery"]["eligible"] and meta["eligible"]
            if not eligible:
                histories.pop(identity, None)
                if status in SCORED or "inference_ms" in row:
                    raise ValueError("quarantined/stale feature entered inference")
            else:
                history = histories.setdefault(identity, deque(maxlen=manifest["history_windows"]))
                if end - previous_end > manifest["max_contiguous_gap_seconds"] or (
                        regime is not None and feature.get("traffic_regime") is not None and regime != feature["traffic_regime"]):
                    history.clear()
                if (status in SCORED) != (len(history) == manifest["history_windows"]):
                    raise ValueError("decision scoring/history warm-up mismatch")
                history.append(end)
            previous[identity] = (end, feature.get("traffic_regime"))
            index = bisect_right(excluded_ends, begin)
            degraded = index < len(excluded) and excluded[index][0] < end
            counts[status] += 1
            decisions_seen += 1
            last_end = max(last_end, end)
            if status == "alert":
                all_alerts[workload] += 1
                degraded_alerts[workload] += int(degraded)
                alert_raw = alerts.readline()
                if not alert_raw or digest(json.loads(alert_raw)) != digest(row):
                    raise ValueError("alert stream differs from ALL decision alerts")
            if status in SCORED:
                for field in ("score", "conformal_p", "inference_ms", "post_window_processing_seconds"):
                    value = number(row[field], field)
                    if value < 0:
                        raise ValueError("negative scored metric")
                if not 0 < row["conformal_p"] <= 1 or not 0 <= row["score"] <= 1:
                    raise ValueError("invalid probability/score range")
                scored[workload] += 1
                if not degraded:
                    add_interval(intervals[workload], begin, end)
        if decisions.readline() or alerts.readline():
            raise ValueError("extra/unbound decisions or alerts")
    if last_end > marker["started_at_unix"] + profile["maximum_wall_seconds"]:
        errors.append("formal wall-time budget exceeded")
    if last_end < started + marker["collector_duration_seconds"] - COLLECTOR_TIMING["duration_slack_seconds"]:
        errors.append("capture did not complete registered duration")
    if not health["valid"] or abs(last_end - health["last_observation"]) > marker["operational_evaluation_contract"]["profile"]["maximum_health_observation_gap_seconds"]:
        errors.append("dependency health gate/tail coverage failed")
    if not scored or set(capture["workloads"]) != set(worker["expected_workloads"]):
        errors.append("node workload coverage incomplete")
    for file, expected in (("collector-before-stop.systemd", {"ActiveState": "inactive", "Result": "success", "ExecMainStatus": "0"}),
                           ("detector-before-stop.systemd", {"ActiveState": "active", "Result": "success", "ExecMainStatus": "0", "NRestarts": "0"})):
        service = dict(l.split("=", 1) for l in (root / file).read_text().splitlines() if "=" in l)
        if any(service.get(k) != v for k, v in expected.items()):
            errors.append("worker service did not finish registered duration cleanly: " + file)
    return {"schema": NODE_SCHEMA, "run_id": root.name, "worker_ip": host,
            "marker_sha256": sha256_file(marker_path), "health_log_sha256": health["health_log_sha256"],
            "source_files_sha256": marker["source_files_sha256"],
            "model_manifest_sha256": marker["model_manifest_sha256"],
            "decision_policy_sha256": marker["decision_policy_sha256"],
            "telemetry_profile_sha256": marker["telemetry_recovery_contract"]["profile_sha256"],
            "detector_freshness_contract_sha256": CONTRACT_SHA256,
            "valid": not errors, "errors": errors[:200], "capture": capture,
            "statuses": dict(counts), "decisions": decisions_seen, "scored_rows": dict(scored),
            "all_alerts": dict(all_alerts), "alerts_during_health_degraded": dict(degraded_alerts),
            "valid_scored_intervals": dict(intervals), "excluded_health_intervals": excluded,
            "inputs_sha256": {name: sha256_file(root / name) for name in (
                "features.jsonl", "decisions.jsonl", "alerts.jsonl", "FORMAL_WORKER_START.json", "START.json",
                "COLLECTOR_RUNTIME_START.json")},
            "formal_recovery_pass": False, "legacy_normal_pass": False,
            "automatic_promotion": False, "automatic_blind_evaluation": False,
            "kernel_to_alert_claim_allowed": False}


def aggregate(marker_path: Path, paths: list[Path]) -> dict:
    marker = validate_marker(json.loads(marker_path.read_text()))
    if len(paths) != 3 or len({p.resolve() for p in paths}) != 3:
        raise ValueError("three distinct node reports required")
    reports = [json.loads(path.read_text()) for path in paths]
    if {r.get("worker_ip") for r in reports} != WORKERS:
        raise ValueError("missing/duplicate worker reports")
    intervals, alerts = defaultdict(list), Counter()
    identity = {"schema": NODE_SCHEMA, "run_id": marker["run_id"],
                "marker_sha256": sha256_file(marker_path), "source_files_sha256": marker["source_files_sha256"],
                "model_manifest_sha256": marker["model_manifest_sha256"], "decision_policy_sha256": marker["decision_policy_sha256"],
                "telemetry_profile_sha256": marker["telemetry_recovery_contract"]["profile_sha256"],
                "detector_freshness_contract_sha256": CONTRACT_SHA256}
    expected = marker["operational_evaluation_contract"]["expected_workloads"]
    health_hashes = set()
    for report in reports:
        if any(report.get(k) != v for k, v in identity.items()):
            raise ValueError("node source/model/policy/profile/run binding mismatch")
        checksum(report["health_log_sha256"])
        health_hashes.add(report["health_log_sha256"])
        for key, count in report["all_alerts"].items():
            if key not in expected or type(count) is not int or count < 0:
                raise ValueError("invalid all-alerts numerator")
            alerts[key] += count
        for key, values in report["valid_scored_intervals"].items():
            if key not in marker["workers"][report["worker_ip"]]["expected_workloads"]:
                raise ValueError("unexpected exposure key")
            for begin, end in values:
                if begin < marker["started_at_unix"] or end > marker["started_at_unix"] + marker["telemetry_recovery_contract"]["profile"]["maximum_wall_seconds"]:
                    raise ValueError("exposure outside registered wall bound")
                add_interval(intervals[key], begin, end)
    if len(health_hashes) != 1:
        raise ValueError("node reports used different health journals")
    profile = marker["operational_evaluation_contract"]["profile"]
    minimum = marker["telemetry_recovery_contract"]["profile"]["minimum_scored_hours_per_workload"]
    workloads = {}
    for key in expected:
        hours = sum(end - begin for begin, end in intervals[key]) / 3600
        rate = alerts[key] / hours if hours else None
        workloads[key] = {"valid_scored_hours": hours, "all_alerts": alerts[key],
                          "all_alerts_per_valid_hour": rate, "exposure_gate": hours >= minimum,
                          "rate_gate": rate is not None and rate <= profile["maximum_alerts_per_hour_per_workload"]}
    total_hours = sum(w["valid_scored_hours"] for w in workloads.values())
    total_alerts = sum(alerts.values())
    rate = total_alerts / total_hours if total_hours else None
    integrity = all(r.get("valid") is True and not r.get("errors")
                    and r["capture"].get("valid") is True
                    and r["capture"].get("profile_sha256") == identity["telemetry_profile_sha256"]
                    and type(r["capture"].get("availability")) in (int, float)
                    and math.isfinite(r["capture"]["availability"])
                    and marker["telemetry_recovery_contract"]["profile"]["minimum_telemetry_availability"] <= r["capture"]["availability"] <= 1
                    and isinstance(r["capture"].get("hard_integrity_counters"), dict)
                    and set(r["capture"]["hard_integrity_counters"]) == set(HARD_COUNTERS)
                    and all(type(v) is int and v == 0 for v in r["capture"]["hard_integrity_counters"].values())
                    for r in reports)
    coverage = all(w["valid_scored_hours"] > 0 for w in workloads.values())
    rate_gate = rate is not None and rate <= profile["maximum_alerts_per_workload_hour"]
    passed = (not marker["diagnostic_only"] and integrity and rate_gate
              and all(w["exposure_gate"] and w["rate_gate"] for w in workloads.values()))
    return {"schema": "sentinel-pulse-recovery-formal-report-v1", "run_id": marker["run_id"],
            "marker_sha256": sha256_file(marker_path), "formal_recovery_pass": passed,
            "diagnostic_only": marker["diagnostic_only"],
            "diagnostic_integrity_gate": integrity and coverage and total_alerts == 0,
            "total_valid_workload_hours": total_hours, "all_alerts": total_alerts,
            "all_alerts_per_valid_workload_hour": rate, "workloads": workloads,
            "node_reports_sha256": {r["worker_ip"]: sha256_file(path) for r, path in zip(reports, paths)},
            "legacy_normal_pass": False, "automatic_blind_evaluation": False,
            "automatic_promotion": False, "kernel_to_alert_claim_allowed": False,
            "false_positive_ground_truth_adjudicated": False}


def write_new(path: Path, value: dict):
    with path.open("x") as stream:
        stream.write(json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n")
    path.chmod(0o444)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    register_cli = sub.add_parser("register")
    for name in ("source-root", "model-dir", "policy", "recovery-profile", "dependency-binding", "workers", "output"):
        register_cli.add_argument("--" + name, required=True, type=Path)
    register_cli.add_argument("--run-id", required=True)
    register_cli.add_argument("--duration-seconds", type=int, default=89880)
    register_cli.add_argument("--diagnostic-only", action="store_true")
    node = sub.add_parser("evaluate-node")
    for name in ("run-dir", "marker", "model-manifest", "health-log", "output"):
        node.add_argument("--" + name, type=Path, required=True)
    node.add_argument("--worker-ip", required=True, choices=sorted(WORKERS))
    attestation = sub.add_parser("attest-worker")
    for name in ("source-root", "model-dir", "policy", "marker", "output"):
        attestation.add_argument("--" + name, required=True, type=Path)
    attestation.add_argument("--worker-ip", required=True, choices=sorted(WORKERS))
    fleet = sub.add_parser("aggregate")
    fleet.add_argument("--marker", type=Path, required=True)
    fleet.add_argument("--node-report", type=Path, action="append", required=True)
    fleet.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise ValueError("refusing to overwrite a registration or terminal verdict")
    if args.command == "register":
        result = register(args.run_id, args.source_root, args.model_dir, args.policy, args.recovery_profile,
                          json.loads(args.dependency_binding.read_text()), json.loads(args.workers.read_text()),
                          args.duration_seconds, args.diagnostic_only)
    elif args.command == "evaluate-node":
        result = evaluate_node(args.run_dir, args.marker, args.worker_ip, args.model_manifest, args.health_log)
    elif args.command == "attest-worker":
        result = attest_worker(args.marker, args.worker_ip, args.source_root, args.model_dir, args.policy)
    else:
        result = aggregate(args.marker, args.node_report)
    write_new(args.output, result)
    if args.command == "evaluate-node":
        raise SystemExit(0 if result["valid"] else 1)
    if args.command == "aggregate":
        raise SystemExit(0 if result["formal_recovery_pass"] or (result["diagnostic_only"] and result["diagnostic_integrity_gate"]) else 1)


if __name__ == "__main__":
    main()
