"""
collect_real_baseline.py
------------------------
Thu thập real Tetragon events để tạo training data cho ML models.

Chạy TRƯỚC khi train models — đảm bảo model học từ traffic thực,
không phải synthetic data.

Cách dùng:
  python3 collect_real_baseline.py

Trước khi chạy, mở 3 terminal bắn traffic:
  Terminal 1 (nginx):
    while true; do curl -s http://nginx.production.svc.cluster.local/ > /dev/null; sleep 0.1; done

  Terminal 2 (redis):
    REDIS_POD=$(kubectl get pod -n production -l app=redis -o jsonpath='{.items[0].metadata.name}')
    while true; do kubectl exec -n production $REDIS_POD -- redis-benchmark -n 1000 -t set,get -q > /dev/null 2>&1; sleep 2; done

  Terminal 3 (postgres):
    PG_POD=$(kubectl get pod -n default -l app=postgres -o jsonpath='{.items[0].metadata.name}')
    while true; do
      kubectl exec -n default $PG_POD -- psql -U postgres -c "SELECT count(*) FROM pg_stat_activity;" > /dev/null 2>&1
      kubectl exec -n default $PG_POD -- pgbench -U postgres -T 5 -c 2 postgres > /dev/null 2>&1
      sleep 3
    done
"""

import sys
import time
import pickle
import os
import threading
import logging
import json
import hashlib
import subprocess
from datetime import datetime, timezone
from pathlib import Path
import numpy as np
from collections import defaultdict

sys.path.insert(0, '.')
from tetragon_consumer import TetragonConsumer
from feature_engineering import WindowManager
from collection_timing import minimum_duration_satisfied, wait_until
from workload_identity import get_deploy_key
from artifact_integrity import artifact_provenance, sha256 as file_sha256
from feature_capture_io import append_capture_row, feature_window_evidence
from validate_feature_capture import validate_capture

# ── Cấu hình ─────────────────────────────────────────────────
COLLECT_MINUTES = int(os.environ.get("COLLECT_MINUTES", "40"))
WINDOW_SECONDS  = int(os.environ.get("WINDOW_SECONDS", "10"))
MIN_EVENTS      = int(os.environ.get("MIN_EVENTS", "20"))
MIN_WINDOWS     = int(os.environ.get("MIN_WINDOWS", "30"))
MAX_WINDOWS     = int(os.environ.get("MAX_WINDOWS_PER_TARGET", "0"))
MIN_COLLECT_MINUTES = int(os.environ.get("MIN_COLLECT_MINUTES", "10"))
OUTPUT_DIR      = os.environ.get("TRAINING_OUTPUT_DIR", "training_data_candidate")
PHASE_NAME      = os.environ.get("BASELINE_PHASE", "unspecified")
VOCAB_PATH      = os.environ.get("SENTINEL_VOCAB", "vocab.pkl")
POLICY_PATH     = os.environ.get("SENTINEL_POLICY")
LOADGEN_PATH    = os.environ.get("SENTINEL_LOADGEN_MANIFEST")
STARTUP_GRACE_SECONDS = float(os.environ.get(
    "SENTINEL_POD_STARTUP_GRACE_SECONDS", "60"
))
POD_REFRESH_SECONDS = float(os.environ.get(
    "SENTINEL_POD_PROVENANCE_REFRESH_SECONDS", "5"
))
TARGET_NS       = {"production", "default"}
TARGET_DEPLOYS  = {
    item.strip() for item in os.environ.get(
        "BASELINE_TARGETS",
        "production/nginx,production/redis,default/postgres",
    ).split(",") if item.strip()
}
FEATURE_CAPTURE_MODE = os.environ.get("SENTINEL_FEATURE_CAPTURE", "off").strip().lower()
FEATURE_CAPTURE_PATH = os.environ.get("SENTINEL_FEATURE_CAPTURE_PATH", "").strip()
FEATURE_CAPTURE_CONTEXT = {
    "release_id": os.environ.get("SENTINEL_CAPTURE_RELEASE_ID", "").strip(),
    "run_id": os.environ.get("SENTINEL_CAPTURE_RUN_ID", "").strip(),
    "phase_id": os.environ.get("SENTINEL_CAPTURE_PHASE_ID", "").strip(),
    "traffic_regime": os.environ.get(
        "SENTINEL_CAPTURE_TRAFFIC_REGIME", ""
    ).strip(),
}
if FEATURE_CAPTURE_MODE not in ("off", "aggregate", "sequence"):
    raise ValueError("SENTINEL_FEATURE_CAPTURE must be off, aggregate, or sequence")
if FEATURE_CAPTURE_MODE != "off":
    if not FEATURE_CAPTURE_PATH:
        raise ValueError("SENTINEL_FEATURE_CAPTURE_PATH is required")
    missing_capture_context = sorted(
        key for key, value in FEATURE_CAPTURE_CONTEXT.items() if not value
    )
    if missing_capture_context:
        raise ValueError(
            f"feature capture context is incomplete: {missing_capture_context}"
        )

# ── Logging ───────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("collect_baseline")

# ── Load vocab ────────────────────────────────────────────────
logger.info("Loading vocab...")
with open(VOCAB_PATH, "rb") as vocab_handle:
    vocab_payload = vocab_handle.read()
vocab = pickle.loads(vocab_payload)
VOCAB_SHA256 = hashlib.sha256(vocab_payload).hexdigest()
logger.info(f"Vocab size: {len(vocab)} features")


# ── State ─────────────────────────────────────────────────────
vectors   = defaultdict(list)   # deploy_key → [vector, ...]
metadata  = defaultdict(list)   # deploy_key → row-aligned window metadata
stats     = defaultdict(lambda: {"windows": 0, "events_total": 0, "skipped_low": 0})
lock      = threading.Lock()
pod_refresh_stop = threading.Event()
pod_started_at = {}
pod_provenance_stats = {
    "refresh_successes": 0,
    "refresh_failures": 0,
    "direct_lookup_failures": 0,
}
pod_cache_lock = threading.Lock()
capture_failures = []


def is_target_event(event) -> bool:
    """Discard unmodelled telemetry before it allocates a feature buffer."""
    pod = getattr(event, "pod", None)
    namespace = getattr(pod, "namespace", None)
    name = getattr(pod, "name", None)
    if not namespace or not name:
        return False
    return get_deploy_key(f"{namespace}/{name}") in TARGET_DEPLOYS


def _parse_kubernetes_timestamp(value):
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()


def refresh_pod_start_cache():
    """Cache creation times before a lifecycle rollout deletes the old pod."""
    try:
        result = subprocess.run(
            ["kubectl", "get", "pods", "-A", "-o", "json"],
            check=True, capture_output=True, text=True, timeout=5,
        )
        discovered = {}
        for item in json.loads(result.stdout).get("items", []):
            metadata_row = item.get("metadata", {})
            namespace = metadata_row.get("namespace")
            name = metadata_row.get("name")
            if not namespace or not name:
                continue
            key = f"{namespace}/{name}"
            if get_deploy_key(key) not in TARGET_DEPLOYS:
                continue
            started = _parse_kubernetes_timestamp(
                metadata_row.get("creationTimestamp")
            )
            if started is not None:
                discovered[key] = started
        with pod_cache_lock:
            pod_started_at.update(discovered)
            pod_provenance_stats["refresh_successes"] += 1
    except (OSError, ValueError, json.JSONDecodeError,
            subprocess.SubprocessError) as exc:
        with pod_cache_lock:
            pod_provenance_stats["refresh_failures"] += 1
        logger.warning("Không refresh được pod creationTimestamp cache: %s", exc)


def pod_cache_refresher():
    refresh_pod_start_cache()
    while not pod_refresh_stop.wait(POD_REFRESH_SECONDS):
        refresh_pod_start_cache()


def get_pod_started_at(pod_key):
    """Return immutable Kubernetes pod age provenance, failing closed."""
    with pod_cache_lock:
        if pod_key in pod_started_at:
            return pod_started_at[pod_key]
    try:
        namespace, name = pod_key.split("/", 1)
        result = subprocess.run(
            ["kubectl", "get", "pod", name, "-n", namespace,
             "-o", "jsonpath={.metadata.creationTimestamp}"],
            check=True, capture_output=True, text=True, timeout=2,
        )
        started = _parse_kubernetes_timestamp(result.stdout.strip())
        if started is not None:
            with pod_cache_lock:
                pod_started_at[pod_key] = started
        return started
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        with pod_cache_lock:
            pod_provenance_stats["direct_lookup_failures"] += 1
        logger.warning("Không lấy được creationTimestamp cho %s: %s", pod_key, exc)
        return None


# ── Feature vector callback ───────────────────────────────────

def on_feature_vector(fv):
    """Nhận FeatureVector từ WindowManager, lưu vào vectors dict."""
    # Chỉ collect namespace target
    if fv.pod_namespace not in TARGET_NS:
        return

    dk = get_deploy_key(fv.pod_key)

    # Bỏ key không hợp lệ
    if not dk or '/' not in dk or dk.endswith('/'):
        return
    if dk not in TARGET_DEPLOYS:
        return

    if FEATURE_CAPTURE_MODE != "off":
        try:
            append_capture_row(
                FEATURE_CAPTURE_PATH, "feature_window", model_key=dk,
                **FEATURE_CAPTURE_CONTEXT,
                **feature_window_evidence(fv, FEATURE_CAPTURE_MODE),
            )
        except Exception as exc:
            with lock:
                capture_failures.append(str(exc))
            logger.exception("Feature capture append failed")

    total_events = fv.total_events()

    # Bỏ window quá ít events (noise)
    if total_events < MIN_EVENTS:
        with lock:
            stats[dk]["skipped_low"] += 1
        logger.debug(
            f"[SKIP] {dk}: chỉ {total_events} events (< {MIN_EVENTS}), bỏ qua"
        )
        return

    started_at = get_pod_started_at(fv.pod_key)
    startup_age_seconds = (
        max(0.0, float(fv.window_end) - started_at)
        if started_at is not None else None
    )
    startup_grace_eligible = bool(
        startup_age_seconds is not None
        and startup_age_seconds < STARTUP_GRACE_SECONDS
    )

    with lock:
        if MAX_WINDOWS and dk in TARGET_DEPLOYS and len(vectors[dk]) >= MAX_WINDOWS:
            return
        vectors[dk].append(fv.vector.copy())
        metadata[dk].append({
            "phase": PHASE_NAME,
            "pod_key": fv.pod_key,
            "pod_creation_timestamp": started_at,
            "startup_age_seconds": startup_age_seconds,
            "startup_grace_eligible": startup_grace_eligible,
            "window_start": fv.window_start,
            "window_end": fv.window_end,
            "event_count": total_events,
            "syscall_counts": dict(sorted(fv.syscall_counts.items())),
        })
        stats[dk]["windows"]      += 1
        stats[dk]["events_total"] += total_events
        n = stats[dk]["windows"]
    # Log mỗi window để theo dõi tiến trình
    marker = "✅" if dk in TARGET_DEPLOYS else "  "
    logger.info(
        f"{marker} [FV] {dk:<35} "
        f"window={n:>3} | events={total_events:>4} | "
        f"total_events={stats[dk]['events_total']:>6}"
    )


# ── Khởi động consumer ────────────────────────────────────────

logger.info("Khởi động WindowManager và TetragonConsumer...")
if STARTUP_GRACE_SECONDS < 0 or POD_REFRESH_SECONDS <= 0:
    raise ValueError("startup grace must be >=0 and pod refresh interval must be >0")
pod_refresh_thread = threading.Thread(
    target=pod_cache_refresher,
    daemon=True,
    name="pod-provenance-refresher",
)
pod_refresh_thread.start()
window_mgr = WindowManager(
    window_seconds=WINDOW_SECONDS,
    vocab=vocab,
    on_feature_vector=on_feature_vector,
)

consumer = TetragonConsumer(mode='kubectl', event_filter=is_target_event)

consumer_thread = threading.Thread(
    target=consumer.run,
    args=(window_mgr.handle_event,),
    daemon=True,
    name="tetragon-consumer",
)
consumer_thread.start()
logger.info(f"Consumer started. Collecting {COLLECT_MINUTES} phút...")
logger.info(f"Window size: {WINDOW_SECONDS}s | Min events/window: {MIN_EVENTS}")
logger.info("=" * 60)
logger.info("Target pods:")
for t in sorted(TARGET_DEPLOYS):
    logger.info(f"  📌 {t}")
logger.info("=" * 60)
if COLLECT_MINUTES < 1 or not 0 <= MIN_COLLECT_MINUTES <= COLLECT_MINUTES:
    raise ValueError(
        "collection duration must satisfy 1 <= COLLECT_MINUTES and "
        "0 <= MIN_COLLECT_MINUTES <= COLLECT_MINUTES"
    )
collection_started_at = datetime.now(timezone.utc)
collection_started_monotonic = time.monotonic()


# ── Vòng lặp collect ──────────────────────────────────────────

def print_summary():
    """In trạng thái hiện tại của tất cả pods đang collect."""
    logger.info("-" * 60)
    logger.info("📊 TRẠNG THÁI HIỆN TẠI:")

    with lock:
        current = {k: dict(v) for k, v in stats.items()}
        current_vectors = {k: len(v) for k, v in vectors.items()}

    if not current:
        logger.info("  (chưa có dữ liệu)")
        return

    all_ok = True
    for dk in sorted(current.keys()):
        n_windows = current_vectors.get(dk, 0)
        n_events  = current[dk]["events_total"]
        n_skip    = current[dk]["skipped_low"]
        status    = "✅" if n_windows >= MIN_WINDOWS else ("⚠️ " if n_windows > 0 else "❌")
        target    = "📌" if dk in TARGET_DEPLOYS else "  "

        if dk in TARGET_DEPLOYS and n_windows < MIN_WINDOWS:
            all_ok = False

        logger.info(
            f"  {status} {target} {dk:<35} "
            f"windows={n_windows:>3}/{MIN_WINDOWS} | "
            f"events={n_events:>6} | skipped={n_skip}"
        )

    # Cảnh báo nếu target pod bị thiếu
    with lock:
        collected_keys = set(vectors.keys())
    missing = TARGET_DEPLOYS - collected_keys
    if missing:
        all_ok = False
        logger.warning(f"⚠️  THIẾU DATA cho: {missing}")
        logger.warning("   → Kiểm tra traffic generation đang chạy không?")
        logger.warning("   → Kiểm tra TetragonConsumer có nhận events không?")

    logger.info("-" * 60)
    return all_ok


try:
    for minute in range(1, COLLECT_MINUTES + 1):
        # Wait against a monotonic wall-clock deadline. ``targets_ready`` is
        # sticky; using Event.wait(60) after it becomes set used to collapse a
        # requested 72-minute capture into roughly three minutes.
        minute_deadline = collection_started_monotonic + minute * 60.0
        wait_until(minute_deadline)

        logger.info(f"\n[{minute}/{COLLECT_MINUTES} phút]")
        all_ready = print_summary()

        # Dừng sớm nếu đã đủ data cho tất cả target pods
        if all_ready and minute >= MIN_COLLECT_MINUTES:
            logger.info("🎉 Đã đủ data cho tất cả target pods! Dừng sớm.")
            break

except KeyboardInterrupt:
    logger.info("\nCtrl+C — dừng collect sớm...")


# Freeze sensor and provenance state before snapshotting arrays/manifests.  A
# late stream failure during artifact serialization must not escape the health
# contract, and callbacks must not mutate row-aligned data while it is copied.
consumer.stop()
consumer_thread.join(timeout=10)
pod_refresh_stop.set()
pod_refresh_thread.join(timeout=max(1.0, POD_REFRESH_SECONDS + 1.0))
if consumer_thread.is_alive() or pod_refresh_thread.is_alive():
    logger.error("Baseline invalid: collector thread did not stop cleanly")
    raise SystemExit(5)
collection_ended_at = datetime.now(timezone.utc)
actual_duration_seconds = time.monotonic() - collection_started_monotonic


# ── Lưu file ──────────────────────────────────────────────────

logger.info("\n" + "=" * 60)
logger.info("💾 LƯU TRAINING DATA:")
logger.info("=" * 60)

os.makedirs(OUTPUT_DIR, exist_ok=True)

saved   = 0
skipped = 0

with lock:
    final_vectors = {k: list(v) for k, v in vectors.items()}
    final_metadata = {k: list(v) for k, v in metadata.items()}

manifest = {
    "created_at": datetime.now(timezone.utc).isoformat(),
    "collection_started_at": collection_started_at.isoformat(),
    "collection_ended_at": collection_ended_at.isoformat(),
    "requested_duration_seconds": COLLECT_MINUTES * 60,
    "minimum_duration_seconds": MIN_COLLECT_MINUTES * 60,
    "actual_duration_seconds": round(actual_duration_seconds, 6),
    "minimum_duration_satisfied": minimum_duration_satisfied(
        actual_duration_seconds, MIN_COLLECT_MINUTES * 60
    ),
    "phase": PHASE_NAME,
    "window_seconds": WINDOW_SECONDS,
    "consumer_target_filter": True,
    "minimum_events": MIN_EVENTS,
    "minimum_windows": MIN_WINDOWS,
    "maximum_windows_per_target": MAX_WINDOWS or None,
    "vocabulary": {
        "path": os.path.abspath(VOCAB_PATH),
        "sha256": VOCAB_SHA256,
        "size": len(vocab),
    },
    "experiment_artifacts": {
        "tetragon_policy": artifact_provenance(POLICY_PATH),
        "loadgen_manifest": artifact_provenance(LOADGEN_PATH),
    },
    "startup_provenance": {
        "method": "kubernetes_metadata_creationTimestamp",
        "startup_grace_seconds": STARTUP_GRACE_SECONDS,
        "refresh_seconds": POD_REFRESH_SECONDS,
        "fail_closed": True,
        **pod_provenance_stats,
    },
    "sensor_health": getattr(consumer.reader, "health", lambda: {})(),
    "targets": {},
}
capture_validation = None
if FEATURE_CAPTURE_MODE != "off":
    capture_path = os.path.abspath(FEATURE_CAPTURE_PATH)
    if Path(capture_path).is_file():
        capture_validation = validate_capture(Path(capture_path))
    else:
        capture_validation = {
            "valid": False,
            "errors": ["capture file was not created"],
            "feature_windows": 0,
        }
    manifest["paired_feature_capture"] = {
        "path": capture_path,
        "sha256": (
            file_sha256(capture_path) if Path(capture_path).is_file() else None
        ),
        "mode": FEATURE_CAPTURE_MODE,
        "context": FEATURE_CAPTURE_CONTEXT,
        "append_failures": list(capture_failures),
        "validation": capture_validation,
    }

for dk, vecs in sorted(final_vectors.items()):
    n = len(vecs)
    if n < MIN_WINDOWS:
        logger.warning(
            f"⚠️  {dk}: chỉ {n} windows (cần {MIN_WINDOWS}) → BỎ QUA"
        )
        skipped += 1
        continue

    X     = np.array(vecs, dtype=np.float32)
    fname = f"{OUTPUT_DIR}/{dk.replace('/', '__')}.npy"
    np.save(fname, X)
    metadata_name = f"{OUTPUT_DIR}/{dk.replace('/', '__')}_metadata.jsonl"
    with open(metadata_name, "w") as handle:
        for row in final_metadata.get(dk, []):
            handle.write(json.dumps(row, sort_keys=True) + "\n")
    event_counts = [row["event_count"] for row in final_metadata.get(dk, [])]
    manifest["targets"][dk] = {
        "shape": list(X.shape),
        "sha256": file_sha256(fname),
        "metadata": metadata_name,
        "metadata_sha256": file_sha256(metadata_name),
        "event_count_min": min(event_counts),
        "event_count_median": float(np.median(event_counts)),
        "event_count_max": max(event_counts),
    }
    logger.info(f"✅ {dk}: shape={X.shape} → {fname}")
    saved += 1

with open(f"{OUTPUT_DIR}/collection_manifest.json", "w") as handle:
    json.dump(manifest, handle, indent=2, sort_keys=True)
    handle.write("\n")

logger.info("=" * 60)
logger.info(f"Saved: {saved} pods | Skipped: {skipped} pods")

if saved == 0:
    logger.error("❌ Không lưu được file nào!")
    logger.error("   Nguyên nhân có thể:")
    logger.error("   1. Không có traffic → chạy traffic generation trước")
    logger.error("   2. TetragonConsumer không nhận events → kiểm tra Tetragon pods")
    logger.error("   3. Collect thời gian quá ngắn → chạy lại lâu hơn")
else:
    logger.info(f"\n✅ Bước tiếp theo:")
    logger.info(f"   python3 ml_models.py")
    logger.info(f"   python3 anomaly_detector2.py --mode kubectl --threshold 0.90")

# ── Kiểm tra target pods ──────────────────────────────────────
missing_targets = TARGET_DEPLOYS - set(
    dk for dk, vecs in final_vectors.items() if len(vecs) >= MIN_WINDOWS
)
if missing_targets:
    logger.warning(f"\n⚠️  THIẾU model cho: {missing_targets}")
    logger.warning("   Các pod này sẽ không được detect anomaly!")
    logger.warning("   → Cần bắn thêm traffic và collect lại")

sensor_health = manifest["sensor_health"]
continuity_failures = (
    int(sensor_health.get("membership_failures", 0))
    + int(sensor_health.get("coverage_failures", 0))
    + int(sensor_health.get("stream_failures", 0))
)
if sensor_health.get("backpressure_events", 0):
    logger.error(
        "Baseline invalid: Tetragon reader experienced %d backpressure events",
        manifest["sensor_health"]["backpressure_events"],
    )
    raise SystemExit(3)
if continuity_failures:
    logger.error(
        "Baseline invalid: sensor continuity failed "
        "(membership_failures=%d coverage_failures=%d stream_failures=%d)",
        sensor_health.get("membership_failures", 0),
        sensor_health.get("coverage_failures", 0),
        sensor_health.get("stream_failures", 0),
    )
    raise SystemExit(4)
if (
    sensor_health.get("require_full_coverage")
    and not sensor_health.get("coverage_healthy")
):
    logger.error("Baseline invalid: full Tetragon coverage was not healthy at exit")
    raise SystemExit(4)
if missing_targets:
    raise SystemExit(2)
if capture_validation is not None and (
    capture_failures or not capture_validation["valid"]
):
    logger.error(
        "Baseline invalid: paired feature capture failed: append=%s validation=%s",
        capture_failures, capture_validation["errors"],
    )
    raise SystemExit(7)
if not manifest["minimum_duration_satisfied"]:
    logger.error(
        "Baseline invalid: actual duration %.3fs is shorter than minimum %ds",
        actual_duration_seconds, MIN_COLLECT_MINUTES * 60,
    )
    raise SystemExit(6)
