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
from datetime import datetime, timezone
import numpy as np
from collections import defaultdict

sys.path.insert(0, '.')
from tetragon_consumer import TetragonConsumer
from feature_engineering import WindowManager

# ── Cấu hình ─────────────────────────────────────────────────
COLLECT_MINUTES = int(os.environ.get("COLLECT_MINUTES", "40"))
WINDOW_SECONDS  = int(os.environ.get("WINDOW_SECONDS", "30"))
MIN_EVENTS      = int(os.environ.get("MIN_EVENTS", "20"))
MIN_WINDOWS     = int(os.environ.get("MIN_WINDOWS", "30"))
MAX_WINDOWS     = int(os.environ.get("MAX_WINDOWS_PER_TARGET", "0"))
MIN_COLLECT_MINUTES = int(os.environ.get("MIN_COLLECT_MINUTES", "10"))
OUTPUT_DIR      = os.environ.get("TRAINING_OUTPUT_DIR", "training_data_candidate")
PHASE_NAME      = os.environ.get("BASELINE_PHASE", "unspecified")
VOCAB_PATH      = os.environ.get("SENTINEL_VOCAB", "vocab.pkl")
POLICY_PATH     = os.environ.get("SENTINEL_POLICY")
LOADGEN_PATH    = os.environ.get("SENTINEL_LOADGEN_MANIFEST")
TARGET_NS       = {"production", "default"}
TARGET_DEPLOYS  = {
    item.strip() for item in os.environ.get(
        "BASELINE_TARGETS",
        "production/nginx,production/redis,default/postgres",
    ).split(",") if item.strip()
}

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


def artifact_provenance(path):
    """Return immutable provenance for an experiment-defining artifact."""
    if not path:
        return None
    absolute = os.path.abspath(path)
    digest = hashlib.sha256()
    with open(absolute, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return {"path": absolute, "sha256": digest.hexdigest()}

# ── State ─────────────────────────────────────────────────────
vectors   = defaultdict(list)   # deploy_key → [vector, ...]
metadata  = defaultdict(list)   # deploy_key → row-aligned window metadata
stats     = defaultdict(lambda: {"windows": 0, "events_total": 0, "skipped_low": 0})
lock      = threading.Lock()
targets_ready = threading.Event()


# ── Helper: pod_key → deployment key ─────────────────────────

def get_deploy_key(pod_key: str) -> str:
    """
    'production/nginx-56fcf95486-9t2j9' → 'production/nginx'

    Logic: bỏ 2 suffix cuối nếu đúng format Kubernetes
      <deploy>-<rs_hash(10)>-<pod_hash(5)>
    """
    try:
        ns, name = pod_key.split('/', 1)
        parts = name.split('-')

        # Thử nhận dạng 2 suffix cuối
        if len(parts) >= 3:
            pod_hash = parts[-1]
            rs_hash  = parts[-2]
            # Pod hash: 5 ký tự alphanum
            # RS hash:  10 ký tự alphanum
            if len(pod_hash) == 5 and len(rs_hash) in (9, 10) and \
               pod_hash.isalnum() and rs_hash.isalnum():
                deploy = '-'.join(parts[:-2])
                return f"{ns}/{deploy}"

        # Fallback: bỏ 1 suffix (StatefulSet: postgres-0)
        if len(parts) >= 2 and parts[-1].isdigit():
            deploy = '-'.join(parts[:-1])
            return f"{ns}/{deploy}"

        return pod_key
    except Exception:
        return pod_key


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

    total_events = fv.total_events()

    # Bỏ window quá ít events (noise)
    if total_events < MIN_EVENTS:
        with lock:
            stats[dk]["skipped_low"] += 1
        logger.debug(
            f"[SKIP] {dk}: chỉ {total_events} events (< {MIN_EVENTS}), bỏ qua"
        )
        return

    with lock:
        if MAX_WINDOWS and dk in TARGET_DEPLOYS and len(vectors[dk]) >= MAX_WINDOWS:
            return
        vectors[dk].append(fv.vector.copy())
        metadata[dk].append({
            "phase": PHASE_NAME,
            "window_start": fv.window_start,
            "window_end": fv.window_end,
            "event_count": total_events,
            "syscall_counts": dict(sorted(fv.syscall_counts.items())),
        })
        stats[dk]["windows"]      += 1
        stats[dk]["events_total"] += total_events
        n = stats[dk]["windows"]
        if MAX_WINDOWS and all(
            len(vectors[target]) >= MAX_WINDOWS for target in TARGET_DEPLOYS
        ):
            targets_ready.set()

    # Log mỗi window để theo dõi tiến trình
    marker = "✅" if dk in TARGET_DEPLOYS else "  "
    logger.info(
        f"{marker} [FV] {dk:<35} "
        f"window={n:>3} | events={total_events:>4} | "
        f"total_events={stats[dk]['events_total']:>6}"
    )


# ── Khởi động consumer ────────────────────────────────────────

logger.info("Khởi động WindowManager và TetragonConsumer...")
window_mgr = WindowManager(
    window_seconds=WINDOW_SECONDS,
    vocab=vocab,
    on_feature_vector=on_feature_vector,
)

consumer = TetragonConsumer(mode='kubectl')

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
        targets_ready.wait(timeout=60)

        logger.info(f"\n[{minute}/{COLLECT_MINUTES} phút]")
        all_ready = print_summary()

        # Dừng sớm nếu đã đủ data cho tất cả target pods
        if all_ready and minute >= MIN_COLLECT_MINUTES:
            logger.info("🎉 Đã đủ data cho tất cả target pods! Dừng sớm.")
            break

except KeyboardInterrupt:
    logger.info("\nCtrl+C — dừng collect sớm...")


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
    "phase": PHASE_NAME,
    "window_seconds": WINDOW_SECONDS,
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
    "sensor_health": getattr(consumer.reader, "health", lambda: {})(),
    "targets": {},
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
    digest = hashlib.sha256()
    with open(fname, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    event_counts = [row["event_count"] for row in final_metadata.get(dk, [])]
    manifest["targets"][dk] = {
        "shape": list(X.shape),
        "sha256": digest.hexdigest(),
        "metadata": metadata_name,
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

consumer.stop()
if manifest["sensor_health"].get("backpressure_events", 0):
    logger.error(
        "Baseline invalid: Tetragon reader experienced %d backpressure events",
        manifest["sensor_health"]["backpressure_events"],
    )
    raise SystemExit(3)
if missing_targets:
    raise SystemExit(2)
