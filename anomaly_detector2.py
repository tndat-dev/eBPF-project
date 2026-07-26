"""
anomaly_detector.py
-------------------
Realtime anomaly detection: kết nối TetragonConsumer → WindowManager → MLModels

Khi phát hiện anomaly → gọi callback (để Operator xử lý isolation)

Chạy:
  python anomaly_detector.py --mode kubectl
  python anomaly_detector.py --mode kubectl --simulate-attack nginx
"""

import logging
import threading
import time
import json
import argparse
import signal
import sys
import os
import numpy as np
from collections import defaultdict
from adaptive_threshold import (load_thresholds, StreamingThreshold,
                                load_calibrators, save_calibrators)
from graph_signals import behavior_signals, evaluate_behavior
from sentinel.telemetry import emit, detection_latency
from dataclasses import dataclass, field
from typing import Callable, List, Optional
from datetime import datetime, timezone

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("detector.log"),
    ]
)
logger = logging.getLogger("anomaly_detector")


# ─────────────────────────────────────────────────────────────────
# FIX: Deployment key resolution
#
# VẤN ĐỀ:
#   Model được lưu theo deployment key (vd: "production/nginx")
#   nhưng live pod_key có full name (vd: "production/nginx-56fcf95486-29lq9").
#   Mỗi lần pod restart suffix thay đổi → không bao giờ tìm được model
#   → no_model = 100% → không detect được gì.
#
# GIẢI PHÁP:
#   get_deployment_key() strip 2 suffix cuối của pod name để lấy
#   deployment name, sau đó resolve_model_key() tìm model tương ứng
#   trong danh sách models đã load.
# ─────────────────────────────────────────────────────────────────

def get_deployment_key(pod_key: str) -> str:
    """
    Chuyển full pod_key → deployment key bằng cách bỏ 2 suffix cuối.

    Ví dụ:
      "production/nginx-56fcf95486-29lq9" → "production/nginx"
      "default/postgres-5cd4775869-sd99s" → "default/postgres"
      "production/redis-5b999654fc-zkc4w" → "production/redis"

    Kubernetes pod name format:
      <deployment>-<replicaset-hash (10 hex)>-<pod-hash (5 alphanum)>
    """
    try:
        ns, pod_name = pod_key.split("/", 1)
        # rsplit từ phải, tối đa 2 lần → bỏ 2 suffix cuối
        parts = pod_name.rsplit("-", 2)
        if len(parts) >= 3:
            return f"{ns}/{parts[0]}"
        return pod_key  # Không có đủ suffix → giữ nguyên (StatefulSet, DaemonSet)
    except ValueError:
        return pod_key


def resolve_model_key(pod_key: str, available_models: List[str]) -> Optional[str]:
    """
    Tìm model key phù hợp cho pod_key trong danh sách available_models.

    Thứ tự ưu tiên:
      1. Exact match (pod_key khớp hoàn toàn)
      2. Deployment match (cùng namespace + deployment name)

    Trả về model_key nếu tìm thấy, None nếu không có model.
    """
    # 1. Exact match
    if pod_key in available_models:
        return pod_key

    # 2. Deployment-level match
    pod_deploy = get_deployment_key(pod_key)
    for model_key in available_models:
        # Model key có thể là deployment key ("production/nginx")
        # hoặc full pod key ("production/nginx-56fcf95486-r6n7g")
        if model_key == pod_deploy:
            return model_key
        if get_deployment_key(model_key) == pod_deploy:
            return model_key

    return None


# ─────────────────────────────────────────────
# AnomalyAlert — kết quả khi phát hiện anomaly
# ─────────────────────────────────────────────

@dataclass
class AnomalyAlert:
    pod_name:       str
    pod_namespace:  str
    node_name:      str
    detected_at:    str           # RFC3339
    ensemble_score: float
    lstm_score:     float
    if_score:       float
    threshold:      float
    top_syscalls:   List[dict]    # [{name, freq, deviation}]
    window_start:   float
    window_end:     float
    detection_latency: Optional[float] = None

    @property
    def pod_key(self) -> str:
        return f"{self.pod_namespace}/{self.pod_name}"

    def to_dict(self) -> dict:
        return {
            "pod_name":       self.pod_name,
            "pod_namespace":  self.pod_namespace,
            "node_name":      self.node_name,
            "detected_at":    self.detected_at,
            "ensemble_score": self.ensemble_score,
            "lstm_score":     self.lstm_score,
            "if_score":       self.if_score,
            "threshold":      self.threshold,
            "top_syscalls":   self.top_syscalls,
            "detection_latency": self.detection_latency,
        }

    def __str__(self) -> str:
        syscalls_str = ", ".join(
            f"{s['name']}({s['freq']:.3f})" for s in self.top_syscalls[:3]
        )
        return (
            f"🚨 ANOMALY: {self.pod_key} | "
            f"score={self.ensemble_score:.4f} "
            f"(lstm={self.lstm_score:.3f}, if={self.if_score:.3f}) | "
            f"top_syscalls=[{syscalls_str}]"
        )


# ─────────────────────────────────────────────
# AnomalyDetector — core detection logic
# ─────────────────────────────────────────────

class AnomalyDetector:
    """
    Nhận FeatureVector từ WindowManager, chạy ML inference,
    và gọi on_alert callback khi phát hiện anomaly.
    """

    def __init__(
        self,
        model_manager,
        on_alert: Optional[Callable[[AnomalyAlert], None]] = None,
        threshold: float = 0.80,
        # Tránh alert lặp lại cho cùng 1 pod trong cooldown_seconds
        cooldown_seconds: int = 300,
    ):
        self.model_manager    = model_manager
        self.on_alert         = on_alert or self._default_alert_handler
        self.threshold        = threshold
        self.thresholds       = load_thresholds(model_manager, minimum=threshold)
        warmup_windows = int(os.environ.get("SENTINEL_WARMUP_WINDOWS", "10"))
        self.calibration_path = os.environ.get("SENTINEL_CALIBRATION", "calibration.json")
        restored = load_calibrators(self.calibration_path, threshold, warmup_windows)
        self.calibrators      = defaultdict(lambda: StreamingThreshold(minimum=threshold, warmup=warmup_windows), restored)
        self._consecutive     = defaultdict(int)
        self.cooldown_seconds = cooldown_seconds

        self._last_alert: dict = {}   # pod_key → timestamp
        self._lock = threading.Lock()
        # Window completion may arrive from both the log-consumer thread and
        # the idle-window flusher. Serialize mutable calibration state and its
        # atomic file snapshot so concurrent workloads cannot lose/corrupt it.
        self._calibration_lock = threading.RLock()
        self._stats = {
            "windows_scored":   0,
            "anomalies_found":  0,
            "pods_no_model":    0,
            "cooldown_skipped": 0,
        }

        # Cache để không log "no model" lặp lại cho cùng 1 pod
        self._no_model_logged: set = set()

    def handle_feature_vector(self, fv):
        """
        Callback cho WindowManager.
        Chạy ML inference và trigger alert nếu anomaly.
        """
        pod_key = fv.pod_key
        self._stats["windows_scored"] += 1

        # ─────────────────────────────────────────────────────────
        # FIX: Resolve model key theo deployment, không dùng exact
        # pod_key để tránh miss khi pod restart đổi suffix.
        # ─────────────────────────────────────────────────────────
        available_models = self.model_manager.list_models()
        model_key = resolve_model_key(pod_key, available_models)

        if model_key is None:
            self._stats["pods_no_model"] += 1
            # Chỉ log lần đầu cho mỗi pod để tránh spam
            if pod_key not in self._no_model_logged:
                deploy_key = get_deployment_key(pod_key)
                logger.debug(
                    f"Không có model cho {pod_key} "
                    f"(deploy_key={deploy_key}), bỏ qua. "
                    f"Available models: {available_models}"
                )
                self._no_model_logged.add(pod_key)
            return

        # Nếu model_key khác pod_key → log để biết đang dùng fallback
        if model_key != pod_key:
            logger.debug(
                f"[MODEL FALLBACK] {pod_key} → dùng model '{model_key}'"
            )

        infer_start = time.perf_counter()
        result = self.model_manager.score(model_key, fv.vector)
        inference_ms = (time.perf_counter() - infer_start) * 1000.0
        if result is None:
            self._stats["pods_no_model"] += 1
            return

        score      = result["ensemble_score"]
        lstm_score = result["lstm_score"]
        if_score   = result["if_score"]
        total_events = fv.total_events()
        behavior_limits = result.get("behavior_limits", {})
        behavior = evaluate_behavior(
            fv.syscall_counts, total_events, behavior_limits
        )
        suspicious_mass = behavior["suspicious_mass"]
        behavior_gate = behavior["gate"]
        ingest_lag = max(0.0, time.time() - fv.window_end)
        emit("inference", pod_key=pod_key, model_key=model_key,
             inference_ms=round(inference_ms, 4), score=score,
             lstm_score=lstm_score, if_score=if_score,
             event_count=total_events,
             ingest_lag_seconds=round(ingest_lag, 4),
             suspicious_mass=round(suspicious_mass, 6),
             behavior_gate=behavior_gate,
             behavior_method=behavior["method"],
             behavior_syscall=behavior["syscall"],
             behavior_frequency=round(behavior["frequency"], 6),
             behavior_limit=round(behavior["limit"], 6),
             behavior_max_ratio=round(behavior["max_ratio"], 6))

        calibrator = self.calibrators[model_key]

        # Bỏ qua window quá ít events — vector quá sparse, IF sẽ flag nhầm
        MIN_EVENTS = int(os.environ.get("SENTINEL_MIN_EVENTS", "100"))
        if total_events < MIN_EVENTS:
            emit("decision", pod_key=pod_key, model_key=model_key,
                 decision="low_event_skip", score=score,
                 event_count=total_events,
                 behavior_gate=behavior_gate,
                 suspicious_mass=round(suspicious_mass, 6))
            logger.debug(
                f"[SKIP] {pod_key}: chỉ {total_events} events "
                f"(cần >= {MIN_EVENTS}), bỏ qua window này"
            )
            return

        # A sudden event-volume collapse usually means a partial Tetragon
        # window or telemetry backpressure, not a behavioral distribution
        # suitable for ML scoring. The guard is half the clean lower-volume
        # tail, so high-load windows cannot raise it and suppress later idle
        # operation.
        with self._calibration_lock:
            learned_minimum_events = (
                calibrator.minimum_event_count
                if calibrator.event_guard_ready else 0
            )
        if learned_minimum_events and total_events < learned_minimum_events:
            emit("decision", pod_key=pod_key, model_key=model_key,
                 decision="collection_quality_skip", score=score,
                 event_count=total_events,
                 learned_minimum_events=learned_minimum_events,
                 behavior_gate=behavior_gate,
                 suspicious_mass=round(suspicious_mass, 6))
            return

        # Log score bình thường
        logger.info(
            f"[SCORE] {pod_key:<45} "
            f"ensemble={score:.4f} "
            f"(lstm={lstm_score:.3f}, if={if_score:.3f}) "
            f"events={total_events}"
        )

        # Score alone is not actionable: normal runtime/model drift can push
        # reconstruction error high. Require an independent kernel signal.
        # A calibration sample must pass *both* gates. In particular, a
        # score-only outlier must never raise the online threshold and hide a
        # later attack (calibration poisoning).
        baseline_threshold = self.thresholds.get(model_key, self.threshold)
        clean_for_calibration = (
            not behavior_gate and score < baseline_threshold
        )
        calibration_state = None
        with self._calibration_lock:
            if clean_for_calibration:
                calibrator.observe(score, total_events)
                save_calibrators(self.calibration_path, self.calibrators)
                if not calibrator.ready:
                    calibration_state = "calibrating"
            elif not behavior_gate and not calibrator.ready:
                calibration_state = "calibration_rejected"
            calibration_windows = len(calibrator.scores)
            threshold = max(baseline_threshold, calibrator.current)
        if calibration_state == "calibrating":
            emit("decision", pod_key=pod_key, model_key=model_key,
                 decision="calibrating", score=score,
                 calibration_windows=calibration_windows,
                 behavior_gate=behavior_gate,
                 suspicious_mass=round(suspicious_mass, 6))
            logger.info(
                f"[CALIBRATING] {model_key}: "
                f"{calibration_windows}/{calibrator.warmup} clean windows"
            )
            return
        if calibration_state == "calibration_rejected":
            emit("decision", pod_key=pod_key, model_key=model_key,
                 decision="calibration_rejected", score=score,
                 baseline_threshold=baseline_threshold,
                 calibration_windows=calibration_windows,
                 behavior_gate=behavior_gate,
                 suspicious_mass=round(suspicious_mass, 6))

        # Per-workload POT threshold plus an independent behavior gate.
        if score < threshold:
            self._consecutive[pod_key] = 0
            emit("decision", pod_key=pod_key, model_key=model_key,
                 decision="normal", score=score, threshold=threshold,
                 behavior_gate=behavior_gate,
                 suspicious_mass=round(suspicious_mass, 6))
            return
        if not behavior_gate:
            logger.info(
                f"[GATED] {pod_key}: score={score:.4f}, "
                f"behavior={behavior['syscall']} "
                f"ratio={behavior['max_ratio']:.3f}"
            )
            self._consecutive[pod_key] = 0
            emit("decision", pod_key=pod_key, model_key=model_key,
                 decision="behavior_gated", score=score, threshold=threshold,
                 behavior_gate=False,
                 behavior_max_ratio=round(behavior["max_ratio"], 6),
                 suspicious_mass=round(suspicious_mass, 6))
            return
        self._consecutive[pod_key] += 1
        if self._consecutive[pod_key] < 2:
            emit("decision", pod_key=pod_key, model_key=model_key,
                 decision="pending_confirmation", score=score,
                 threshold=threshold,
                 behavior_gate=True,
                 behavior_syscall=behavior["syscall"],
                 behavior_max_ratio=round(behavior["max_ratio"], 6),
                 suspicious_mass=round(suspicious_mass, 6), consecutive=1)
            logger.info(f"[PENDING] {pod_key}: score={score:.4f} threshold={threshold:.4f} suspicious_mass={suspicious_mass:.3f} (1/2 windows)")
            return

        # Kiểm tra cooldown
        now = time.time()
        with self._lock:
            last = self._last_alert.get(pod_key, 0)
            if now - last < self.cooldown_seconds:
                remaining = int(self.cooldown_seconds - (now - last))
                logger.warning(
                    f"[COOLDOWN] {pod_key}: alert trong cooldown "
                    f"(còn {remaining}s)"
                )
                self._stats["cooldown_skipped"] += 1
                emit("decision", pod_key=pod_key, model_key=model_key,
                     decision="cooldown", score=score, threshold=threshold,
                     behavior_gate=True,
                     suspicious_mass=round(suspicious_mass, 6))
                return
            self._last_alert[pod_key] = now

        # Tạo AnomalyAlert
        self._stats["anomalies_found"] += 1
        top_syscalls = self._get_top_syscalls(fv)
        alert = AnomalyAlert(
            pod_name=fv.pod_name,
            pod_namespace=fv.pod_namespace,
            node_name=fv.node_name,
            detected_at=datetime.now(timezone.utc).isoformat(),
            ensemble_score=score,
            lstm_score=lstm_score,
            if_score=if_score,
            threshold=threshold,
            top_syscalls=behavior_signals(
                fv.syscall_counts, fv.total_events(), behavior_limits
            ),
            window_start=fv.window_start,
            window_end=fv.window_end,
            detection_latency=detection_latency(pod_key),
        )
        emit("detection", pod_key=pod_key, model_key=model_key,
             detection_latency=alert.detection_latency, score=score,
             threshold=threshold, behavior_gate=True,
             behavior_syscall=behavior["syscall"],
             behavior_max_ratio=round(behavior["max_ratio"], 6),
             suspicious_mass=round(suspicious_mass, 6))

        logger.warning(str(alert))
        try:
            self.on_alert(alert)
        except Exception as e:
            logger.error(f"Lỗi trong on_alert callback: {e}")

    def _get_top_syscalls(self, fv, top_n: int = 5) -> List[dict]:
        """Lấy top N syscalls theo tần suất trong window."""
        sorted_syscalls = sorted(
            fv.syscall_counts.items(),
            key=lambda x: x[1], reverse=True
        )[:top_n]

        total = fv.total_events() or 1
        return [
            {
                "name":  name,
                "freq":  count / total,
                "count": count,
            }
            for name, count in sorted_syscalls
        ]

    def _default_alert_handler(self, alert: AnomalyAlert):
        """Handler mặc định: in ra console và lưu file."""
        alert_data = alert.to_dict()
        alert_json = json.dumps(alert_data, indent=2)

        fname = (
            f"alerts/{alert.pod_namespace}__{alert.pod_name}_"
            f"{int(alert.window_start)}.json"
        )
        import os
        os.makedirs("alerts", exist_ok=True)
        with open(fname, "w") as f:
            f.write(alert_json)
        logger.warning(f"Alert saved: {fname}")

    def get_stats(self) -> dict:
        return dict(self._stats)


# ─────────────────────────────────────────────
# AttackSimulator — inject syscall bất thường
# ─────────────────────────────────────────────

class AttackSimulator:
    """
    Giả lập attack bằng cách inject syscall pattern bất thường
    vào WindowManager — dùng để test model detect được không.
    """

    ATTACK_PROFILES = {
        # S1: Reverse Shell — execve shell + connect bất thường
        "reverse_shell": {
            "execve": 0.50, "connect": 0.35, "read": 0.10, "write": 0.05,
        },
        # S2: Container Escape
        "container_escape": {
            "unshare": 0.30, "mount": 0.30, "clone": 0.20,
            "execve": 0.15, "openat": 0.05,
        },
        # S3: Cryptomining — clone nhiều threads
        "cryptomining": {
            "clone": 0.60, "read": 0.20, "write": 0.15, "execve": 0.05,
        },
        # S4: Privilege Escalation
        "privilege_escalation": {
            "setuid": 0.35, "setgid": 0.25, "capset": 0.20,
            "execve": 0.15, "openat": 0.05,
        },
        # S5: Data Exfiltration
        "data_exfiltration": {
            "openat": 0.40, "read": 0.30, "connect": 0.20,
            "write": 0.05, "execve": 0.05,
        },
    }

    def __init__(self, window_manager, target_pod_key: str, vocab: dict):
        self.window_manager  = window_manager
        self.target_pod_key  = target_pod_key
        self.vocab           = vocab

    def inject(self, attack_type: str, duration_seconds: int = 60):
        """
        Inject attack events vào WindowManager cho target pod.
        """
        if attack_type not in self.ATTACK_PROFILES:
            logger.error(f"Attack type không hợp lệ: {attack_type}")
            logger.error(f"Chọn: {list(self.ATTACK_PROFILES.keys())}")
            return
        from sentinel.telemetry import inject as record_injection
        record_injection(self.target_pod_key, attack_type)

        profile = self.ATTACK_PROFILES[attack_type]
        ns, name = self.target_pod_key.split("/", 1)

        logger.warning(
            f"🔴 INJECT ATTACK: {attack_type} → {self.target_pod_key} "
            f"({duration_seconds}s)"
        )

        import random

        class FakePod:
            def __init__(self, n, ns_): self.name = n; self.namespace = ns_; self.uid = ""
        class FakeProcess:
            def __init__(self): self.pid=9999; self.uid=0; self.binary="/bin/sh"; self.arguments=""; self.parent_exec_id=""; self.exec_id=""
        class FakeEvent:
            def __init__(self, syscall, pod_name, pod_ns, node="k8s-worker2.local"):
                self.pod = FakePod(pod_name, pod_ns)
                self.process = FakeProcess()
                self.syscall_name = syscall
                self.node_name = node
                self.event_type = "process_kprobe"
                self.timestamp = ""

        syscalls = list(profile.keys())
        weights  = [profile[s] for s in syscalls]
        total_w  = sum(weights)
        weights  = [w / total_w for w in weights]

        start = time.time()
        injected = 0
        while time.time() - start < duration_seconds:
            syscall = random.choices(syscalls, weights=weights)[0]
            event   = FakeEvent(syscall, name, ns)
            self.window_manager.handle_event(event)
            injected += 1
            time.sleep(0.05)  # 20 events/s

        logger.warning(
            f"🔴 Attack injection kết thúc: {injected} events injected "
            f"trong {duration_seconds}s"
        )


# ─────────────────────────────────────────────
# Main — chạy detector
# ─────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Realtime Anomaly Detector")
    parser.add_argument("--mode", choices=["kubectl", "file"], default="kubectl")
    parser.add_argument("--window", type=int, default=30,
                        help="Window size giây (mặc định 30)")
    parser.add_argument("--threshold", type=float, default=0.80)
    parser.add_argument("--model-dir", default="models")
    parser.add_argument("--vocab", default="vocab.pkl")
    parser.add_argument("--simulate-attack", default=None,
                        choices=["reverse_shell", "container_escape",
                                 "cryptomining", "privilege_escalation",
                                 "data_exfiltration"],
                        help="Giả lập attack để test model")
    parser.add_argument("--attack-target", default=None,
                        help="pod_key để inject attack (vd: production/nginx-xxx)")
    parser.add_argument("--attack-delay", type=int, default=90,
                        help="Đợi N giây trước khi inject attack (mặc định 90s)")
    parser.add_argument("--duration", type=int, default=0,
                        help="Tự dừng sau N giây (0=chạy mãi)")
    parser.add_argument("--dry-run", action="store_true", default=True,
                        help="Chỉ log, không thực sự gọi K8s API (mặc định)")
    parser.add_argument("--live-response", action="store_true",
                        help="Cho phép responder cordon/quarantine/evict")
    args = parser.parse_args()

    import pickle
    from tetragon_consumer import TetragonConsumer
    from feature_engineering import WindowManager
    from ml_models import ModelManager

    # ─────────────────────────────────────────────────────────────────
    # Load vocab TRƯỚC khi tạo WindowManager và ModelManager.
    # Cả hai phải dùng cùng một vocab để feature vector có cùng
    # số chiều (vocab_size) — tránh lỗi dimension mismatch khi scoring.
    # ─────────────────────────────────────────────────────────────────
    logger.info(f"Loading vocab from {args.vocab}...")
    with open(args.vocab, "rb") as f:
        vocab = pickle.load(f)
    logger.info(f"Vocab loaded: {len(vocab)} features")

    # Load models
    logger.info("Loading ML models...")
    manager = ModelManager(model_dir=args.model_dir, vocab_path=args.vocab)
    manager.load_all()
    models = manager.list_models()
    if not models:
        logger.error("Không có model nào! Chạy ml_models.py trước.")
        sys.exit(1)
    logger.info(f"Loaded models: {models}")

    # ─────────────────────────────────────────────────────────────────
    # FIX: Log deployment key mapping để dễ debug
    # ─────────────────────────────────────────────────────────────────
    logger.info("Deployment key mapping:")
    for m in models:
        logger.info(f"  Model '{m}' → deploy_key='{get_deployment_key(m)}'")

    # Khởi tạo IsolationResponder
    from isolation_responder import IsolationResponder
    responder = IsolationResponder(dry_run=(not args.live_response))

    # Khởi tạo detector
    detector = AnomalyDetector(
        model_manager=manager,
        on_alert=responder.respond,
        threshold=args.threshold,
        cooldown_seconds=120,
    )

    # ─────────────────────────────────────────────────────────────────
    # Truyền vocab vào WindowManager để feature_engineering dùng
    # cùng vocab_index với models đã train — đảm bảo số chiều khớp.
    # ─────────────────────────────────────────────────────────────────
    window_mgr = WindowManager(
        window_seconds=args.window,
        on_feature_vector=detector.handle_feature_vector,
        vocab=vocab,
    )

    # Khởi tạo Consumer
    consumer = TetragonConsumer(mode=args.mode)

    # Graceful shutdown
    stop_event = threading.Event()
    def handle_signal(sig, frame):
        logger.info("Đang dừng detector...")
        stop_event.set()
    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    # Start consumer thread
    consumer_thread = threading.Thread(
        target=consumer.run,
        args=(window_mgr.handle_event,),
        daemon=True,
        name="tetragon-consumer",
    )
    consumer_thread.start()

    # Stats thread
    def print_stats():
        while not stop_event.is_set():
            time.sleep(60)
            stats = detector.get_stats()
            logger.info(
                f"[STATS] windows={stats['windows_scored']} | "
                f"anomalies={stats['anomalies_found']} | "
                f"no_model={stats['pods_no_model']} | "
                f"cooldown={stats['cooldown_skipped']}"
            )
    threading.Thread(target=print_stats, daemon=True).start()

    logger.info("=" * 60)
    logger.info("🟢 Anomaly Detector khởi động")
    logger.info(f"   Window:    {args.window}s")
    logger.info(f"   Threshold: {args.threshold}")
    logger.info(f"   Models:    {len(models)} pods")
    logger.info("=" * 60)

    # Inject attack sau delay (nếu có)
    if args.simulate_attack:
        target = args.attack_target or models[0]
        logger.info(
            f"⏳ Sẽ inject '{args.simulate_attack}' vào {target} "
            f"sau {args.attack_delay}s..."
        )

        def delayed_attack():
            time.sleep(args.attack_delay)
            if stop_event.is_set():
                return
            sim = AttackSimulator(window_mgr, target, vocab)
            sim.inject(args.simulate_attack, duration_seconds=60)

        threading.Thread(target=delayed_attack, daemon=True,
                         name="attack-sim").start()

    # Vòng lặp chính
    start_time = time.time()
    while not stop_event.is_set():
        time.sleep(1)
        if args.duration > 0 and time.time() - start_time >= args.duration:
            logger.info(f"Đã chạy đủ {args.duration}s, tự dừng.")
            break

    logger.info("Detector dừng.")
    consumer.stop()
    stats = detector.get_stats()
    logger.info(f"Final stats: {stats}")


if __name__ == "__main__":
    main()
# Đây là đoạn cần thêm vào hàm score() trong ModelManager:
# Thay vì match exact pod_key, match theo deployment prefix
# vd: "production/nginx-56fcf95486-29lq9" → "production/nginx"
