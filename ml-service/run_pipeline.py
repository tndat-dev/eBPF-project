"""
run_pipeline.py
---------------
Script tích hợp: chạy toàn bộ pipeline

  Tetragon stream → TetragonConsumer
                  → WindowManager (sliding window 60s)
                  → BaselineManager (lưu Redis, build vocab)

Chạy:
  # Mode kubectl (khuyến nghị)
  python run_pipeline.py --mode kubectl --window 60

  # Mode file (nếu log được mount vào pod)
  python run_pipeline.py --mode file --log-path /var/run/cilium/tetragon/tetragon.log

  # Chỉ collect baseline 24h rồi dừng
  python run_pipeline.py --mode kubectl --baseline-only
"""

import argparse
import logging
import threading
import time
import signal
import sys

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("pipeline.log"),
    ]
)
logger = logging.getLogger("pipeline")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["kubectl", "file"], default="kubectl")
    parser.add_argument("--log-path", default="/var/run/cilium/tetragon/tetragon.log")
    parser.add_argument("--namespace", default="kube-system",
                        help="Namespace của Tetragon pod")
    parser.add_argument("--window", type=int, default=60,
                        help="Kích thước sliding window (giây)")
    parser.add_argument("--redis-host", default="localhost")
    parser.add_argument("--redis-port", type=int, default=6379)
    parser.add_argument("--baseline-only", action="store_true",
                        help="Chỉ chạy baseline collection rồi dừng")
    parser.add_argument("--baseline-hours", type=float, default=24,
                        help="Thời gian baseline (giờ), mặc định 24h")
    args = parser.parse_args()

    # Import các module
    from tetragon_consumer import TetragonConsumer
    from feature_engineering import WindowManager
    from baseline_collector import BaselineManager, get_redis_client

    # Khởi tạo Redis
    redis_client = get_redis_client(args.redis_host, args.redis_port)

    # Khởi tạo BaselineManager
    baseline_mgr = BaselineManager(redis_client=redis_client)

    # Điều chỉnh thời gian baseline nếu cần (cho test nhanh)
    if args.baseline_hours != 24:
        baseline_mgr.collector.BASELINE_PHASE_SECONDS = int(args.baseline_hours * 3600)
        logger.info(f"Baseline phase: {args.baseline_hours}h = "
                    f"{baseline_mgr.collector.BASELINE_PHASE_SECONDS}s")

    # Khởi tạo WindowManager
    window_mgr = WindowManager(
        window_seconds=args.window,
        on_feature_vector=baseline_mgr.handle_feature_vector,
        ignored_namespaces=[
            "kube-system", "kube-public", "kube-node-lease",
            "cilium", "monitoring", "istio-ingress",
        ]
    )

    # Khởi tạo Tetragon Consumer
    consumer = TetragonConsumer(
        mode=args.mode,
        log_path=args.log_path,
        namespace=args.namespace,
    )

    # Graceful shutdown
    stop_event = threading.Event()
    def handle_sigterm(sig, frame):
        logger.info("Nhận SIGTERM/SIGINT, đang dừng...")
        stop_event.set()
    signal.signal(signal.SIGTERM, handle_sigterm)
    signal.signal(signal.SIGINT, handle_sigterm)

    # Thread theo dõi tiến trình baseline
    def monitor_progress():
        while not stop_event.is_set():
            time.sleep(300)  # log mỗi 5 phút
            stats = baseline_mgr.collector.get_stats()
            logger.info(
                f"[PROGRESS] {stats['progress_pct']:.1f}% | "
                f"Windows: {stats['total_windows']} | "
                f"Pods: {stats['pods_seen']} | "
                f"Elapsed: {stats['elapsed_hours']:.2f}h"
            )
            # In top pods theo số windows
            pods = baseline_mgr.collector.list_pods()
            if pods:
                pods_sorted = sorted(pods, key=lambda p: p["window_count"], reverse=True)
                logger.info("Top pods:")
                for p in pods_sorted[:5]:
                    logger.info(
                        f"  {p['pod_namespace']}/{p['pod_name']}: "
                        f"{p['window_count']} windows"
                    )

            # Kiểm tra baseline hoàn thành
            if baseline_mgr.collector.is_baseline_complete():
                logger.info("✅ Baseline phase hoàn thành!")
                training_data = baseline_mgr.finalize()
                logger.info(f"Training data ready cho {len(training_data)} pods.")

                if args.baseline_only:
                    # Lưu training data ra file để dùng cho ML training
                    import pickle, os
                    os.makedirs("training_data", exist_ok=True)
                    for pod_key, X in training_data.items():
                        fname = pod_key.replace("/", "__") + ".npy"
                        import numpy as np
                        np.save(f"training_data/{fname}", X)
                        logger.info(f"Saved: training_data/{fname} shape={X.shape}")
                    stop_event.set()
                break

    monitor_thread = threading.Thread(target=monitor_progress, daemon=True)
    monitor_thread.start()

    # Chạy consumer (blocking)
    try:
        logger.info("="*60)
        logger.info("Pipeline khởi động")
        logger.info(f"  Mode: {args.mode}")
        logger.info(f"  Window: {args.window}s")
        logger.info(f"  Baseline phase: {args.baseline_hours}h")
        logger.info(f"  Redis: {args.redis_host}:{args.redis_port}")
        logger.info("="*60)

        consumer_thread = threading.Thread(
            target=consumer.run,
            args=(window_mgr.handle_event,),
            daemon=True
        )
        consumer_thread.start()

        # Đợi cho đến khi stop
        while not stop_event.is_set():
            time.sleep(1)

    except Exception as e:
        logger.error(f"Lỗi pipeline: {e}", exc_info=True)
    finally:
        logger.info("Pipeline dừng.")
        # Force flush tất cả buffers
        for pod_key in window_mgr.get_active_pods():
            window_mgr.remove_pod(pod_key)
        logger.info(f"Stats cuối: {window_mgr.get_stats()}")


if __name__ == "__main__":
    main()
