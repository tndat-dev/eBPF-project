"""
feature_engineering.py
-----------------------
Sliding window buffer per pod + n-gram frequency vector.

Pipeline:
  SyscallEvent (stream) → PodWindowBuffer → [60s window full] → FeatureVector

Mỗi pod có một buffer riêng. Khi buffer đủ 60 giây,
tạo n-gram frequency vector và push vào hàng đợi để ML inference.
"""

import time
import threading
import logging
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple
import numpy as np
import pickle
import os
from datetime import datetime, timezone

logger = logging.getLogger("feature_engineering")


# ─────────────────────────────────────────────
# Vocabulary — danh sách n-gram từ training data
# ─────────────────────────────────────────────

# Danh sách syscall đã biết trước (từ TracingPolicy của bạn)
# Sẽ được mở rộng khi train trên baseline data thực tế
BASE_SYSCALLS = [
    "execve", "execveat", "connect", "open", "openat",
    "setuid", "setgid", "capset", "unshare", "mount",
    "clone", "clone3", "pivot_root", "ptrace",
    "accept", "bind", "listen",
]

def build_vocabulary(syscall_list: List[str], k: int = 2) -> Dict[str, int]:
    """
    Xây dựng vocabulary từ danh sách syscall names.
    Bao gồm unigram (k=1) và bigram (k=2).

    Returns:
        vocab: dict mapping n-gram string → index
    """
    vocab = {}
    idx = 0
    # Unigrams
    for s in syscall_list:
        if s not in vocab:
            vocab[s] = idx
            idx += 1
    # Bigrams
    for s1 in syscall_list:
        for s2 in syscall_list:
            key = f"{s1}|{s2}"
            if key not in vocab:
                vocab[key] = idx
                idx += 1
    return vocab

# Vocab mặc định từ base syscalls (sẽ được thay bằng vocab từ training data)
DEFAULT_VOCAB = build_vocabulary(BASE_SYSCALLS, k=2)
VOCAB_SIZE = len(DEFAULT_VOCAB)
logger.info(f"Default vocabulary size: {VOCAB_SIZE} features")


def parse_event_time(value, fallback: Optional[float] = None) -> float:
    """Parse Tetragon RFC3339 timestamps, falling back to arrival time."""
    if isinstance(value, (int, float)):
        return float(value)
    if value:
        try:
            parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.timestamp()
        except (TypeError, ValueError, OverflowError):
            pass
    return time.time() if fallback is None else float(fallback)


# ─────────────────────────────────────────────
# FeatureVector — kết quả của 1 window
# ─────────────────────────────────────────────

@dataclass
class FeatureVector:
    pod_name: str
    pod_namespace: str
    node_name: str
    window_start: float   # Unix timestamp
    window_end: float
    vector: np.ndarray    # shape: (VOCAB_SIZE,)
    raw_syscalls: List[str]  # syscall sequence thô trong window
    syscall_counts: Dict[str, int]  # unigram counts (cho RCA)

    @property
    def pod_key(self) -> str:
        return f"{self.pod_namespace}/{self.pod_name}"

    def duration(self) -> float:
        return self.window_end - self.window_start

    def total_events(self) -> int:
        return len(self.raw_syscalls)


def extract_ngram_vector(
    syscall_sequence: List[str],
    vocab: Dict[str, int],
) -> np.ndarray:
    """
    Chuyển đổi syscall sequence → n-gram frequency vector.

    Args:
        syscall_sequence: list các syscall name trong window
        vocab: mapping n-gram → index

    Returns:
        vector: np.ndarray shape (len(vocab),), giá trị normalized [0,1]
    """
    if not syscall_sequence:
        return np.zeros(len(vocab), dtype=np.float32)

    vector = np.zeros(len(vocab), dtype=np.float32)
    n = len(syscall_sequence)

    # Unigrams
    unigram_counts = Counter(syscall_sequence)
    for name, count in unigram_counts.items():
        if name in vocab:
            vector[vocab[name]] = count / n

    # Bigrams
    for i in range(len(syscall_sequence) - 1):
        key = f"{syscall_sequence[i]}|{syscall_sequence[i+1]}"
        if key in vocab:
            vector[vocab[key]] += 1.0 / n

    return vector


# ─────────────────────────────────────────────
# PodWindowBuffer — buffer per pod
# ─────────────────────────────────────────────

class PodWindowBuffer:
    """
    Buffer theo thời gian cho một pod cụ thể.
    Tích lũy SyscallEvent trong window_seconds giây,
    sau đó emit FeatureVector.
    """

    def __init__(
        self,
        pod_name: str,
        pod_namespace: str,
        node_name: str,
        window_seconds: int = 60,
        vocab: Optional[Dict[str, int]] = None,
        on_window_complete: Optional[Callable] = None,
    ):
        self.pod_name = pod_name
        self.pod_namespace = pod_namespace
        self.node_name = node_name
        self.window_seconds = window_seconds
        self.vocab = vocab or DEFAULT_VOCAB
        self.on_window_complete = on_window_complete

        self._syscalls: List[str] = []      # syscall names trong window hiện tại
        self._window_start: Optional[float] = None
        self._last_event_time: Optional[float] = None
        self._last_event_arrival_wall: Optional[float] = None
        self._lock = threading.Lock()

    @property
    def pod_key(self) -> str:
        return f"{self.pod_namespace}/{self.pod_name}"

    def add_event(self, syscall_name: str,
                  event_time: Optional[float] = None) -> Optional[FeatureVector]:
        """
        Thêm một syscall event vào buffer.
        Nếu window đầy → tạo FeatureVector và reset buffer.

        Returns:
            FeatureVector nếu window vừa complete, None nếu chưa.
        """
        arrival_wall = time.time()
        timestamp = arrival_wall if event_time is None else float(event_time)
        completed = None
        with self._lock:
            if self._window_start is None:
                self._window_start = timestamp

            # Close the previous event-time window before assigning the
            # boundary event to the next window. This remains correct even if
            # the log reader is minutes behind wall clock.
            if (
                self._syscalls
                and timestamp - self._window_start >= self.window_seconds
            ):
                boundary = self._window_start + self.window_seconds
                completed = self._flush(window_end=boundary)
                if timestamp - boundary >= self.window_seconds:
                    # Do not materialize empty windows across a long event gap.
                    self._window_start = timestamp

            self._syscalls.append(syscall_name)
            self._last_event_time = timestamp
            self._last_event_arrival_wall = arrival_wall

        if self.on_window_complete and completed:
            self.on_window_complete(completed)
        return completed

    def _flush(self, window_end: float) -> Optional[FeatureVector]:
        """Tạo FeatureVector từ buffer hiện tại và reset."""
        if not self._syscalls or self._window_start is None:
            self._window_start = window_end
            return None

        syscall_counts = dict(Counter(self._syscalls))
        vector = extract_ngram_vector(self._syscalls, self.vocab)

        fv = FeatureVector(
            pod_name=self.pod_name,
            pod_namespace=self.pod_namespace,
            node_name=self.node_name,
            window_start=self._window_start,
            window_end=window_end,
            vector=vector,
            raw_syscalls=list(self._syscalls),
            syscall_counts=syscall_counts,
        )

        # Reset cho window tiếp theo
        self._syscalls = []
        self._window_start = window_end

        logger.debug(
            f"Window complete: {self.pod_key} | "
            f"{fv.total_events()} events | "
            f"vector norm={np.linalg.norm(vector):.4f}"
        )
        return fv

    def idle_flush_due(self, wall_time: Optional[float] = None) -> bool:
        """Whether an event-time buffer has received nothing for one window."""
        now = time.time() if wall_time is None else wall_time
        with self._lock:
            return bool(
                self._syscalls
                and self._last_event_arrival_wall is not None
                and now - self._last_event_arrival_wall >= self.window_seconds
            )

    def force_flush(self, window_end: Optional[float] = None) -> Optional[FeatureVector]:
        """Flush ngay cả khi window chưa đầy (dùng khi pod bị terminate)."""
        with self._lock:
            if self._window_start is None:
                return None
            end = window_end or (self._window_start + self.window_seconds)
            return self._flush(window_end=end)


# ─────────────────────────────────────────────
# WindowManager — quản lý buffer cho toàn bộ cluster
# ─────────────────────────────────────────────

class WindowManager:
    """
    Quản lý PodWindowBuffer cho tất cả pod đang chạy.
    - Tự động tạo buffer mới khi thấy pod mới
    - Đẩy FeatureVector vào callback khi window complete
    - Dọn buffer của pod đã terminate

    Đây là entry point chính từ TetragonConsumer.
    """

    def __init__(
        self,
        window_seconds: int = 60,
        vocab: Optional[Dict[str, int]] = None,
        on_feature_vector: Optional[Callable[[FeatureVector], None]] = None,
        # Namespace bị bỏ qua (system namespaces)
        ignored_namespaces: Optional[List[str]] = None,
    ):
        self.window_seconds = window_seconds
        self.vocab = vocab or DEFAULT_VOCAB
        self.on_feature_vector = on_feature_vector
        self.ignored_namespaces = set(ignored_namespaces or [
            "kube-system", "kube-public", "kube-node-lease",
            "cilium", "monitoring",
        ])

        self._buffers: Dict[str, PodWindowBuffer] = {}
        self._lock = threading.Lock()
        self._stats = defaultdict(int)

        # Background timer: flush tất cả buffers định kỳ
        # không phụ thuộc vào việc có event mới hay không
        self._flush_thread = threading.Thread(
            target=self._background_flush_loop,
            daemon=True,
            name="window-flusher",
        )
        self._flush_thread.start()
        logger.info(f"Background flusher started (window={window_seconds}s, poll<=1s)")

    def _background_flush_loop(self):
        """
        Chạy nền, flush tất cả buffers mỗi window_seconds giây.
        Đảm bảo window luôn được tạo dù pod ít event.
        """
        while True:
            # Poll more frequently than the window boundary. Sleeping for the
            # full window can miss a boundary by milliseconds and delay
            # detection by an entire additional window.
            time.sleep(min(1.0, max(0.1, self.window_seconds / 10)))
            with self._lock:
                pod_keys = list(self._buffers.keys())
            for pod_key in pod_keys:
                try:
                    with self._lock:
                        buf = self._buffers.get(pod_key)
                    if buf:
                        if buf.idle_flush_due():
                            fv = buf.force_flush()
                            if fv and fv.total_events() > 0:
                                self._on_window_complete(fv)
                                logger.debug(
                                    f"[timer-flush] {pod_key}: "
                                    f"{fv.total_events()} events"
                                )
                except Exception as e:
                    logger.error(f"Lỗi background flush {pod_key}: {e}")

    def handle_event(self, event):
        """
        Gọi từ TetragonConsumer callback.
        event: SyscallEvent instance từ tetragon_consumer.py
        """
        # Bỏ qua system namespaces
        if event.pod.namespace in self.ignored_namespaces:
            return

        pod_key = f"{event.pod.namespace}/{event.pod.name}"
        self._stats["total_events"] += 1

        with self._lock:
            if pod_key not in self._buffers:
                logger.info(f"Pod mới phát hiện, tạo buffer: {pod_key}")
                self._buffers[pod_key] = PodWindowBuffer(
                    pod_name=event.pod.name,
                    pod_namespace=event.pod.namespace,
                    node_name=event.node_name,
                    window_seconds=self.window_seconds,
                    vocab=self.vocab,
                    on_window_complete=self._on_window_complete,
                )
            buffer = self._buffers[pod_key]

        event_time = parse_event_time(getattr(event, "timestamp", None))
        buffer.add_event(event.syscall_name, event_time=event_time)

    def _on_window_complete(self, fv: FeatureVector):
        """Được gọi khi một window hoàn thành."""
        self._stats["windows_completed"] += 1
        if self.on_feature_vector:
            try:
                self.on_feature_vector(fv)
            except Exception as e:
                logger.error(f"Lỗi khi xử lý FeatureVector: {e}")

    def remove_pod(self, pod_key: str):
        """Dọn buffer khi pod terminate (gọi từ K8s watcher)."""
        with self._lock:
            if pod_key in self._buffers:
                buf = self._buffers.pop(pod_key)
                fv = buf.force_flush()
                if fv and self.on_feature_vector:
                    self.on_feature_vector(fv)
                logger.info(f"Đã xóa buffer cho pod: {pod_key}")

    def get_active_pods(self) -> List[str]:
        with self._lock:
            return list(self._buffers.keys())

    def get_stats(self) -> dict:
        return dict(self._stats)


# ─────────────────────────────────────────────
# VocabularyBuilder — build vocab từ baseline data
# ─────────────────────────────────────────────

class VocabularyBuilder:
    """
    Thu thập tất cả syscall xuất hiện trong baseline phase
    rồi build vocabulary cho training.
    Lưu vocab vào file để tái sử dụng.
    """

    def __init__(self, vocab_path: str = "vocab.pkl"):
        self.vocab_path = vocab_path
        self._seen_syscalls: set = set()
        self._lock = threading.Lock()

    def observe(self, syscall_names: List[str]):
        with self._lock:
            self._seen_syscalls.update(syscall_names)

    def build(self) -> Dict[str, int]:
        with self._lock:
            vocab = build_vocabulary(sorted(self._seen_syscalls), k=2)
            logger.info(
                f"Vocab built: {len(self._seen_syscalls)} syscalls → "
                f"{len(vocab)} features (unigram+bigram)"
            )
            return vocab

    def save(self, vocab: Optional[Dict[str, int]] = None):
        v = vocab or self.build()
        with open(self.vocab_path, "wb") as f:
            pickle.dump(v, f)
        logger.info(f"Vocab saved: {self.vocab_path}")

    @staticmethod
    def load(vocab_path: str = "vocab.pkl") -> Dict[str, int]:
        with open(vocab_path, "rb") as f:
            vocab = pickle.load(f)
        logger.info(f"Vocab loaded: {len(vocab)} features từ {vocab_path}")
        return vocab


# ─────────────────────────────────────────────
# Test nhanh
# ─────────────────────────────────────────────

if __name__ == "__main__":
    from dataclasses import dataclass

    # Giả lập vài events
    completed_windows = []

    manager = WindowManager(
        window_seconds=5,  # 5 giây cho test nhanh
        on_feature_vector=lambda fv: completed_windows.append(fv)
    )

    # Giả lập SyscallEvent thô
    class FakePod:
        def __init__(self): self.name = "nginx-abc123"; self.namespace = "production"; self.uid = "uid1"
    class FakeProcess:
        def __init__(self): self.pid=100; self.uid=0; self.binary="/usr/bin/curl"; self.arguments=""; self.parent_exec_id=""; self.exec_id=""
    class FakeEvent:
        def __init__(self, syscall):
            self.pod = FakePod(); self.process = FakeProcess()
            self.syscall_name = syscall; self.node_name = "k8s-worker1"
            self.event_type = "process_kprobe"; self.timestamp = ""

    import random
    syscalls = ["execve", "connect", "open", "setuid", "clone"]
    print("Giả lập 100 events trong 6 giây...")
    for i in range(100):
        event = FakeEvent(random.choice(syscalls))
        manager.handle_event(event)
        time.sleep(0.06)  # 100 events × 60ms = 6 giây → 1 window complete

    print(f"\nWindows hoàn thành: {len(completed_windows)}")
    for w in completed_windows:
        print(f"  Pod: {w.pod_key} | Events: {w.total_events()} | "
              f"Duration: {w.duration():.1f}s | "
              f"Top syscalls: {sorted(w.syscall_counts.items(), key=lambda x:-x[1])[:3]}")
        print(f"  Vector shape: {w.vector.shape}, norm: {np.linalg.norm(w.vector):.4f}")
