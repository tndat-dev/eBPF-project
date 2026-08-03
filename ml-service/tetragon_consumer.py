"""
tetragon_consumer.py
--------------------
Đọc event stream từ Tetragon (qua JSON log export) và parse ra
structured SyscallEvent theo từng pod.

Cách Tetragon export event:
  kubectl exec -n kube-system <tetragon-pod> -c tetragon -- \
    cat /var/run/cilium/tetragon/tetragon.log

Chạy consumer:
  python tetragon_consumer.py --mode file   # đọc từ log file trực tiếp
  python tetragon_consumer.py --mode kubectl # exec vào pod Tetragon
"""

import json
import subprocess
import sys
import time
import logging
from dataclasses import dataclass, field
from typing import Callable, Optional, Generator
import argparse
import threading
import os
import queue
from datetime import datetime, timezone

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("tetragon_consumer")


# ─────────────────────────────────────────────
# Data classes — cấu trúc event sau khi parse
# ─────────────────────────────────────────────

@dataclass
class PodInfo:
    name: str
    namespace: str
    uid: str = ""

@dataclass
class ProcessInfo:
    pid: int
    uid: int
    binary: str           # e.g. "/usr/bin/curl"
    arguments: str        # e.g. "google.com"
    parent_exec_id: str   # dùng để reconstruct process tree ở RCA
    exec_id: str

@dataclass
class SyscallEvent:
    """Event đã được parse, gắn nhãn pod và syscall name."""
    event_type: str         # "process_exec" | "process_kprobe"
    syscall_name: str       # e.g. "execve", "connect", "open"
    pod: PodInfo
    process: ProcessInfo
    timestamp: str          # RFC3339
    node_name: str


# ─────────────────────────────────────────────
# Parser — convert raw Tetragon JSON → SyscallEvent
# ─────────────────────────────────────────────

class TetragonEventParser:
    """
    Tetragon export 2 loại event chính:
      - process_exec: khi một process mới được execve'd
      - process_kprobe: khi kprobe hook được kích hoạt (sys_connect, sys_open, ...)

    Mapping kprobe function_name → syscall name thân thiện:
    """

    KPROBE_SYSCALL_MAP = {
        # Tetragon trên x86_64 dùng prefix __x64_sys_
        "__x64_sys_execve":    "execve",
        "__x64_sys_execveat":  "execveat",
        "__x64_sys_connect":   "connect",
        "__x64_sys_open":      "open",
        "__x64_sys_openat":    "openat",
        "__x64_sys_read":      "read",
        "__x64_sys_write":     "write",
        # Nginx's event loop commonly emits response buffers through writev
        # rather than write.  Normalize the vectored variant to the existing
        # ``write`` feature so a hardened Nginx profile remains compatible
        # with the versioned vocabulary while still contributing telemetry.
        "__x64_sys_writev":    "write",
        "__x64_sys_close":     "close",
        "__x64_sys_setuid":    "setuid",
        "__x64_sys_setgid":    "setgid",
        "__x64_sys_capset":    "capset",
        "__x64_sys_unshare":   "unshare",
        "__x64_sys_mount":     "mount",
        "__x64_sys_clone":     "clone",
        "__x64_sys_clone3":    "clone3",
        "__x64_sys_pivot_root":"pivot_root",
        "__x64_sys_ptrace":    "ptrace",
        "__x64_sys_accept":    "accept",
        "__x64_sys_accept4":   "accept",
        "__x64_sys_bind":      "bind",
        "__x64_sys_listen":    "listen",
        # Fallback không có prefix (ARM64 hoặc kernel cũ)
        "sys_execve":    "execve",
        "sys_connect":   "connect",
        "sys_open":      "open",
        "sys_openat":    "openat",
        "sys_read":      "read",
        "sys_write":     "write",
        "sys_writev":    "write",
        "sys_close":     "close",
        "sys_setuid":    "setuid",
        "sys_setgid":    "setgid",
        "sys_capset":    "capset",
        "sys_unshare":   "unshare",
        "sys_mount":     "mount",
        "sys_clone":     "clone",
        "sys_pivot_root":"pivot_root",
        "sys_ptrace":    "ptrace",
        "sys_accept":    "accept",
        "sys_accept4":   "accept",
    }

    def parse_line(self, raw_line: str) -> Optional[SyscallEvent]:
        """Parse một dòng JSON từ Tetragon log. Trả về None nếu không parse được."""
        raw_line = raw_line.strip()
        if not raw_line:
            return None
        try:
            data = json.loads(raw_line)
        except json.JSONDecodeError:
            return None

        # Xác định loại event
        if "process_exec" in data:
            return self._parse_exec_event(data)
        elif "process_kprobe" in data:
            return self._parse_kprobe_event(data)
        return None

    def _extract_pod_and_process(self, proc_dict: dict) -> tuple[Optional[PodInfo], Optional[ProcessInfo]]:
        """Trích xuất PodInfo và ProcessInfo từ process dict."""
        pod_dict = proc_dict.get("pod")
        if not pod_dict:
            # Event không có pod context (process hệ thống) → bỏ qua
            return None, None

        pod = PodInfo(
            name=pod_dict.get("name", ""),
            namespace=pod_dict.get("namespace", "default"),
            uid=pod_dict.get("uid", ""),
        )

        process = ProcessInfo(
            pid=proc_dict.get("pid", 0),
            uid=proc_dict.get("uid", 0),
            binary=proc_dict.get("binary", ""),
            arguments=proc_dict.get("arguments", ""),
            parent_exec_id=proc_dict.get("parent_exec_id", ""),
            exec_id=proc_dict.get("exec_id", ""),
        )
        return pod, process

    def _parse_exec_event(self, data: dict) -> Optional[SyscallEvent]:
        """parse process_exec event → syscall 'execve'."""
        exec_data = data["process_exec"]
        proc_dict = exec_data.get("process", {})
        pod, process = self._extract_pod_and_process(proc_dict)
        if not pod:
            return None

        return SyscallEvent(
            event_type="process_exec",
            syscall_name="execve",
            pod=pod,
            process=process,
            timestamp=data.get("time", ""),
            node_name=exec_data.get("node_name", data.get("node_name", "")),
        )

    def _parse_kprobe_event(self, data: dict) -> Optional[SyscallEvent]:
        """parse process_kprobe event → syscall tương ứng."""
        kprobe_data = data["process_kprobe"]
        func_name = kprobe_data.get("function_name", "")
        syscall_name = self.KPROBE_SYSCALL_MAP.get(func_name)
        if not syscall_name:
            # kprobe không trong danh sách quan tâm
            return None

        proc_dict = kprobe_data.get("process", {})
        pod, process = self._extract_pod_and_process(proc_dict)
        if not pod:
            return None

        return SyscallEvent(
            event_type="process_kprobe",
            syscall_name=syscall_name,
            pod=pod,
            process=process,
            timestamp=data.get("time", ""),
            node_name=kprobe_data.get("node_name", data.get("node_name", "")),
        )


# ─────────────────────────────────────────────
# Reader — sinh ra raw JSON lines từ nhiều nguồn
# ─────────────────────────────────────────────

class TetragonLogFileReader:
    """
    Đọc Tetragon log file trực tiếp trên máy worker node.
    Dùng khi ML Service chạy trên cùng node hoặc log được mount vào pod.
    """
    def __init__(self, log_path: str = "/var/run/cilium/tetragon/tetragon.log"):
        self.log_path = log_path

    def stream(self) -> Generator[str, None, None]:
        logger.info(f"Đọc log từ file: {self.log_path}")
        with open(self.log_path, "r") as f:
            # Seek về cuối file để chỉ đọc event mới
            f.seek(0, 2)
            while True:
                line = f.readline()
                if line:
                    yield line
                else:
                    time.sleep(0.05)


class TetragonKubectlReader:
    """
    Đọc Tetragon log từ TẤT CẢ Tetragon pods ready song song (1 pod/node được
    DaemonSet schedule).
    
    Với 2 worker nodes → 2 Tetragon pods → 2 luồng đọc song song.
    Tất cả events được gộp vào 1 queue chung.
    
    Yêu cầu: kubectl được cấu hình đúng context.
    """
    def __init__(self, namespace: str = "kube-system", container: str = "tetragon",
                 log_path: str = "/var/run/cilium/tetragon/tetragon.log"):
        self.namespace = namespace
        self.container = container
        self.log_path = log_path
        self._queue = queue.Queue(
            maxsize=int(os.environ.get("SENTINEL_QUEUE_SIZE", "100000"))
        )
        self._stop_event = threading.Event()
        self._procs: dict[str, set[subprocess.Popen]] = {}
        self._procs_lock = threading.Lock()
        self._membership_lock = threading.Lock()
        self._threads: dict[str, threading.Thread] = {}
        self._active_pods: set[str] = set()
        self._refresh_seconds = float(
            os.environ.get("SENTINEL_TETRAGON_REFRESH_SECONDS", "15")
        )
        self._last_refresh = 0.0
        self._backpressure_events = 0
        self._membership_refreshes = 0
        self._membership_failures = 0
        self._coverage_failures = 0
        self._stream_failures = 0
        self._stream_failure_details: list[dict] = []
        self._stale_streams_removed = 0
        # Production must not make an ML decision from a partial sensor set.
        # Keep the library default permissive for one-node/file-based tests;
        # the systemd unit explicitly enables this gate for the live detector.
        self._require_full_coverage = os.environ.get(
            "SENTINEL_REQUIRE_FULL_TETRAGON_COVERAGE", "false"
        ).strip().lower() in {"1", "true", "yes", "on"}
        self._daemonset_name = os.environ.get(
            "SENTINEL_TETRAGON_DAEMONSET", "tetragon"
        )
        self._ready_tetragon_pods: set[str] = set()
        self._expected_tetragon_pods: Optional[int] = None
        self._coverage_healthy = not self._require_full_coverage

    def _get_all_tetragon_pods(self, *, announce: bool = True) -> list[str]:
        """Lấy tên pod Tetragon có container sensor thực sự ready.

        ``status.phase=Running`` không đủ: pod có thể hiện
        ``ContainerStatusUnknown`` trong khi kubelet/container runtime đang
        lỗi. Streaming từ pod đó sẽ retry ``kubectl exec`` vô ích và, tệ hơn,
        khiến detector ngộ nhận telemetry đã phủ đủ node.
        """
        result = subprocess.run(
            ["kubectl", "get", "pods", "-n", self.namespace,
             "-l", "app.kubernetes.io/name=tetragon", "-o", "json"],
            capture_output=True, text=True, check=True
        )
        payload = json.loads(result.stdout)
        pods = []
        for item in payload.get("items", []):
            metadata = item.get("metadata", {})
            status = item.get("status", {})
            if (metadata.get("deletionTimestamp")
                    or status.get("phase") != "Running"):
                continue
            container_status = next(
                (entry for entry in status.get("containerStatuses", [])
                 if entry.get("name") == self.container),
                None,
            )
            if container_status and container_status.get("ready") is True:
                pods.append(metadata["name"])
        pods.sort()
        if not pods:
            raise RuntimeError("Không tìm thấy pod Tetragon ready nào!")
        if announce:
            logger.info("Tìm thấy %d Tetragon pod ready: %s", len(pods), pods)
        return pods

    def _get_expected_tetragon_pod_count(self) -> int:
        """Read DaemonSet desired scheduling count for the coverage gate."""
        result = subprocess.run(
            ["kubectl", "get", "daemonset", self._daemonset_name,
             "-n", self.namespace,
             "-o", "jsonpath={.status.desiredNumberScheduled}"],
            capture_output=True, text=True, check=True,
        )
        expected = int(result.stdout.strip())
        if expected <= 0:
            raise RuntimeError(
                f"DaemonSet {self._daemonset_name} has invalid desired count {expected}"
            )
        return expected

    def _clear_queued_events(self):
        """Discard events captured before coverage was lost; never score them."""
        while True:
            try:
                self._queue.get_nowait()
            except queue.Empty:
                return

    def _pod_is_active(self, pod_name: str) -> bool:
        with self._membership_lock:
            return pod_name in self._active_pods

    def _terminate_pod_processes(self, pod_name: str):
        """Stop only stale kubectl streams; never interrupt healthy nodes."""
        with self._procs_lock:
            procs = list(self._procs.get(pod_name, set()))
        for proc in procs:
            if proc.poll() is None:
                proc.terminate()

    def _start_pod_thread(self, pod_name: str):
        thread = threading.Thread(
            target=self._stream_one_pod,
            args=(pod_name,),
            daemon=True,
            name=f"reader-{pod_name}",
        )
        self._threads[pod_name] = thread
        thread.start()
        logger.info("Thread started cho pod: %s", pod_name)

    def _reconcile_pods(self, *, initial: bool = False) -> bool:
        """Track DaemonSet rollovers so removed pods cannot retry forever."""
        try:
            ready_pods = set(self._get_all_tetragon_pods(announce=initial))
            expected = (
                self._get_expected_tetragon_pod_count()
                if self._require_full_coverage else None
            )
        except Exception as exc:
            self._membership_failures += 1
            logger.error("Chưa lấy được pod list: %s", exc)
            if self._require_full_coverage:
                with self._membership_lock:
                    previous = set(self._active_pods)
                    self._active_pods = set()
                    self._ready_tetragon_pods = set()
                    self._expected_tetragon_pods = None
                    self._coverage_healthy = False
                for pod_name in previous:
                    self._terminate_pod_processes(pod_name)
                self._clear_queued_events()
            return False

        coverage_healthy = (
            not self._require_full_coverage
            or (expected is not None and len(ready_pods) == expected)
        )
        discovered = ready_pods if coverage_healthy else set()
        if not coverage_healthy:
            self._coverage_failures += 1
            logger.error(
                "Tetragon coverage incomplete: ready=%d desired=%d; "
                "pausing ML ingestion and decisions",
                len(ready_pods), expected,
            )

        with self._membership_lock:
            previous = set(self._active_pods)
            removed = previous - discovered
            added = discovered - previous
            self._active_pods = discovered
            self._membership_refreshes += 1
            self._last_refresh = time.monotonic()
            self._ready_tetragon_pods = ready_pods
            self._expected_tetragon_pods = expected
            self._coverage_healthy = coverage_healthy
            for pod_name, thread in list(self._threads.items()):
                if not thread.is_alive() and pod_name not in discovered:
                    self._threads.pop(pod_name, None)
            for pod_name in removed:
                self._threads.pop(pod_name, None)
            start = [
                pod_name for pod_name in sorted(added)
                if pod_name not in self._threads or not self._threads[pod_name].is_alive()
            ]

        for pod_name in removed:
            self._terminate_pod_processes(pod_name)
        if not coverage_healthy:
            self._clear_queued_events()
        if removed:
            self._stale_streams_removed += len(removed)
        for pod_name in start:
            self._start_pod_thread(pod_name)
        if added or removed:
            logger.info(
                "Tetragon membership refreshed: added=%s removed=%s",
                sorted(added), sorted(removed),
            )
        return bool(discovered) and coverage_healthy

    def _stream_one_pod(self, pod_name: str):
        """
        Luồng riêng cho từng Tetragon pod.
        Lọc bỏ kube-system events tại source để tránh ngập queue.
        Dùng tail -n 0 để bỏ qua log cũ, chỉ đọc events mới.
        """
        SKIP_NAMESPACES = {
            "kube-system", "kube-public", "kube-node-lease",
            "cilium", "monitoring",
        }
        while not self._stop_event.is_set() and self._pod_is_active(pod_name):
            try:
                cmd = [
                    "kubectl", "exec", "-n", self.namespace,
                    pod_name, "-c", self.container, "--",
                    # -F follows the filename across Tetragon log rotation;
                    # -f would silently remain attached to the old inode.
                    "tail", "-n", "0", "-F", self.log_path
                ]
                logger.info(f"[{pod_name}] Bắt đầu đọc log (skip old entries)...")
                proc = subprocess.Popen(
                    cmd, stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL, text=True, bufsize=1
                )
                with self._procs_lock:
                    self._procs.setdefault(pod_name, set()).add(proc)
                for line in proc.stdout:
                    if self._stop_event.is_set():
                        break
                    # Lọc nhanh bằng string match trước khi parse JSON
                    should_skip = any(
                        f'"namespace":"{ns}"' in line for ns in SKIP_NAMESPACES
                    )
                    if should_skip:
                        continue
                    # Never silently drop security events. Backpressure the
                    # per-node reader and surface saturation as sensor health.
                    while not self._stop_event.is_set():
                        try:
                            self._queue.put(line, timeout=0.25)
                            break
                        except queue.Full:
                            self._backpressure_events += 1
                            if self._backpressure_events % 100 == 1:
                                logger.error(
                                    "[%s] event queue saturated: size=%d "
                                    "backpressure_events=%d",
                                    pod_name, self._queue.qsize(),
                                    self._backpressure_events,
                                )
                proc.wait()
                with self._procs_lock:
                    self._procs.get(pod_name, set()).discard(proc)
                if (not self._stop_event.is_set()
                        and self._pod_is_active(pod_name)):
                    self._record_stream_failure(
                        pod_name, "kubectl_exec_exit", returncode=proc.returncode,
                    )
                    logger.warning(f"[{pod_name}] kubectl exec kết thúc, retry sau 5s...")
            except Exception as e:
                if (not self._stop_event.is_set()
                        and self._pod_is_active(pod_name)):
                    self._record_stream_failure(
                        pod_name, "reader_exception", error=repr(e),
                    )
                    logger.error(f"[{pod_name}] Lỗi: {e}, retry sau 5s...")
            self._stop_event.wait(5)

    def _record_stream_failure(self, pod_name: str, kind: str, **details):
        """Keep bounded provenance for continuity failures, not only a count."""
        self._stream_failures += 1
        self._stream_failure_details.append({
            "observed_at": datetime.now(timezone.utc).isoformat(),
            "pod": pod_name,
            "kind": kind,
            "retry_seconds": 5,
            **details,
        })
        # A long-lived detector must remain memory bounded during an outage.
        del self._stream_failure_details[:-100]

    def stop(self):
        """Stop readers and reap all kubectl-exec child processes."""
        self._stop_event.set()
        with self._procs_lock:
            procs = [proc for group in self._procs.values() for proc in group]
        for proc in procs:
            if proc.poll() is None:
                proc.terminate()
        for proc in procs:
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=1)

    def health(self) -> dict:
        return {
            "queue_size": self._queue.qsize(),
            "queue_capacity": self._queue.maxsize,
            "backpressure_events": self._backpressure_events,
            "membership_refreshes": self._membership_refreshes,
            "membership_failures": self._membership_failures,
            "coverage_failures": self._coverage_failures,
            "stream_failures": self._stream_failures,
            "stream_failure_details": list(self._stream_failure_details),
            "stale_streams_removed": self._stale_streams_removed,
            "active_tetragon_pods": sorted(self._active_pods),
            "ready_tetragon_pods": sorted(self._ready_tetragon_pods),
            "expected_tetragon_pods": self._expected_tetragon_pods,
            "require_full_coverage": self._require_full_coverage,
            "coverage_healthy": self._coverage_healthy,
        }

    def stream(self) -> Generator[str, None, None]:
        """
        Khởi động 1 thread/pod, gộp tất cả vào queue rồi yield ra.
        """
        # Discover membership first, then refresh it periodically. A DaemonSet
        # pod can be recreated while the detector stays up; retaining a static
        # pod list would otherwise create an endless retry on the deleted pod.
        while not self._stop_event.is_set():
            if self._reconcile_pods(initial=True):
                break
            self._stop_event.wait(5)
        if not self._active_pods:
            return

        logger.info("Đang đọc từ %d nodes song song...", len(self._active_pods))

        # Yield từ queue chung (blocking)
        while not self._stop_event.is_set():
            if time.monotonic() - self._last_refresh >= self._refresh_seconds:
                self._reconcile_pods()
            try:
                line = self._queue.get(timeout=1)
                yield line
            except queue.Empty:
                continue  # timeout → thử lại


# ─────────────────────────────────────────────
# TetragonConsumer — kết hợp Reader + Parser
# ─────────────────────────────────────────────

class TetragonConsumer:
    """
    Consumer chính: stream events từ Tetragon và gọi callback handler.

    Ví dụ sử dụng:
        def my_handler(event: SyscallEvent):
            print(f"{event.pod.namespace}/{event.pod.name}: {event.syscall_name}")

        consumer = TetragonConsumer(mode="kubectl")
        consumer.run(my_handler)
    """
    def __init__(self, mode: str = "kubectl",
                 log_path: str = "/var/run/cilium/tetragon/tetragon.log",
                 namespace: str = "kube-system",
                 event_filter: Optional[Callable[[SyscallEvent], bool]] = None):
        self.parser = TetragonEventParser()
        # Tetragon can export global ProcessExec records in addition to policy
        # kprobes. Filter after parsing, before any per-pod window allocation,
        # so unmodelled workloads cannot inflate the detector's queue/state.
        self.event_filter = event_filter

        if mode == "file":
            self.reader = TetragonLogFileReader(log_path)
        elif mode == "kubectl":
            self.reader = TetragonKubectlReader(namespace=namespace)
        else:
            raise ValueError(f"mode phải là 'file' hoặc 'kubectl', nhận được: {mode}")

    def run(self, on_event_callback):
        """
        Vòng lặp chính: đọc line → parse → gọi callback.
        Chạy mãi mãi (blocking).
        """
        event_count = 0
        skip_count = 0
        filtered_count = 0
        log_interval = int(os.environ.get(
            "SENTINEL_CONSUMER_LOG_INTERVAL", "100000"
        ))
        logger.info("Bắt đầu stream event từ Tetragon...")

        for raw_line in self.reader.stream():
            event = self.parser.parse_line(raw_line)
            if event:
                if self.event_filter and not self.event_filter(event):
                    filtered_count += 1
                    continue
                event_count += 1
                try:
                    on_event_callback(event)
                except Exception as e:
                    logger.error(f"Lỗi trong callback: {e}")
            else:
                skip_count += 1

            if (event_count + skip_count) % log_interval == 0:
                total = event_count + skip_count
                health = getattr(self.reader, "health", lambda: {})()
                logger.info(
                    f"Đã xử lý {total} dòng: "
                    f"{event_count} events hợp lệ, {filtered_count} filtered, "
                    f"{skip_count} bỏ qua, "
                    f"sensor_health={health}"
                )

    def stop(self):
        stop = getattr(self.reader, "stop", None)
        if stop:
            stop()


# ─────────────────────────────────────────────
# Test nhanh — chạy trực tiếp để kiểm tra
# ─────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Tetragon Event Consumer")
    parser.add_argument("--mode", choices=["file", "kubectl"], default="kubectl",
                        help="Nguồn đọc: 'kubectl' (exec vào pod) hoặc 'file' (đọc log trực tiếp)")
    parser.add_argument("--log-path", default="/var/run/cilium/tetragon/tetragon.log")
    parser.add_argument("--namespace", default="kube-system")
    args = parser.parse_args()

    seen_pods = set()

    def print_event(event: SyscallEvent):
        pod_key = f"{event.pod.namespace}/{event.pod.name}"
        if pod_key not in seen_pods:
            seen_pods.add(pod_key)
            logger.info(f"Pod mới: {pod_key}")
        print(
            f"[{event.timestamp[:19]}] "
            f"{event.pod.namespace}/{event.pod.name:<40} "
            f"syscall={event.syscall_name:<12} "
            f"binary={event.process.binary}"
        )

    consumer = TetragonConsumer(
        mode=args.mode,
        log_path=args.log_path,
        namespace=args.namespace,
    )
    consumer.run(print_event)
