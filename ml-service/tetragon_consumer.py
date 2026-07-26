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
from typing import Optional, Generator
import argparse
import threading
import os
import queue

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
    Đọc Tetragon log từ TẤT CẢ Tetragon pods song song (1 pod/worker node).
    
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
        self._procs = []
        self._procs_lock = threading.Lock()
        self._backpressure_events = 0

    def _get_all_tetragon_pods(self) -> list[str]:
        """Lấy tên TẤT CẢ pod Tetragon đang chạy (1 pod/node)."""
        result = subprocess.run(
            ["kubectl", "get", "pods", "-n", self.namespace,
             "-l", "app.kubernetes.io/name=tetragon",
             "-o", "jsonpath={.items[*].metadata.name}"],
            capture_output=True, text=True, check=True
        )
        pods = result.stdout.strip().split()
        if not pods:
            raise RuntimeError("Không tìm thấy pod Tetragon nào đang chạy!")
        logger.info(f"Tìm thấy {len(pods)} Tetragon pod(s): {pods}")
        return pods

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
        while not self._stop_event.is_set():
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
                    self._procs.append(proc)
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
                    if proc in self._procs:
                        self._procs.remove(proc)
                if not self._stop_event.is_set():
                    logger.warning(f"[{pod_name}] kubectl exec kết thúc, retry sau 5s...")
            except Exception as e:
                if not self._stop_event.is_set():
                    logger.error(f"[{pod_name}] Lỗi: {e}, retry sau 5s...")
            self._stop_event.wait(5)

    def stop(self):
        """Stop readers and reap all kubectl-exec child processes."""
        self._stop_event.set()
        with self._procs_lock:
            procs = list(self._procs)
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
        }

    def stream(self) -> Generator[str, None, None]:
        """
        Khởi động 1 thread/pod, gộp tất cả vào queue rồi yield ra.
        """
        # Lấy danh sách tất cả Tetragon pods
        pods = []
        while not self._stop_event.is_set():
            try:
                pods = self._get_all_tetragon_pods()
                break
            except Exception as e:
                logger.error(f"Chưa lấy được pod list: {e}, retry sau 5s...")
                self._stop_event.wait(5)
        if not pods:
            return

        # Tạo 1 thread cho mỗi pod (1 thread/worker node)
        for pod_name in pods:
            t = threading.Thread(
                target=self._stream_one_pod,
                args=(pod_name,),
                daemon=True,
                name=f"reader-{pod_name}",
            )
            t.start()
            logger.info(f"Thread started cho pod: {pod_name}")

        logger.info(f"Đang đọc từ {len(pods)} nodes song song...")

        # Yield từ queue chung (blocking)
        while not self._stop_event.is_set():
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
                 namespace: str = "kube-system"):
        self.parser = TetragonEventParser()

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
        log_interval = int(os.environ.get(
            "SENTINEL_CONSUMER_LOG_INTERVAL", "100000"
        ))
        logger.info("Bắt đầu stream event từ Tetragon...")

        for raw_line in self.reader.stream():
            event = self.parser.parse_line(raw_line)
            if event:
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
                    f"{event_count} events hợp lệ, {skip_count} bỏ qua, "
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
