"""Privacy-minimised, restart-safe Falco evidence collector for V8 AIMS runs."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import threading
from typing import Any


SCHEMA = "sentinel-falco-alert/v1"
STATE_SCHEMA = "sentinel-falco-collector-state/v1"
TARGET_PREFIXES = (
    "aims-frontend-", "api-gateway-", "auth-service-", "cart-service-",
    "catalog-service-", "inventory-service-", "order-service-",
    "security-telemetry-service-",
)
LOG_PATTERN = re.compile(
    r"^(?P<outer>\S+)\s+(?P<clock>\S+):\s+"
    r"(?P<priority>[A-Za-z]+)\s+(?P<rule>.*?)\s+\|"
)
NAMESPACE_PATTERN = re.compile(r"(?:^|\s)k8s_ns_name=(?P<value>\S+)")
POD_PATTERN = re.compile(r"(?:^|\s)k8s_pod_name=(?P<value>\S+)")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def line_timestamp(line: str) -> float | None:
    try:
        token = line.split(maxsplit=1)[0]
        return datetime.fromisoformat(token.replace("Z", "+00:00")).timestamp()
    except (IndexError, ValueError):
        return None


def parse_falco_line(
    line: str, *, source_pod: str, source_node: str, release_id: str,
) -> dict[str, Any] | None:
    """Return only non-sensitive Falco decision metadata for an AIMS pod."""
    match = LOG_PATTERN.search(line.strip())
    namespace = NAMESPACE_PATTERN.search(line)
    pod = POD_PATTERN.search(line)
    if not match or not namespace or not pod:
        return None
    target_namespace = namespace.group("value")
    target_pod = pod.group("value")
    if (
        target_namespace != "production"
        or not any(target_pod.startswith(prefix) for prefix in TARGET_PREFIXES)
    ):
        return None
    try:
        event_ts = datetime.fromisoformat(
            match.group("outer").replace("Z", "+00:00")
        ).timestamp()
    except ValueError:
        return None
    row = {
        "schema": SCHEMA,
        "kind": "falco_alert",
        "event_ts": event_ts,
        "priority": match.group("priority"),
        "rule": match.group("rule").strip(),
        "source_falco_pod": source_pod,
        "source_node": source_node,
        "target_namespace": target_namespace,
        "target_pod": target_pod,
        "release_id": release_id,
        "contains_arguments_or_payloads": False,
        "raw_output_stored": False,
    }
    identity = json.dumps(row, sort_keys=True, separators=(",", ":")).encode()
    row["event_id"] = sha256_bytes(identity)
    return row


def atomic_json(path: Path, payload: dict[str, Any]) -> None:
    temporary = path.with_suffix(path.suffix + f".tmp-{os.getpid()}")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    temporary.replace(path)


class Collector:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.root = args.output_root.resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.output = self.root / "falco-alerts.jsonl"
        self.state_path = self.root / "collector-state.json"
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.readers: dict[str, threading.Thread] = {}
        self.active: set[str] = set()
        self.failures: list[dict[str, Any]] = []
        self.reader_ranges: dict[str, dict[str, Any]] = {}
        self.lines_seen = 0
        self.rows_written = 0
        self.duplicates = 0
        self.started_at = utc_now()
        self.seen = set()
        if self.output.is_file():
            for line in self.output.read_text().splitlines():
                try:
                    self.seen.add(json.loads(line)["event_id"])
                except (KeyError, TypeError, ValueError):
                    raise ValueError("existing Falco evidence is malformed")

    def kubectl(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [self.args.kubectl, *arguments], text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )

    def discover(self) -> dict[str, str]:
        result = self.kubectl(
            "-n", self.args.namespace, "get", "pods", "-l", self.args.selector,
            "-o", "json",
        )
        if result.returncode != 0:
            raise RuntimeError(f"Falco membership query failed: {result.stderr.strip()}")
        document = json.loads(result.stdout)
        return {
            item["metadata"]["name"]: item["spec"]["nodeName"]
            for item in document.get("items", [])
            if item.get("status", {}).get("phase") == "Running"
            and any(
                condition.get("type") == "Ready"
                and condition.get("status") == "True"
                for condition in item.get("status", {}).get("conditions", [])
            )
        }

    def snapshot(self) -> None:
        code = self.root / "code"
        code.mkdir(exist_ok=True)
        source = Path(__file__).resolve()
        source_copy = code / source.name
        payload = source.read_bytes()
        if source_copy.exists() and source_copy.read_bytes() != payload:
            raise ValueError("collector source changed within evidence root")
        source_copy.write_bytes(payload)
        commands = {
            "falco-daemonset.yaml": (
                "-n", self.args.namespace, "get", "daemonset", "falco", "-o", "yaml",
            ),
            "falco-configmap.yaml": (
                "-n", self.args.namespace, "get", "configmap", "falco", "-o", "yaml",
            ),
            "falco-pods.json": (
                "-n", self.args.namespace, "get", "pods", "-l", self.args.selector,
                "-o", "json",
            ),
            "nodes.txt": ("get", "nodes", "-o", "wide"),
        }
        for name, command in commands.items():
            destination = self.root / name
            result = self.kubectl(*command)
            if result.returncode != 0:
                raise RuntimeError(f"snapshot failed for {name}: {result.stderr.strip()}")
            if destination.exists() and destination.read_text() != result.stdout:
                raise ValueError(f"Falco snapshot changed during resume: {name}")
            destination.write_text(result.stdout)
        atomic_json(self.root / "collection-contract.json", {
            "schema": "sentinel-falco-collection-contract/v1",
            "release_id": self.args.release_id,
            "since_time": self.args.since_time,
            "expected_readers": self.args.expected_readers,
            "target_namespace": "production",
            "target_prefixes": list(TARGET_PREFIXES),
            "privacy": {
                "arguments": False, "raw_output": False,
                "file_paths": False, "network_payloads": False,
            },
            "collector_sha256": sha256_bytes(payload),
        })

    def append(self, row: dict[str, Any]) -> None:
        encoded = (
            json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode()
        with self.lock:
            if row["event_id"] in self.seen:
                self.duplicates += 1
                return
            descriptor = os.open(
                self.output, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600,
            )
            try:
                if os.write(descriptor, encoded) != len(encoded):
                    raise OSError("short Falco evidence write")
            finally:
                os.close(descriptor)
            self.seen.add(row["event_id"])
            self.rows_written += 1

    def reader(self, pod: str, node: str) -> None:
        while not self.stop.is_set():
            command = [
                self.args.kubectl, "-n", self.args.namespace, "logs", pod,
                "-c", "falco", "--timestamps", "--follow",
                f"--since-time={self.args.since_time}",
            ]
            process = subprocess.Popen(
                command, text=True, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, bufsize=1,
            )
            with self.lock:
                self.active.add(pod)
            assert process.stdout is not None
            for line in process.stdout:
                timestamp = line_timestamp(line)
                with self.lock:
                    self.lines_seen += 1
                    item = self.reader_ranges.setdefault(pod, {
                        "node": node, "lines_seen": 0,
                        "minimum_log_timestamp": None,
                        "maximum_log_timestamp": None,
                    })
                    item["lines_seen"] += 1
                    if timestamp is not None:
                        minimum = item["minimum_log_timestamp"]
                        maximum = item["maximum_log_timestamp"]
                        item["minimum_log_timestamp"] = (
                            timestamp if minimum is None else min(minimum, timestamp)
                        )
                        item["maximum_log_timestamp"] = (
                            timestamp if maximum is None else max(maximum, timestamp)
                        )
                row = parse_falco_line(
                    line, source_pod=pod, source_node=node,
                    release_id=self.args.release_id,
                )
                if row is not None:
                    self.append(row)
            stderr = process.stderr.read() if process.stderr else ""
            returncode = process.wait()
            with self.lock:
                self.active.discard(pod)
                self.failures.append({
                    "observed_at": utc_now(), "pod": pod,
                    "returncode": returncode,
                    "stderr_sha256": sha256_bytes(stderr.encode()),
                })
                self.failures = self.failures[-100:]
            if self.stop.wait(5):
                break

    def state(self, membership: dict[str, str] | None = None) -> dict[str, Any]:
        membership = membership or {}
        with self.lock:
            return {
                "schema": STATE_SCHEMA,
                "release_id": self.args.release_id,
                "started_at": self.started_at,
                "updated_at": utc_now(),
                "since_time": self.args.since_time,
                "expected_readers": self.args.expected_readers,
                "ready_falco_pods": sorted(membership),
                "active_readers": sorted(self.active),
                "coverage_healthy": (
                    len(membership) == self.args.expected_readers
                    and set(membership).issubset(self.active)
                ),
                "stream_failures": len(self.failures),
                "stream_failure_details": list(self.failures),
                "reader_ranges": {
                    pod: dict(item)
                    for pod, item in sorted(self.reader_ranges.items())
                },
                "lines_seen": self.lines_seen,
                "privacy_safe_rows_written": self.rows_written,
                "duplicate_rows_dropped": self.duplicates,
                "output": str(self.output),
            }

    def run(self) -> int:
        self.snapshot()
        membership: dict[str, str] = {}
        try:
            while not self.stop.is_set():
                try:
                    membership = self.discover()
                    if len(membership) != self.args.expected_readers:
                        raise RuntimeError(
                            f"expected {self.args.expected_readers} ready Falco pods, "
                            f"found {len(membership)}"
                        )
                    for pod, node in membership.items():
                        if pod not in self.readers or not self.readers[pod].is_alive():
                            thread = threading.Thread(
                                target=self.reader, args=(pod, node), daemon=True,
                            )
                            self.readers[pod] = thread
                            thread.start()
                except (RuntimeError, ValueError, json.JSONDecodeError) as exc:
                    with self.lock:
                        self.failures.append({
                            "observed_at": utc_now(), "pod": None,
                            "kind": "membership", "error_sha256": sha256_bytes(
                                str(exc).encode()
                            ),
                        })
                        self.failures = self.failures[-100:]
                atomic_json(self.state_path, self.state(membership))
                self.stop.wait(10)
        finally:
            self.stop.set()
            atomic_json(self.state_path, self.state(membership))
        return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--since-time", required=True)
    parser.add_argument("--release-id", required=True)
    parser.add_argument("--namespace", default="falco")
    parser.add_argument("--selector", default="app.kubernetes.io/name=falco")
    parser.add_argument("--expected-readers", type=int, default=6)
    parser.add_argument("--kubectl", default="kubectl")
    args = parser.parse_args()
    if args.expected_readers < 1:
        parser.error("--expected-readers must be positive")
    datetime.fromisoformat(args.since_time.replace("Z", "+00:00"))
    return Collector(args).run()


if __name__ == "__main__":
    raise SystemExit(main())
