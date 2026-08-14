"""Attack-marker attribution used only for latency evidence, never decisions."""

from __future__ import annotations

import json
from pathlib import Path


class InjectionTracker:
    def __init__(self, path: Path, horizon_seconds: float = 15.0):
        self.path = path
        self.horizon_seconds = horizon_seconds
        self.offset = 0
        self.markers = []
        self.consumed = set()

    def refresh(self) -> None:
        try:
            with self.path.open(encoding="utf-8") as handle:
                handle.seek(self.offset)
                for line in handle:
                    marker = json.loads(line)
                    if marker.get("schema") != "sentinel-pulse-injection-v1":
                        continue
                    self.markers.append(marker)
                self.offset = handle.tell()
        except FileNotFoundError:
            return

    def match(self, decision: dict) -> dict | None:
        self.refresh()
        alerted_at = float(decision["alerted_at"])
        for marker in reversed(self.markers):
            injection_id = str(marker["injection_id"])
            if injection_id in self.consumed:
                continue
            injected_at = float(marker["injected_at"])
            if injected_at > alerted_at or alerted_at - injected_at > self.horizon_seconds:
                continue
            window_end = decision.get("window_end")
            if window_end is not None and float(window_end) < injected_at:
                continue
            marker_cgroup = marker.get("cgroup_id")
            if marker_cgroup is not None and str(marker_cgroup) != str(decision.get("cgroup_id")):
                continue
            marker_workload = marker.get("workload_key")
            if marker_workload is not None and marker_workload != decision.get("workload_key"):
                continue
            self.consumed.add(injection_id)
            return marker
        return None
