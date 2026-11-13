#!/usr/bin/env python3
"""Analysis for protocol pulse-live-lidds-v1: detection, false-alarm cycles, latency and lineage of the LID-DS
scenarios replayed on the cluster (scripts/lidds_live/driver.py).

A cycle (``schedule-live.jsonl`` / ``schedule-capture.jsonl``) names its victim pod uid and, for an exploit cycle, the
exploit time. A victim window is an alarm when its logged ``token_score`` exceeds its ``token_threshold`` (the fitted
model of pulse-live-lidds-v1; the worker records both in decisions.jsonl). Matching is by pod uid, so it does not
depend on workload-name inference.

- detected: an exploit cycle with an alarm window of its victim ending in [exploit_time, exploit_time + horizon];
- false-alarm cycle: a normal cycle with an alarm window ending in its recording span (warm-up excluded);
- latency: end of the first detecting window minus the exploit time;
- lineage: the session-event share of the victim's alarm windows (tokens.jsonl); the victim has no runtime exec, so a
  share near 0 confirms the exploit is detected on the native stream (H2 of ml-final-study-v1 amendment 2).

    python3 pulse_live_lidds.py --run-root DIR --output out.json [--horizon 30]
"""
import argparse
from collections import defaultdict
import json
from pathlib import Path
import sys

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from sentinel_pulse.common import open_sealed  # noqa: E402

WARMUP = 30.0
RECORDING = 150.0


def load_cycles(run_root):
    rows = []
    for name in ("schedule-capture.jsonl", "schedule-live.jsonl"):
        path = run_root / name
        if path.exists():
            for line in path.read_text().splitlines():
                if line.strip():
                    r = json.loads(line)
                    if "victim_uid" in r:
                        r["phase"] = "live" if "live" in name else "capture"
                        rows.append(r)
    return rows


def victim_windows(run_root, uids):
    """{uid: [(window_end, score, threshold, session_events, events)]} from the worker decisions and token windows."""
    alarms = defaultdict(list)
    sess = {}
    for seg in sorted(run_root.glob("workers/*/segments/*")):
        tok = seg / "tokens.jsonl"
        if tok.exists():
            with open_sealed(tok) as stream:
                for line in stream:
                    if '"token_window"' not in line:
                        continue
                    row = json.loads(line)
                    if row.get("pod_uid") in uids:
                        sess[(row["pod_uid"], round(float(row["window_end"]), 3))] = (
                            int(row.get("session_events", 0)), int(row["events"]))
        dec = seg / "decisions.jsonl"
        if dec.exists():
            with open_sealed(dec) as stream:
                for line in stream:
                    if '"token-score"' not in line:
                        continue
                    row = json.loads(line)
                    uid = row.get("pod_uid")
                    if uid in uids and row.get("token_score") is not None and row.get("token_threshold") is not None:
                        alarms[uid].append((float(row["window_end"]), float(row["token_score"]), float(row["token_threshold"])))
    for uid in alarms:
        alarms[uid].sort()
    return alarms, sess


def first_alarm(windows, lo, hi):
    for end, score, thr in windows:
        if lo <= end <= hi and score > thr:
            return end
    return None


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--run-root", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True)
    ap.add_argument("--horizon", type=float, default=30.0)
    a = ap.parse_args()
    cycles = load_cycles(a.run_root)
    uids = {c["victim_uid"] for c in cycles}
    alarms, sess = victim_windows(a.run_root, uids)

    per = defaultdict(lambda: dict(exploit_cycles=0, detected=0, normal_cycles=0, false_alarm_cycles=0,
                                   latencies=[], warmup_alarm_cycles=0, alarm_session_events=0, alarm_events=0, alarm_windows=0))
    for c in cycles:
        if c["phase"] != "live" or "recording_start" not in c:
            continue
        scn = c["scenario"]
        w = alarms.get(c["victim_uid"], [])
        rec0, rec1 = c["recording_start"], c["recording_start"] + c.get("recording_seconds", RECORDING)
        # warm-up alarms (victim's own start) reported separately
        if first_alarm(w, rec0 - c.get("warmup_seconds", WARMUP), rec0) is not None:
            per[scn]["warmup_alarm_cycles"] += 1
        if c.get("is_exploit") and "exploit_time" in c:
            per[scn]["exploit_cycles"] += 1
            hit = first_alarm(w, c["exploit_time"], c["exploit_time"] + a.horizon)
            if hit is not None:
                per[scn]["detected"] += 1
                per[scn]["latencies"].append(hit - c["exploit_time"])
                for end, score, thr in w:
                    if c["exploit_time"] <= end <= c["exploit_time"] + a.horizon and score > thr:
                        se, ev = sess.get((c["victim_uid"], round(end, 3)), (0, 0))
                        per[scn]["alarm_session_events"] += se
                        per[scn]["alarm_events"] += ev
                        per[scn]["alarm_windows"] += 1
        else:
            per[scn]["normal_cycles"] += 1
            if first_alarm(w, rec0, rec1) is not None:
                per[scn]["false_alarm_cycles"] += 1

    out = {}
    pooled = dict(exploit_cycles=0, detected=0, normal_cycles=0, false_alarm_cycles=0, latencies=[])
    for scn, d in sorted(per.items()):
        lat = sorted(d["latencies"])
        out[scn] = dict(exploit_cycles=d["exploit_cycles"], detected=d["detected"],
                        recall=d["detected"] / d["exploit_cycles"] if d["exploit_cycles"] else None,
                        normal_cycles=d["normal_cycles"], false_alarm_cycles=d["false_alarm_cycles"],
                        false_alarm_rate=d["false_alarm_cycles"] / d["normal_cycles"] if d["normal_cycles"] else None,
                        warmup_alarm_cycles=d["warmup_alarm_cycles"],
                        latency_p50=float(np.percentile(lat, 50)) if lat else None,
                        latency_p95=float(np.percentile(lat, 95)) if lat else None,
                        alarm_session_share=d["alarm_session_events"] / d["alarm_events"] if d["alarm_events"] else None)
        for k in ("exploit_cycles", "detected", "normal_cycles", "false_alarm_cycles"):
            pooled[k] += d[k]
        pooled["latencies"] += d["latencies"]
    lat = sorted(pooled["latencies"])
    doc = dict(schema="pulse-live-lidds-v1-analysis", protocol="sentinel_pulse/protocol/pulse-live-lidds-v1.json",
               run=str(a.run_root), horizon=a.horizon, per_scenario=out,
               pooled=dict(exploit_cycles=pooled["exploit_cycles"], detected=pooled["detected"],
                           recall=pooled["detected"] / pooled["exploit_cycles"] if pooled["exploit_cycles"] else None,
                           normal_cycles=pooled["normal_cycles"], false_alarm_cycles=pooled["false_alarm_cycles"],
                           false_alarm_rate=pooled["false_alarm_cycles"] / pooled["normal_cycles"] if pooled["normal_cycles"] else None,
                           latency_p50=float(np.percentile(lat, 50)) if lat else None,
                           latency_p95=float(np.percentile(lat, 95)) if lat else None))
    a.output.write_text(json.dumps(doc, indent=1))
    print(json.dumps(dict(pooled=doc["pooled"], scenarios={s: (d["detected"], d["exploit_cycles"], d["false_alarm_cycles"]) for s, d in out.items()})))


if __name__ == "__main__":
    main()
