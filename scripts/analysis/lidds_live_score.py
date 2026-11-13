#!/usr/bin/env python3
"""Offline fit + score for the single-node lidds-live run (protocol pulse-live-lidds-v1), from the probe runner's
output and the driver's schedules.

The loader wrote every lidds-live token window to tokens.jsonl (cgroup_id, window_end, grams) and the resolver wrote
timestamped metadata (cgroup_id -> workload/pod_uid) to meta.jsonl. The driver wrote schedule-capture.jsonl (normal
cycles) and schedule-live.jsonl (normal and exploit cycles). Per victim workload: learn a CountTokenLM from the capture
windows, set the registered threshold (moment Gumbel without the top 1 %, alpha' = 0.00018, on 60 s block maxima), and
score the live windows. An exploit cycle is detected when a victim window in [exploit_time, exploit_time + horizon]
scores above the threshold.

    python3 lidds_live_score.py --run-dir DIR --output out.json [--horizon 30 --block 60 --alpha 0.00018]
"""
import argparse
from collections import defaultdict
import json
import math
from pathlib import Path
import sys

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from sentinel_pulse.detector.token_model import CountTokenLM, strip  # noqa: E402
import lidds_ml_v2 as m  # noqa: E402
import lidds_ml_v4 as v4  # noqa: E402

WARMUP = 30.0
RECORDING = 150.0


def cgroup_map(run_dir):
    """cgroup_id (str) -> (workload_key, pod_uid, container) from every resolver snapshot (union; cgroups are unique)."""
    out = {}
    path = run_dir / "meta.jsonl"
    if path.exists():
        for line in path.read_text().splitlines():
            if not line.strip():
                continue
            for cg, item in json.loads(line)["cgroups"].items():
                if item.get("namespace") == "lidds-live" and item.get("workload_name"):
                    out[str(cg)] = (f"lidds-live/{item['workload_name']}:{item.get('container_name', 'victim')}",
                                    item.get("pod_uid"), item.get("container_name"))
    return out


def windows_by_workload(run_dir, cg2wl):
    """{workload_key: [(window_end, grams, session_events, events)]} from tokens.jsonl."""
    out = defaultdict(list)
    path = run_dir / "tokens.jsonl"
    with path.open() as stream:
        for line in stream:
            if '"token_grams"' not in line:
                continue
            row = json.loads(line)
            wl = cg2wl.get(str(row["cgroup_id"]))
            if not wl:
                continue
            out[wl[0]].append((float(row["window_end"]), row["grams"], int(row.get("session_events", 0)), int(row["events"])))
    for wl in out:
        out[wl].sort()
    return out


def cycles(run_dir):
    rows = []
    for name, phase in (("schedule-capture.jsonl", "capture"), ("schedule-live.jsonl", "live")):
        p = run_dir / name
        if p.exists():
            for line in p.read_text().splitlines():
                if line.strip():
                    r = json.loads(line)
                    if "recording_start" in r:
                        r["phase"] = phase
                        rows.append(r)
    return rows


def learn(windows):
    lm = CountTokenLM()
    for _, grams, _, _ in windows:
        for *g, c in grams:
            lm.learn(strip(g), int(c))
    return lm.finalize()


def score(lm, grams):
    return lm.window_score(grams)


def threshold(lm, capture_windows, block, alpha):
    """Moment Gumbel (lidds-ml-v4 rule) on the held-out-free 60 s block maxima of the capture windows."""
    blocks = defaultdict(float)
    for end, grams, _, _ in capture_windows:
        blocks[math.floor(end / block)] = max(blocks[math.floor(end / block)], score(lm, grams))
    maxima = np.array(list(blocks.values()), float)
    if len(maxima) < 3:
        return None, maxima
    return m.threshold(v4.trimmed_gumbel(maxima), alpha), maxima


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--run-dir", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True)
    ap.add_argument("--horizon", type=float, default=30.0)
    ap.add_argument("--block", type=float, default=60.0)
    ap.add_argument("--alpha", type=float, default=0.00018)
    a = ap.parse_args()
    cg2wl = cgroup_map(a.run_dir)
    wins = windows_by_workload(a.run_dir, cg2wl)
    cyc = cycles(a.run_dir)
    # a victim workload per scenario (victim-<slug>); collect capture-phase and live-phase spans
    by_scn = defaultdict(lambda: dict(capture_spans=[], exploit=[], normal=[], workload=None))
    for c in cyc:
        scn = c["scenario"]
        wl = f"lidds-live/victim-{scn.lower().replace('_', '-').replace('.', '-')}:victim"
        by_scn[scn]["workload"] = wl
        span = (c["recording_start"], c["recording_start"] + c.get("recording_seconds", RECORDING))
        if c["phase"] == "capture":
            by_scn[scn]["capture_spans"].append(span)
        elif c.get("is_exploit") and "exploit_time" in c:
            by_scn[scn]["exploit"].append(c)
        else:
            by_scn[scn]["normal"].append(c)

    out = {}
    pooled = dict(exploit_cycles=0, detected=0, normal_cycles=0, false_alarm_cycles=0, latencies=[])
    for scn, d in sorted(by_scn.items()):
        wl = d["workload"]
        w = wins.get(wl, [])
        in_capture = [x for x in w if any(lo <= x[0] <= hi for lo, hi in d["capture_spans"])]
        if len(in_capture) < 5:
            out[scn] = dict(note="too few capture windows", capture_windows=len(in_capture), workload=wl,
                            victim_windows=len(w))
            continue
        lm = learn(in_capture)
        tau, maxima = threshold(lm, in_capture, a.block, a.alpha)
        if tau is None:
            out[scn] = dict(note="too few capture blocks for a threshold", capture_windows=len(in_capture))
            continue
        det = lat = fa = 0
        lats, shares = [], []
        for c in d["exploit"]:
            lo, hi = c["exploit_time"], c["exploit_time"] + a.horizon
            hit = None
            for end, grams, se, ev in w:
                if lo <= end <= hi and score(lm, grams) > tau:
                    hit = end if hit is None else hit
                    shares.append(se / ev if ev else 0.0)
            if hit is not None:
                det += 1
                lats.append(hit - c["exploit_time"])
        for c in d["normal"]:
            lo, hi = c["recording_start"], c["recording_start"] + c.get("recording_seconds", RECORDING)
            if any(lo <= end <= hi and score(lm, grams) > tau for end, grams, _, _ in w):
                fa += 1
        out[scn] = dict(workload=wl, capture_windows=len(in_capture), threshold=tau, capture_blocks=len(maxima),
                        exploit_cycles=len(d["exploit"]), detected=det,
                        recall=det / len(d["exploit"]) if d["exploit"] else None,
                        normal_cycles=len(d["normal"]), false_alarm_cycles=fa,
                        latency_p50=float(np.percentile(lats, 50)) if lats else None,
                        latency_p95=float(np.percentile(lats, 95)) if lats else None,
                        alarm_session_share=float(np.mean(shares)) if shares else None)
        pooled["exploit_cycles"] += len(d["exploit"])
        pooled["detected"] += det
        pooled["normal_cycles"] += len(d["normal"])
        pooled["false_alarm_cycles"] += fa
        pooled["latencies"] += lats
    lat = sorted(pooled["latencies"])
    doc = dict(schema="lidds-live-score-v1", protocol="sentinel_pulse/protocol/pulse-live-lidds-v1.json",
               run=str(a.run_dir), horizon=a.horizon, alpha=a.alpha, per_scenario=out,
               pooled=dict(exploit_cycles=pooled["exploit_cycles"], detected=pooled["detected"],
                           recall=pooled["detected"] / pooled["exploit_cycles"] if pooled["exploit_cycles"] else None,
                           normal_cycles=pooled["normal_cycles"], false_alarm_cycles=pooled["false_alarm_cycles"],
                           latency_p50=float(np.percentile(lat, 50)) if lat else None,
                           latency_p95=float(np.percentile(lat, 95)) if lat else None))
    a.output.write_text(json.dumps(doc, indent=1))
    print(json.dumps(dict(pooled=doc["pooled"],
                          scenarios={s: (v.get("detected"), v.get("exploit_cycles"), v.get("false_alarm_cycles"), v.get("note"))
                                     for s, v in out.items()})))


if __name__ == "__main__":
    main()
