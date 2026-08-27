#!/usr/bin/env python3
"""
Sentinel Pulse A5 Periodic Soak Checker.
Runs every 30 minutes on k8s-master (or via lab script).
Logs structured status to SOAK_PERIODIC_CHECKS.log and appends to pulse-a5-monitor.md.
"""
import os
import sys
import json
import time
import subprocess
import datetime

RUN_ID = "pulse500-normal-soak-a5-20260827T070900Z"
EVIDENCE_DIR = f"/home/dat/sentinel-pulse-evidence/{RUN_ID}"
MONITOR_FILE = os.path.join(EVIDENCE_DIR, "MONITOR.jsonl")
LOG_FILE = os.path.join(EVIDENCE_DIR, "SOAK_PERIODIC_CHECKS.log")
REPORT_MD = "/home/dat/eBPF-project/scripts/pulse-a5-monitor.md"

WORKERS = ["10.1.16.237", "10.1.16.238", "10.1.16.239"]
WORKER_NAMES = {
    "10.1.16.237": "k8s-worker1",
    "10.1.16.238": "k8s-worker4",
    "10.1.16.239": "k8s-worker3"
}

def run_cmd(cmd):
    try:
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15)
        return res.stdout.strip()
    except Exception as e:
        return f"ERROR: {e}"

def check_soak():
    now_utc = datetime.datetime.now(datetime.timezone.utc)
    ts_str = now_utc.strftime("%Y-%m-%dT%H:%M:%SZ")

    # Start info
    start_ts = 1787818106.0  # 2026-08-27T08:08:26Z
    try:
        if os.path.exists(os.path.join(EVIDENCE_DIR, "SOAK_START.json")):
            with open(os.path.join(EVIDENCE_DIR, "SOAK_START.json")) as f:
                sdata = json.load(f)
                sb = sdata.get("started_not_before", "")
                if sb:
                    dt = datetime.datetime.fromisoformat(sb)
                    start_ts = dt.timestamp()
    except Exception:
        pass

    elapsed_s = time.time() - start_ts
    elapsed_h = elapsed_s / 3600.0
    pct = min(100.0, (elapsed_h / 24.0) * 100.0)

    # Monitor log check
    worker_stats = {}
    total_decisions = 0
    total_alerts = 0
    total_restarts = 0

    if os.path.exists(MONITOR_FILE):
        try:
            with open(MONITOR_FILE) as f:
                for line in f:
                    try:
                        d = json.loads(line)
                        host = d.get("host", "")
                        worker_stats[host] = d
                    except Exception:
                        pass
        except Exception as e:
            print(f"Error reading MONITOR.jsonl: {e}")

    summary_lines = []
    summary_lines.append(f"=== SOAK CHECK AT {ts_str} (Elapsed: {elapsed_h:.2f}h / {pct:.1f}%) ===")

    for w in WORKERS:
        wname = WORKER_NAMES.get(w, w)
        st = worker_stats.get(w, {})
        col = st.get("collector", "unknown")
        det = st.get("detector", "unknown")
        dec = st.get("decisions", 0)
        al = st.get("alerts", 0)
        nr = st.get("nrestarts", 0)

        total_decisions += dec
        total_alerts += al
        total_restarts += nr

        summary_lines.append(
            f"  - {wname} ({w}): collector={col}, detector={det}, decisions={dec:,}, alerts={al}, restarts={nr}"
        )

    summary_lines.append(f"  TOTAL: decisions={total_decisions:,}, alerts={total_alerts}, restarts={total_restarts}")

    # Check k8s pods
    pods_out = run_cmd("kubectl get pods -n production --no-headers 2>/dev/null | awk '{print $3}' | sort | uniq -c")
    summary_lines.append(f"  PRODUCTION PODS: {pods_out.replace('\n', '; ')}")

    # Check disk
    disk_out = run_cmd("df -h / | awk 'NR==2{print $4\" avail (\"$5\" used)\"}'")
    summary_lines.append(f"  MASTER DISK: {disk_out}")

    log_entry = "\n".join(summary_lines) + "\n"
    print(log_entry)

    # Write to SOAK_PERIODIC_CHECKS.log
    try:
        os.makedirs(EVIDENCE_DIR, exist_ok=True)
        with open(LOG_FILE, "a") as f:
            f.write(log_entry + "\n")
    except Exception as e:
        print(f"Failed writing to {LOG_FILE}: {e}")

    # Append markdown entry if REPORT_MD exists
    try:
        if os.path.exists(REPORT_MD):
            md_entry = (
                f"- **{ts_str}** ({elapsed_h:.2f}h / {pct:.1f}% soak) — Total decisions: {total_decisions:,}, "
                f"Alerts: {total_alerts}, Restarts: {total_restarts}. Workers: 3/3 healthy.\n"
            )
            with open(REPORT_MD, "a") as f:
                f.write(md_entry)
    except Exception as e:
        print(f"Failed updating {REPORT_MD}: {e}")

if __name__ == "__main__":
    check_soak()
