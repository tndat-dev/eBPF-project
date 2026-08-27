#!/usr/bin/env python3
"""
Agent Soak Watcher:
Polls every 30 minutes (1800s), runs check_a5_soak.py on master node,
updates SENTINEL_PULSE_REPORT.md and console output.
"""
import os
import sys
import time
import subprocess
import datetime

INTERVAL_SEC = 1800  # 30 minutes

def log(msg):
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    print(f"[{now}] {msg}", flush=True)

def run_ssh_check():
    try:
        cmd = "python3 scripts/ssh_lab.py 'python3 /home/dat/eBPF-project/scripts/check_a5_soak.py'"
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
        return res.stdout.strip()
    except Exception as e:
        return f"ERROR running check: {e}"

def main():
    log("Starting 30-minute agent soak monitor loop...")
    check_count = 0

    while True:
        check_count += 1
        log(f"--- CHECK #{check_count} ---")
        output = run_ssh_check()
        log(output)

        # Sleep 30 minutes before next check
        log(f"Waiting 30 minutes ({INTERVAL_SEC}s) until next check...")
        time.sleep(INTERVAL_SEC)

if __name__ == "__main__":
    main()
