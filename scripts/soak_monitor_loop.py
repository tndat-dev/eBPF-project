#!/usr/bin/env python3
"""Read-only console watcher for the current normal-soak campaign."""

import time
import subprocess
import datetime

INTERVAL_SEC = 1800  # 30 minutes

def log(msg):
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    print(f"[{now}] {msg}", flush=True)

def run_ssh_check():
    try:
        command = [
            "python3", "scripts/ssh_lab.py", "--host", "10.1.16.234",
            "python3", "/home/dat/eBPF-project/scripts/check_a5_soak.py",
        ]
        result = subprocess.run(
            command, check=False, capture_output=True, text=True, timeout=30
        )
        output = result.stdout.strip()
        if result.stderr:
            output += f"\nstderr: {result.stderr.strip()}"
        return f"exit={result.returncode} {output}".strip()
    except Exception as e:
        return f"ERROR running check: {e}"

def main():
    log("Starting 30-minute read-only soak monitor loop...")
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
