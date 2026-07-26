"""Replay real Tetragon capture and estimate detector false positives.

This deliberately uses captured events rather than generated vectors. Windows
are grouped per deployment, scored by the deployed model, and passed through
the same score/persistence/behavior gates as the realtime detector.
"""
import argparse
import json
import pickle
from collections import defaultdict
from datetime import datetime

from feature_engineering import extract_ngram_vector
from ml_models import ModelManager
from tetragon_consumer import TetragonEventParser

SUSPICIOUS = {
    "execve", "execveat", "clone", "clone3", "unshare", "mount", "ptrace",
    "setuid", "setgid", "capset", "connect",
}

def epoch(value):
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except Exception:
        return None

def deployment_key(namespace, pod):
    parts = pod.rsplit("-", 2)
    return f"{namespace}/{parts[0] if len(parts) == 3 else pod}"

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", default="raw_tetragon.jsonl")
    ap.add_argument("--window", type=int, default=30)
    ap.add_argument("--threshold", type=float, default=.80)
    ap.add_argument("--warmup", type=int, default=2)
    args = ap.parse_args()

    with open("vocab.pkl", "rb") as f:
        vocab = pickle.load(f)
    manager = ModelManager(model_dir="models", vocab_path="vocab.pkl")
    manager.load_all()
    available = set(manager.list_models())
    parser = TetragonEventParser()
    windows = defaultdict(list)
    with open(args.input, errors="replace") as f:
        for line in f:
            event = parser.parse_line(line)
            if not event:
                continue
            key = deployment_key(event.pod.namespace, event.pod.name)
            if key not in available:
                continue
            ts = epoch(event.timestamp)
            if ts is not None:
                windows[(key, int(ts // args.window))].append(event.syscall_name)

    consecutive = defaultdict(int)
    seen = defaultdict(int)
    rows = []
    alerts = 0
    for (key, bucket), calls in sorted(windows.items(), key=lambda x: (x[0][1], x[0][0])):
        if len(calls) < 150:
            continue
        seen[key] += 1
        result = manager.score(key, extract_ngram_vector(calls, vocab))
        score = result["ensemble_score"]
        suspicious_mass = sum(c in SUSPICIOUS for c in calls) / len(calls)
        candidate = score >= args.threshold and suspicious_mass >= .10
        if seen[key] <= args.warmup:
            candidate = False
        consecutive[key] = consecutive[key] + 1 if candidate else 0
        alert = consecutive[key] >= 2
        alerts += int(alert)
        rows.append({"workload": key, "events": len(calls), "score": score,
                     "suspicious_mass": suspicious_mass, "alert": alert})

    report = {
        "windows": len(rows), "alerts": alerts,
        "false_positive_rate": alerts / max(len(rows), 1),
        "by_workload": {k: sum(r["alert"] for r in rows if r["workload"] == k)
                        for k in sorted(available)},
        "max_normal_score": max((r["score"] for r in rows), default=None),
        "max_normal_suspicious_mass": max((r["suspicious_mass"] for r in rows), default=None),
    }
    print(json.dumps(report, indent=2, sort_keys=True))

if __name__ == "__main__":
    main()
