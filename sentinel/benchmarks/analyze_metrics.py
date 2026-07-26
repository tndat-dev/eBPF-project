"""Summarize Sentinel JSONL telemetry with robust latency statistics."""
import argparse, json, statistics

def percentile(values, p):
    if not values: return None
    values = sorted(values); k = (len(values)-1) * p / 100
    lo, hi = int(k), min(int(k)+1, len(values)-1)
    return values[lo] + (values[hi]-values[lo]) * (k-lo)

def main():
    ap = argparse.ArgumentParser(); ap.add_argument("path"); args = ap.parse_args()
    rows = [json.loads(x) for x in open(args.path) if x.strip()]
    def vals(kind, field): return [float(r[field]) for r in rows if r.get("kind") == kind and r.get(field) is not None]
    for kind, field, unit in [("inference","inference_ms","ms"), ("detection","detection_latency","s")]:
        x = vals(kind, field)
        if x: print(f"{kind}: n={len(x)} median={statistics.median(x):.4f}{unit} p95={percentile(x,95):.4f}{unit} p99={percentile(x,99):.4f}{unit}")
    print(f"events={len(rows)}")
if __name__ == "__main__": main()
