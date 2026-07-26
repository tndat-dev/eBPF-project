"""
analyze-profile.py
------------------
Phân tích raw Tetragon events → WORKLOAD_PROFILES (unigram + bigram transitions)

Output dùng trực tiếp cho generate-baseline.py (Markov chain sampling).
"""
import json
import pickle
from collections import defaultdict, Counter

NORMALIZE = {
    "__x64_sys_read":   "read",
    "sys_read":         "read",
    "__x64_sys_write":  "write",
    "sys_write":        "write",
    "__x64_sys_close":  "close",
    "sys_close":        "close",
    "__x64_sys_openat": "openat",
    "sys_openat":       "openat",
    "__x64_sys_connect":"connect",
    "__x64_sys_accept4":"accept",
    "__x64_sys_clone":  "clone",
    "__x64_sys_execve": "execve",
}

TARGET_KEYWORDS = ["nginx", "redis", "postgres", "keycloak"]

# Unigram
counters = defaultdict(Counter)
totals   = defaultdict(int)

# Bigram transitions: workload → {syscall_a → Counter({syscall_b: count})}
transitions = defaultdict(lambda: defaultdict(Counter))

# Track last syscall per pod để tính bigram đúng
last_syscall = {}   # pod_name → syscall

matched = 0
skipped = 0

with open("raw_tetragon.jsonl") as f:
    for line in f:
        try:
            ev  = json.loads(line)
            kp  = ev.get("process_kprobe", {})
            ns  = kp.get("process", {}).get("pod", {}).get("namespace", "")
            pod = kp.get("process", {}).get("pod", {}).get("name", "")
            fn  = kp.get("function_name", "")
        except Exception:
            skipped += 1
            continue

        if ns in ("kube-system", "cilium-system"):
            skipped += 1
            continue

        workload = next((k for k in TARGET_KEYWORDS if k in pod.lower()), None)
        if not workload or fn not in NORMALIZE:
            skipped += 1
            continue

        syscall = NORMALIZE[fn]
        counters[workload][syscall] += 1
        totals[workload] += 1
        matched += 1

        # Bigram: nếu cùng pod có syscall trước đó
        if pod in last_syscall:
            prev = last_syscall[pod]
            transitions[workload][prev][syscall] += 1

        last_syscall[pod] = syscall

print(f"Matched events: {matched}, Skipped: {skipped}\n")

# ── In WORKLOAD_PROFILES (unigram) ────────────────────────────
print("=" * 60)
print("WORKLOAD_PROFILES (unigram) — dùng để verify:")
print("=" * 60)
for workload, cnt in counters.items():
    total = totals[workload]
    print(f'\n"{workload}": {{   # {total} events tong cong')
    bar_scale = 40 / max(cnt.values())
    for syscall, count in cnt.most_common():
        freq  = count / total
        bar   = "#" * int(count * bar_scale)
        print(f'    "{syscall}": {freq:.3f},  # {count} lan  {bar}')
    print("}")

# ── In BIGRAM TRANSITIONS ─────────────────────────────────────
print("\n" + "=" * 60)
print("BIGRAM TRANSITIONS (Markov) — dùng trong generate-baseline.py:")
print("=" * 60)
for workload in sorted(transitions.keys()):
    print(f'\n# {workload}:')
    for prev_sc, next_cnt in sorted(transitions[workload].items()):
        total_trans = sum(next_cnt.values())
        trans_str = ", ".join(
            f'"{nxt}": {cnt/total_trans:.3f}'
            for nxt, cnt in next_cnt.most_common()
        )
        print(f'    "{prev_sc}" → {{ {trans_str} }}  '
              f'# {total_trans} transitions')

# ── Lưu profiles ra file để generate-baseline.py dùng ────────
profiles_data = {
    "unigram": {
        wl: {sc: cnt / totals[wl] for sc, cnt in counter.items()}
        for wl, counter in counters.items()
    },
    "transitions": {
        wl: {
            prev: {
                nxt: cnt / sum(next_cnt.values())
                for nxt, cnt in next_cnt.items()
            }
            for prev, next_cnt in trans.items()
        }
        for wl, trans in transitions.items()
    },
    "start_prob": {
        # Xác suất syscall đầu tiên = unigram (không có prior)
        wl: {sc: cnt / totals[wl] for sc, cnt in counter.items()}
        for wl, counter in counters.items()
    }
}

with open("workload_profiles.pkl", "wb") as f:
    pickle.dump(profiles_data, f)

print("\n" + "=" * 60)
print("✅ Saved: workload_profiles.pkl")
print("   Bước tiếp: python3 generate-baseline.py")
print("=" * 60)
