"""
generate_baseline2.py
---------------------
Tạo training data từ REAL Tetragon events (thay thế generate-baseline.py dùng Markov synthetic).
Usage: python3 generate_baseline2.py
"""

import json, numpy as np, pickle
from collections import Counter, defaultdict
from datetime import datetime

with open("vocab.pkl", "rb") as f:
    vocab = pickle.load(f)

NORMALIZE = {
    "__x64_sys_read":"read","__x64_sys_write":"write",
    "__x64_sys_close":"close","__x64_sys_openat":"openat",
    "__x64_sys_connect":"connect","__x64_sys_accept4":"accept",
    "__x64_sys_clone":"clone","__x64_sys_execve":"execve",
    "__x64_sys_execveat":"execve","__x64_sys_setuid":"setuid",
    "__x64_sys_unshare":"unshare","__x64_sys_mount":"mount",
}

TARGET_WORKLOADS = {
    "nginx":    "production/nginx",
    "redis":    "production/redis",
    "postgres": "default/postgres",
}

def parse_time(t):
    try: return datetime.fromisoformat(t.replace("Z","+00:00")).timestamp()
    except: return 0.0

def make_vector(syscalls):
    vec = np.zeros(len(vocab))
    total = len(syscalls)
    if total == 0: return vec
    for sc, cnt in Counter(syscalls).items():
        if sc in vocab:
            vec[vocab[sc]] = cnt / total
    for a, b in zip(syscalls, syscalls[1:]):
        key = f"{a}|{b}"
        if key in vocab:
            vec[vocab[key]] += 1 / total
    return vec

# Load events theo pod
pod_events = defaultdict(list)
with open("raw_tetragon.jsonl") as f:
    for line in f:
        try:
            ev = json.loads(line.strip())
            kp = ev.get("process_kprobe", {})
            pod = kp.get("process",{}).get("pod",{}).get("name","")
            ns  = kp.get("process",{}).get("pod",{}).get("namespace","")
            fn  = kp.get("function_name","")
            t   = ev.get("time","")
            if fn in NORMALIZE and pod:
                pod_events[(ns, pod)].append((parse_time(t), NORMALIZE[fn]))
        except: pass

WINDOW_SEC = 30
results = defaultdict(list)

for (ns, pod), events in pod_events.items():
    workload = next((k for k in TARGET_WORKLOADS if k in pod.lower()), None)
    if not workload: continue
    model_key = TARGET_WORKLOADS[workload]

    events.sort(key=lambda x: x[0])
    start = events[0][0]
    buckets = defaultdict(list)
    for t, sc in events:
        buckets[int((t - start) / WINDOW_SEC)].append(sc)

    for b in sorted(buckets):
        scs = buckets[b]
        if len(scs) >= 10:
            results[model_key].append(make_vector(scs))

print(f"Vocab size: {len(vocab)}")
for model_key, vecs in results.items():
    arr = np.array(vecs)
    print(f"\n{model_key}: {len(arr)} real windows")
    while len(arr) < 120:
        arr = np.vstack([arr, arr])
    arr = arr[:120]
    arr += np.random.normal(0, 0.001, arr.shape)
    arr = np.clip(arr, 0, 1)

    fname = model_key.replace("/", "__") + ".npy"
    np.save(f"training_data/{fname}", arr)
    print(f"  ✅ Saved: training_data/{fname} {arr.shape}")
    for k, v in sorted(vocab.items(), key=lambda x: -arr[:,x[1]].mean()):
        m = arr[:,v].mean()
        if m > 0.01:
            print(f"     {k:20s}: {m:.4f}")
