"""
generate-baseline.py
--------------------
Tạo training vectors từ WORKLOAD_PROFILES thực tế.

FIX: Dùng Markov chain (bigram transitions) thay vì random.choices độc lập
     → synthetic vectors có bigram pattern giống real traffic
     → giảm false positive khi model gặp real traffic

Pipeline:
  1. python3 analyze-profile.py        → workload_profiles.pkl
  2. python3 generate-baseline.py      → training_data/*.npy
  3. python3 ml_models.py              → models/
  4. python3 anomaly_detector2.py ...
"""

import numpy as np
import pickle
import os
import random
from collections import Counter

# ── Load vocab ────────────────────────────────────────────────
vocab = pickle.load(open('vocab.pkl', 'rb'))
VOCAB_SIZE = len(vocab)
print(f"Vocab size: {VOCAB_SIZE}")

# ── Load profiles từ analyze-profile.py ──────────────────────
with open("workload_profiles.pkl", "rb") as f:
    profiles_data = pickle.load(f)

unigram     = profiles_data["unigram"]
transitions = profiles_data["transitions"]
start_prob  = profiles_data["start_prob"]

print(f"Loaded profiles for: {list(unigram.keys())}")

# ── Map deployment key → workload ─────────────────────────────
# Dùng deployment key (production/nginx) thay vì full pod name
WORKLOAD_KEYS = {
    "production/nginx":  "nginx",
    "production/redis":  "redis",
    "default/postgres":  "postgres",
}


# ── Markov chain sequence generator ──────────────────────────

def sample_start(workload: str) -> str:
    """Chọn syscall đầu tiên theo unigram distribution."""
    sc   = list(start_prob[workload].keys())
    prob = list(start_prob[workload].values())
    return random.choices(sc, weights=prob, k=1)[0]


def sample_next(workload: str, prev: str) -> str:
    """
    Chọn syscall tiếp theo theo bigram transition.
    Fallback về unigram nếu không có transition từ prev.
    """
    trans = transitions.get(workload, {})
    if prev in trans and trans[prev]:
        nxt  = list(trans[prev].keys())
        prob = list(trans[prev].values())
        return random.choices(nxt, weights=prob, k=1)[0]
    # Fallback: unigram
    sc   = list(unigram[workload].keys())
    prob = list(unigram[workload].values())
    return random.choices(sc, weights=prob, k=1)[0]


def generate_markov_sequence(workload: str, length: int = 200):
    """
    Tạo syscall sequence dùng Markov chain.

    Khác với random.choices (độc lập):
      random.choices: P(openat→read) = P(read) = unigram freq
      Markov:         P(read|openat) = transition prob từ real data

    Ví dụ nginx thực tế:
      openat → close (0.75), write (0.25)
      vs random: openat → bất kỳ theo unigram
    """
    seq = [sample_start(workload)]
    for _ in range(length - 1):
        seq.append(sample_next(workload, seq[-1]))
    return seq


def sequence_to_vector(seq, vocab):
    """Chuyển syscall sequence → feature vector (unigram + bigram)."""
    vector = np.zeros(len(vocab), dtype=np.float32)
    n = len(seq)
    if n == 0:
        return vector

    # Unigram
    for s, c in Counter(seq).items():
        if s in vocab:
            vector[vocab[s]] = c / n

    # Bigram — với Markov chain, phần này sẽ đúng với real data
    for i in range(len(seq) - 1):
        key = f"{seq[i]}|{seq[i+1]}"
        if key in vocab:
            vector[vocab[key]] += 1.0 / n

    return vector


# ── Generate training data ────────────────────────────────────
os.makedirs('training_data', exist_ok=True)

# Xoá file cũ
old = [f for f in os.listdir('training_data') if f.endswith('.npy')]
if old:
    print(f"Xoá {len(old)} file cũ...")
    for f in old:
        os.remove(f'training_data/{f}')

N_WINDOWS = 120

for deploy_key, workload in WORKLOAD_KEYS.items():
    if workload not in unigram:
        print(f"⚠️  Không có profile cho '{workload}', bỏ qua {deploy_key}")
        continue

    vectors = []
    for i in range(N_WINDOWS):
        length = random.randint(150, 250)
        seq    = generate_markov_sequence(workload, length)
        vec    = sequence_to_vector(seq, vocab)
        vectors.append(vec)

    X     = np.array(vectors, dtype=np.float32)
    fname = f"training_data/{deploy_key.replace('/', '__')}.npy"
    np.save(fname, X)
    print(f"✅ {deploy_key}: shape={X.shape}, workload={workload} → {fname}")

print("\nDone! Files saved:")
for f in sorted(os.listdir('training_data')):
    if f.endswith('.npy'):
        X = np.load(f'training_data/{f}')
        dk = f.replace('.npy', '').replace('__', '/')
        print(f"  {f}  ({dk}): {X.shape}")

print("\nBước tiếp: python3 ml_models.py")
