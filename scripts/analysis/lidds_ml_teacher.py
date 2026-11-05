#!/usr/bin/env python3
"""A small LSTM next-token model on the enriched tokens, the upper reference of the sequence model class.

Same tokens, same per-thread windows and same window score (mean of the 10 highest per-event negative
log-probabilities) as lidds_ml_tokens.py, so the two compare directly: if the LSTM does not beat the n-gram language
model at the same false-alarm level on development, longer memory adds little and the n-gram model, which fits a
kernel table, is close to what the sequence information allows. It is offline only; nothing here is meant to run
live. Trained on normal training recordings only: unique (context, next token) pairs weighted by sqrt(count); tokens
seen once train the OOV slot, so an unseen token gets a learned probability, not a fixed alarm. CPU only, bounded by
``seconds`` of wall time.

    python3 lidds_ml_teacher.py --archives DIR --scenario NAME --output out.npz [--seconds 7200]
"""
import argparse
from collections import Counter
import json
import math
from pathlib import Path
import resource
import sys
import time

import numpy as np
import torch
from torch import nn

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lidds_ml_tokens as tk  # noqa: E402

v2, convert = tk.v2, tk.convert
CONTEXT, PAD, OOV, TOP = 8, 0, 1, 10
MAX_PAIRS = 400_000
MIN_STEPS = 50
COLUMNS = ['window_end', 'top10', 'events']


class Net(nn.Module):
    def __init__(self, vocab, embedding, hidden):
        super().__init__()
        self.embed = nn.Embedding(vocab, embedding, padding_idx=PAD)
        self.lstm = nn.LSTM(embedding, hidden, batch_first=True)
        self.out = nn.Linear(hidden, vocab)

    def forward(self, x):
        h, _ = self.lstm(self.embed(x))
        return self.out(h[:, -1])


class Teacher:
    def __init__(self, seed=20261105, embedding=32, hidden=64):
        self.seed, self.embedding, self.hidden = seed, embedding, hidden
        self.vocab, self.net, self.memo = {}, None, {}

    def ids(self, g):
        ctx = [self.vocab.get(t, OOV) for t in g[:-1]][-CONTEXT:]
        return [PAD] * (CONTEXT - len(ctx)) + ctx, self.vocab.get(g[-1], OOV)

    def fit(self, grams, epochs=6, seconds=7200, batch=2048):
        torch.manual_seed(self.seed)
        started = time.time()
        counts = Counter(tuple(g[-(CONTEXT + 1):]) for g in grams)
        tokens = Counter()
        for g, c in counts.items():
            tokens[g[-1]] += c
        self.vocab = {t: i + 2 for i, t in enumerate(sorted(t for t, c in tokens.items() if c > 1))}
        pairs = sorted(counts.items(), key=lambda kv: -kv[1])[:MAX_PAIRS]
        x = torch.tensor([self.ids(g)[0] for g, _ in pairs], dtype=torch.long)
        y = torch.tensor([self.ids(g)[1] for g, _ in pairs], dtype=torch.long)
        w = torch.tensor([math.sqrt(c) for _, c in pairs], dtype=torch.float32)
        self.net = Net(len(self.vocab) + 2, self.embedding, self.hidden)
        opt = torch.optim.Adam(self.net.parameters(), lr=2e-3)
        loss_fn = nn.CrossEntropyLoss(reduction='none')
        gen = torch.Generator().manual_seed(self.seed)
        done, stopped = 0, False
        steps = max(len(x) // batch, MIN_STEPS)     # a workload with few unique pairs still gets enough updates
        for _ in range(epochs):
            for _ in range(steps):
                idx = torch.randint(len(x), (min(batch, len(x)),), generator=gen)
                loss = (loss_fn(self.net(x[idx]), y[idx]) * w[idx]).sum() / w[idx].sum()
                opt.zero_grad(); loss.backward(); opt.step()
                if time.time() - started > seconds:
                    stopped = True
                    break
            done += 1
            if stopped:
                break
        self.net.eval()
        return dict(epochs=done, stopped_by_time=stopped, pairs=len(pairs), unique_pairs=len(counts), vocabulary=len(self.vocab),
                    oov_targets=int((y == OOV).sum()), seconds=time.time() - started)

    @torch.no_grad()
    def nll(self, grams, batch=8192):
        """Negative log-probability of each gram's last token given its context, memoized on unique grams."""
        keys = [tuple(g[-(CONTEXT + 1):]) for g in grams]
        todo = sorted({k for k in keys if k not in self.memo})
        for i in range(0, len(todo), batch):
            part = todo[i:i + batch]
            pairs = [self.ids(k) for k in part]
            x = torch.tensor([p[0] for p in pairs], dtype=torch.long)
            y = torch.tensor([p[1] for p in pairs], dtype=torch.long)
            lp = torch.log_softmax(self.net(x), dim=1).gather(1, y[:, None])[:, 0]
            self.memo.update(zip(part, (-lp).tolist()))
        return np.asarray([self.memo[k] for k in keys], dtype=float)


def window_scores(per, teacher):
    rows = []
    for w in sorted(per):
        v = teacher.nll(per[w]) if per[w] else np.zeros(0)
        top = np.sort(v)[-TOP:] if len(v) else v
        rows.append((w, float(top.mean()) if len(top) else 0.0, len(v)))
    return np.asarray(rows, dtype=float).reshape(-1, len(COLUMNS))


def cpu_hours():
    r = resource.getrusage(resource.RUSAGE_SELF)
    return (r.ru_utime + r.ru_stime) / 3600


def evaluate(archive, epochs=6, seconds=7200, hidden=64, embedding=32):
    grams = []
    for _, _, blob in v2.split_recordings(archive, {'training'}):
        for g in tk.window_tokens(convert.recording(blob)[1], n=CONTEXT + 1).values():
            grams.extend(g)
    teacher = Teacher(hidden=hidden, embedding=embedding)
    c0 = cpu_hours()
    report = teacher.fit(grams, epochs=epochs, seconds=seconds)
    report['train_cpu_hours'] = cpu_hours() - c0
    del grams
    out, meta = {}, {}
    for _, name, blob in v2.split_recordings(archive, {'validation'}):
        out[f'val/{name}'] = window_scores(tk.window_tokens(convert.recording(blob)[1], n=CONTEXT + 1), teacher)
    for split, name, blob in v2.split_recordings(archive, {'test-normal', 'test-normal_and_attack'}):
        out[name] = window_scores(tk.window_tokens(convert.recording(blob)[1], n=CONTEXT + 1), teacher)
        meta[name] = dict(split=split, exploit=tk.meta_of(blob))
    return out, meta, report


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--archives', type=Path, required=True)
    ap.add_argument('--scenario', required=True)
    ap.add_argument('--seconds', type=int, default=7200)
    ap.add_argument('--threads', type=int, default=4)
    ap.add_argument('--output', type=Path, required=True)
    a = ap.parse_args()
    torch.set_num_threads(a.threads)
    t0 = time.time()
    out, meta, report = evaluate(a.archives / f'{a.scenario}.zip', seconds=a.seconds)
    np.savez_compressed(a.output, **out)
    a.output.with_suffix('.json').write_text(json.dumps(dict(scenario=a.scenario, columns=COLUMNS, recordings=meta, report=report,
                                                             seconds=time.time() - t0)))
    print(json.dumps(dict(scenario=a.scenario, report=report, seconds=round(time.time() - t0))))


if __name__ == '__main__':
    main()
