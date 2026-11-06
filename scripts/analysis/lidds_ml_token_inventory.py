#!/usr/bin/env python3
"""Which syscalls' exit information do the lidds-ml-v2 tokens need? Development recordings only, descriptive.

The cheap token alphabets (lidds_ml_token_alphabets.py) lose 5-10 recall points, so the probe needs some exit
information; a hook on every exit is too expensive, a per-syscall fexit costs only on that syscall. This counts, for
every development recording, the (syscall, kind) pairs that appear in something the training recordings never had:
an unseen token, or the last token of an unseen 4-gram. kind is err (errno), open (mode + directory), size (I/O size)
or name. Attack recordings count only after the first exploit time.

    python3 lidds_ml_token_inventory.py --archives DIR --scenario NAME --alarms alarms.json.gz --output out.json
"""
import argparse
from collections import Counter
import json
from pathlib import Path
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lidds_ml_tokens as tk  # noqa: E402
import lidds_ml_token_alphabets as ta  # noqa: E402

signals, convert, v2 = tk.signals, tk.convert, tk.v2


def kind(tok):
    return 'err' if '!' in tok else 'open' if ':' in tok else 'size' if '#' in tok else 'name'


def novel(per, seen_tokens, seen_grams, after=None):
    """{(syscall, kind) -> number of windows} of the unseen tokens and of the last token of unseen grams."""
    out = Counter()
    for w, grams in per.items():
        if after is not None and w <= after:
            continue
        hit = set()
        for g in grams:
            t = g[-1]
            if t not in seen_tokens or (len(g) == tk.N and g not in seen_grams):
                hit.add((tk.base_name(t), kind(t)))
        out.update(hit)
    return out


def evaluate(archive, wanted):
    seen_tokens, seen_grams = set(), set()
    for _, _, blob in v2.split_recordings(archive, {'training'}):
        for grams in tk.window_tokens(convert.recording(blob)[1]).values():
            for g in grams:
                seen_tokens.add(g[-1])
                if len(g) == tk.N:
                    seen_grams.add(g)
    out = {}
    for split, name, blob in v2.split_recordings(archive, {'test-normal', 'test-normal_and_attack'}):
        if not wanted(name, split):
            continue
        exploit = tk.meta_of(blob)
        per = tk.window_tokens(convert.recording(blob)[1])
        c = novel(per, seen_tokens, seen_grams, exploit if split == 'test-normal_and_attack' else None)
        out[name] = dict(split=split, exploit=exploit, novel={f'{s}|{k}': n for (s, k), n in c.items()})
    return out, len(seen_tokens), len(seen_grams)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--archives', type=Path, required=True)
    ap.add_argument('--scenario', required=True)
    ap.add_argument('--alarms', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    a = ap.parse_args()
    t0 = time.time()
    out, nt, ng = evaluate(a.archives / f'{a.scenario}.zip', ta.development_only(a.alarms, a.scenario))
    a.output.write_text(json.dumps(dict(scenario=a.scenario, seen_tokens=nt, seen_grams=ng, recordings=out, seconds=time.time() - t0)))
    print(json.dumps(dict(scenario=a.scenario, recordings=len(out), seconds=round(time.time() - t0))))


if __name__ == '__main__':
    main()
