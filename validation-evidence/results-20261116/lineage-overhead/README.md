# Cost of the lineage tag (token-probe-overhead-v1 amendment 3, 16/11/2026)

`scripts/overhead_ab.sh` on the three workers at the same time, 5 rounds, 10 s per mode, conditions rotated each round,
no live run or collector active. Builds: tokD_base = `/home/dat/pulse-tokens-20261110/build` (the build of
pulse-live-v5-1110); tokD and tokD_filtered = `/home/dat/pulse-tokens-lineage-5fc5f37/build` (lineage tag, commit 5fc5f37, token
proof and lineage proof valid on all three workers before the timing). Analysis: `scripts/analysis/overhead_ab.py`
(`overhead-lineage.json`); raw rows: `k8s-worker*.jsonl`.

Median ns per operation, and the lineage build against the v5 build (paired by round, 95 % bootstrap CI of the ratio):

| Node | Mode | off | tokD_base (v5) | tokD (lineage) | Lineage vs v5 |
|---|---|---|---|---|---|
| worker1 | getpid | 1,047 | 1,428 | 1,420 | -0.6 % [-5.4; 6.7] |
| worker1 | futex | 1,112 | 1,604 | 1,565 | -2.4 % [-5.9; -0.9] |
| worker1 | openclose | 7,921 | 9,734 | 9,288 | -1.1 % [-7.2; 1.6] |
| worker1 | forkwait | 376,248 | 384,559 | 373,544 | -3.2 % [-6.9; 7.0] |
| worker3 | getpid | 1,102 | 1,493 | 1,426 | 3.7 % [-5.9; 7.8] |
| worker3 | futex | 1,141 | 1,620 | 1,616 | 0.5 % [-5.0; 6.6] |
| worker3 | openclose | 7,633 | 8,968 | 9,438 | 5.6 % [-1.8; 22.1] |
| worker3 | forkwait | 332,221 | 339,448 | 340,797 | 1.5 % [-2.8; 4.6] |
| worker4 | getpid | 1,029 | 1,516 | 1,467 | -0.5 % [-5.1; 10.5] |
| worker4 | futex | 1,114 | 1,618 | 1,645 | 0.7 % [-1.5; 2.2] |
| worker4 | openclose | 7,655 | 9,628 | 9,543 | 1.6 % [-3.9; 20.0] |
| worker4 | forkwait | 338,589 | 344,968 | 343,651 | 0.6 % [-5.6; 2.4] |

(Ratios are medians of per-round ratios, so they need not match the ratio of the medians.)

The lineage tag adds no cost that this setup can resolve: every interval of the paired ratio but one contains 0, and the
one that does not is negative. A fork with exit and wait costs 330-380 us on these VMs, so the fork hook is far below the
run-to-run noise of that path. The token probe as a whole (v5 build against off) still adds about 0.4-0.5 us per simple
syscall and 1.3-2.0 us per open + close, as measured on 07/11.
