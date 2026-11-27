# Three-day fit for the final live run (26-27/11)

Fit directory: `/mnt/sentinel-pulse-archive/pulse-live-diurnal3-fit-1126` (NFS via .234). Steps run by
`scripts/final_fit_chain_1126.sh` (unit `final-fit-chain-1126`) and, after the by-program step failed, by
`scripts/final_fit_rest_1127.sh` (unit `final-fit-rest-1127`, by-program rerun `fit3-prog-1127b`). Step log: `chain.log`.

**Data.**
- Training and cross-fit data: capture `pulse-token-capture-diurnal2-1124`, both days under the diurnal profile, with routine operator commands.
- Extra runs:
  - capture `pulse-token-capture-diurnal-1121`, its whole 24 h;
  - the normal tail of `pulse-live-final-1119` after its campaign.
- Fit parameters are those of `pulse-live-diurnal-fit-1123`:
  - α′ 0.0003, top 3, trim 0.005, 60 s blocks;
  - 5-fold cross-fit over 30-min chunks;
  - moment Gumbel on held-out block maxima;
  - split files gzip-compressed (`--gzip-work`).

**t3 per workload** (`token-FIT.json`, `token-MODELS.json`, sha256 `d3a70755...`; `fit3-token-1126.log`). There are 21 models. Held-out blocks above threshold, pooled: 2,200 of 322,048 (0.683 %).

**A6** (`a6.json`, `a6-scale.json`). Pooled held-out exceedance is 0.683 % for t3 and 0.662 % with A6. Per regime, t3 → A6:

| regime | t3 | A6 |
|---|---|---|
| burst | 2.55 % | 2.44 % |
| peak | 1.09 % | 1.07 % |
| steady | 0.76 % | 0.72 % |
| toolmix | 0.57 % | 0.56 % |
| night | 0.46 % | 0.43 % |
| recovery | 0.45 % | 0.44 % |

10 of 21 workloads get a factor below 1. The lowest are rabbitmq at 0.682 and kafka-dual-role at 0.743.

**Pooled session model** (`session-pooled-*`, `fit3-session-1126.log`). Threshold 13.103 at α′ 0.00015 (share 0.5). Held-out blocks above threshold: 622 of 239,758.

**Alert-path configuration** (`SESSION-S1a-A6.json`, sha256 `efbc1acd...`):
- the native part of each window is scored against the workload's t3 threshold at α′ 0.0003 × the A6 factor;
- the session part is scored against the pooled session model;
- no per-workload session models.

**Per-program session models, B2** (`session-prog-*`, `fit3-prog-1127b.log`; exec-identity-v1, offline on the final run, not on its alert path).
- They are learnt from capture 1124 only. The first attempt failed because the extra runs were recorded with the earlier probe, which has no `session_prog`. exec-identity-v1 learns program models from the capture that records program identity.
- A minimum of 200 learning blocks is required. A program below it is scored by the pooled model.

| program | hash | blocks | threshold | held-out above |
|---|---|---|---|---|
| (session before its first exec) | 0 | 141,232 | 12.807 | 291 |
| python | 24586 | 115,240 | 5.837 | 1,342 |
| hostname | 10683 | 17,286 | 0.231 | 3 |
| redis-cli | 19409 | 17,286 | 0.842 | 1 |
| sh | 29178 | 17,286 | 4.743 | 42 |
| grep | 20721 | 8,679 | 1.195 | 37 |
| curl | 2153 | 8,643 | 6.758 | 49 |
| bash | 26022 | 8,643 | 5.455 | 1 |
| kafka_readiness | 23588 | 8,643 | 1.792 | 0 |
| kafka_liveness. | 32396 | 8,643 | 1.792 | 1 |
| readlink | 4345 | 8,643 | 1.792 | 0 |
| sleep | 10461 | 61 | below minimum | - |
| find | 32443 | 63 | below minimum | - |
| stat | 5345 | 57 | below minimum | - |
| wc | 3648 | 53 | below minimum | - |

Findings before the final run:
- **Four of the five routine operator commands fall below the minimum.** Capture 1124 holds about 60 learning blocks each for sleep, find, stat and wc, so they stay on the pooled model. grep has its own model because exec probes also run it.
- **hostname is already learnt.** Exec probes run it, so in B2 it is not a new program, although it is in the held-out operator set.
- **python's model is noisy.** Most exec probes run python, and its held-out exceedance is 1.16 %, against 0.26 % for the pooled session model.

**Datasets** (`datasets.json`; `improvement_round2.py datasets` on the current code, t3 score caches, development data).
- t3 reproduces LID-DS 2021 529/544 with 5 false-alarm recordings and p95 1.57 s.
- CB-DS 891/891 with 3.
- LID-DS 2019 development (1 s tolerance) 310/321 with 9.
- None of the changes for the final run (three-day cluster fit, A6, S1a) changes dataset scoring.
