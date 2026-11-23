# session-stream-v1 (protocol `sentinel_pulse/protocol/session-stream-v1.json`, registered 21/11 19:55 +07)

Session models (`scripts/analysis/token_branch_fit.py --part session`, unit `session-fit-1122`, 22/11 15:41–17:23 UTC)
learnt from capture `pulse-token-capture-v6-1116` plus the final run's selection prefix: pooled (`pooled-FIT.json`,
1,199,956 session windows, 39,530 blocks, threshold 13.79 at α′ 0.00015, 172 held-out blocks above) and per workload
(`per-FIT.json`, 13 workloads with ≥ 200 blocks).

**S0/S1/S2 on pulse-live-final-1119** (`session-stream.json.gz`, `scripts/analysis/session_stream.py`, unit
`session-stream-1123`, H0 denominators; S0 reproduces the H0 counts and the 0.362 burden):

| | Attack (primary) | Lotl | Event generator | Control | Admin | Harmless binary | Burden (episodes per replica-hour) |
|---|---|---|---|---|---|---|---|
| S0 (t3 whole window) | 296/296 | 666/666 | 549/556 | 0/694 | 585/606 | 672/672 | 0.362 (223) |
| S1 (native t3 or pooled session) | 296/296 | 666/666 | 549/556 | 0/694 | 594/606 | 672/672 | 0.253 (156) |
| S2 (per-workload session where fitted) | 296/296 | 666/666 | 549/556 | 0/694 | 587/606 | 672/672 | 0.281 (173) |

Decision: the registered burden level is ≤ 0.24; S1 (−30 %, no recall loss) and S2 fail it, **not adopted**, so no
LID-DS rerun. Admin and harmless-binary flags do not change.

**S3, learnt triage** (`s3-triage.json`, `scripts/analysis/session_triage.py`; v6 features `v6-session-features.json.gz`,
whose S0 reproduces the v6 receipts): leave-one-family-out over 3,166 flagged session intervals: operator commands
passed 0–11 % each, but the harmless binary 61 % (it is the attack fixture's binary in benign mode), held-out fixture
scenarios recognised 13–50 %, lotl 31 %, event-generator actions 77–93 %; cross-run (train final, test v6): attacks 77 %,
benign 5.6 %. Criteria (every attack family ≥ 90 %, benign ≤ 20 %; cross-run attacks ≥ 95 %) fail: **not adopted**. The
classifier learns the campaign's families, not intent.
