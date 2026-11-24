# load-threshold-v1 and the S1 dataset check (24/11)

Protocol `sentinel_pulse/protocol/load-threshold-v1.json` (registered 23/11 09:49 +07 before any computation).
Code `sentinel_pulse/detector/load_threshold.py`, `scripts/analysis/load_threshold_study.py`.

**Datasets** (`datasets.json`, development data from the t3 score caches; L0 reproduces t3: LID-DS 2021 development
529/544 with 5 false-alarm recordings, CB-DS 891/891 with 3, LID-DS 2019 development 310/321 with 9):

| Candidate | LID-DS 2021 dev (detected / false alarms) | CB-DS false alarms | LID-DS 2019 dev (detected / false alarms) |
|---|---|---|---|
| L0 (t3) | 529 / 5 | 3 | 310 / 9 |
| L2 per bin / split | 529 / 16, 529 / 13 | 3, 3 | 310 / 16, 310 / 13 |
| L3 per bin / split | 529 / 23, 529 / 16 | 5, 4 | 310 / 24, 310 / 19 |
| L4 per bin / split | 530 / 34, 529 / 18 | 10, 7 | 310 / 28, 310 / 16 |

**Cluster** (`cluster.json`, held-out block maxima per event class of `pulse-live-diurnal-fit-1123`; L0 reproduces the
diurnal fit's held-out exceedance): pooled share of 60 s blocks above threshold L0 0.706 %, L2 0.972 / 0.708 %, L3
1.200 / 0.767 %, L4 1.441 / 0.861 %; burst 4.10 % (L0) against 3.70–7.65 %, peak 1.10 % against 0.95–1.85 %.

**Selection** (`selection.json`): no candidate meets the must-rules (every one raises dataset false alarms 2 to 7
times, none lowers the cluster's pooled exceedance): **L0 stays**. The extra alarms under heavy load are not explained
by the window's event count.

**S1 on the datasets** (`s1-dev-alpha.py`, development caches): S1 as evaluated in session-stream-v1 scores the native
part at alpha' 0.00015; on a dataset (no session lineage) that is t3 at 0.00015: LID-DS 2021 development **523/544**
with 5 false alarms (p95 1.67 s), CB-DS 891/891 with 2, LID-DS 2019 development 310/321 with 3. Amendment 1's statement
that S1 equals t3 on datasets was wrong; by its own rule (any dataset difference blocks the adoption) S1 is blocked.

**S1a** (`session-stream-s1a.json.gz`, `scripts/analysis/session_stream.py --branch-alpha 0.0003`): the native part at
t3's own threshold (alpha' 0.0003), the session part by the pooled session model at 0.00015. On datasets S1a is t3 by
construction (no session events). On `pulse-live-final-1119`: primary attacks 296/296, lotl 666/666, event generator
549/556, idle control 0/694, burden **0.273** episodes per replica-hour (S0 0.362, S1 0.253).

Diurnal pooled session model for the final run (`diurnal-session-pooled-FIT.json`): 3,010,732 session windows of the
diurnal capture plus the final run's normal tail, 98,525 blocks, threshold 13.18 at alpha' 0.00015, 293 held-out above.
