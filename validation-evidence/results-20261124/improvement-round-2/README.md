# improvement-round-2 (24/11)

Protocol `sentinel_pulse/protocol/improvement-round-2.json` (registered 24/11 14:15 +07 before any score of the
candidates). Code `scripts/analysis/improvement_round2.py`, `scripts/analysis/lidds_token_study.py` (spec options
`mask_calls`, `distinct`, `persist`), `sentinel_pulse/detector/token_model.py` (`window_score` options),
`scripts/analysis/token_branch_fit.py` (`--score-mask`, `--score-distinct`, `--persist`).

**Datasets** (`datasets.json`, development data from the t3 score caches; the t3 gate reproduces t3: LID-DS 2021
development 529/544 with 5 false-alarm recordings, CB-DS 891/891 with 3, LID-DS 2019 development 310/321 with 9).
Must: LID-DS 2021 >= 529 with <= 5 and p95 <= 1.6 s, CB-DS 891 with <= 3, LID-DS 2019 >= 310 with <= 9.

| Candidate | LID-DS 2021 dev (detected / false alarms / p95 s) | CB-DS (detected / false alarms) | LID-DS 2019 dev (detected / false alarms) | Must |
|---|---|---|---|---|
| t3 | 529 / 5 / 1.57 | 891 / 3 | 310 / 9 | yes |
| A2 mask (futex, sched_yield, rt_sigreturn) | 526 / 5 / 1.50 | 891 / 3 | 310 / 13 | no |
| A3 distinct grams | 528 / 4 / 1.64 | 891 / 2 | 309 / 8 | no |
| A2 + A3 | 527 / 4 / 1.45 | 891 / 3 | 309 / 12 | no |
| A4 two-window persistence | 286 / 3 / 7.18 | 808 / 0 | 159 / 12 | no |
| A5 Kneser-Ney (kn-n4) | 530 / 6 / 1.56 | 891 / 0 | 288 / 7 | no |

None of A2-A5 meets the dataset must-rules, so none goes to the cluster step.

**A6, per-workload alpha'** (`a6.json`, `a6-scale.json`; held-out 60 s block maxima of the diurnal fit
`pulse-live-diurnal-fit-1123`, 5-fold cross-fit over 30 min chunks). Scale = min(1, pooled exceedance / workload
exceedance); 9 of 21 workloads keep 1.0, the lowest is order-service 0.768. Pooled share of blocks above threshold:
t3 0.706 %, A6 **0.678 %** (must: below 0.706 %). Per regime (t3 -> A6): burst 4.10 -> 3.98 %, peak 1.10 -> 1.06 %,
toolmix 0.69 -> 0.63 %, steady 0.52 -> 0.49 %, recovery 0.49 -> 0.47 %, night 0.43 -> 0.42 %.

**Attacks on pulse-live-final-1119 intervals** (`intervals-s1a-a6.txt`, H0 denominators, diurnal models): S1a and
S1a + A6 both give primary 100 %, PAD 300 100 %, on-off 100 %, 0.1 and 0.5 per s 100 %, lotl 100 %, event generator
98.7 %, idle control 0 %, p95 kernel -> end of alarm window 0.49 s. **A6 is adopted** (every must-rule met).

**B1, leave-one-command-out operator sessions** (`b1.json`, `b1-log.txt`; run 26/11 on .234, unit `b1-1126`, the faster
evaluation: native part scored once, session model per held-out command = pooled model of fit 1123 plus the other
commands' operator sessions of `pulse-live-final-1119` and `pulse-live-v6-1117`). The S1a + A6 line reproduces the earlier
receipt exactly (primary 100 %, PAD 300 100 %, on-off 100 %, 0.1 and 0.5 per s 100 %, lotl 100 %, event generator 98.7 %,
idle control 0 %, p95 0.49 s). Operator sessions flagged, held-out command (B1) against S1a + A6 without B1:

| held out | with B1 | without B1 |
|---|---|---|
| find | 50/50 | 50/50 |
| grep | 57/57 | 57/57 |
| head | 65/66 | 65/66 |
| hostname | 42/52 | 44/52 |
| ls_tmp | 58/58 | 58/58 |
| printenv | 54/65 | 65/65 |
| sleep | 67/68 | 67/68 |
| stat | 67/67 | 67/67 |
| wc | 70/71 | 70/71 |
| whoami | 51/52 | 51/52 |
| **all** | **581/606 (95.9 %)** | **594/606 (98.0 %)** |

The per-command count without B1 comes from the rerun of 27/11 (unit `b1-1127`, `admin_without_b1`; the S1a + A6 line and
every with-B1 count equal the 26/11 run). Every attack family stays as without B1 for every held-out command (p95 0.49 s).
B1 lowers the flagged sessions for two commands only (printenv 65 -> 54, hostname 44 -> 42) and leaves eight unchanged:
learning other commands' sessions in the pooled model hardly carries over to a new command. The rule ("flagged lower on
the held-out command") holds for 2 of 10 commands, so B1 is not adopted. In the final fit the routine commands (find,
grep, sleep, stat, wc) are learnt from capture 1124 as normal operations (exec-identity-v1), the held-out commands are
not learnt.

**Not offline**: B2 (program identity of exec sessions) is protocol `exec-identity-v1` (receipts in
`../exec-identity/`); B3 (Kubernetes pods/exec audit) comes last, after the model is fixed.
