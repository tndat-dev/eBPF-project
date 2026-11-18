# improvement-round-v1 (registered 19/11 02:30, amendments 02:31 and later): results

Reference: lidds-ml-v5-t3 (top 3, trim 0.5 %, α′ 0.0003). Must-rule (lidds2019-development-v1 amendment 1): LID-DS 2021
development ≥ 529/544 with ≤ 6 false alarms, p95 ≤ 1.60 s, CB-DS ≥ 891 with ≤ 3; 2019 development false alarms ≤ 1 %.

## D13 io_uring (19/11)
`io_uring_setup` from a production pod (seccomp RuntimeDefault): **EPERM**; `/proc/sys/kernel/io_uring_disabled` = 0, so
seccomp blocks it. The io_uring path is closed by the runtime profile, and the probe's seccomp hook sees every attempt.

## D4, D14, D15, D16 (`improvement-offline.json`, `scripts/analysis/improvement_offline.py`, .234 19/11 19:3x UTC)

| Candidate | LID-DS 2021 dev (det / FA, p95) | CB-DS | 2019 dev, 1 s tolerance (det / FA) | Must |
|---|---|---|---|---|
| t3 (reference) | 529 / 5, 1.57 s | 891 / 3 | 310 / 9 | yes |
| D4 top-3 OR top-10 (5 splits) | 530 / 7 | 891 / 3 | 310 / 5–9 | no (7 > 6) |
| D15 Shewhart-CUSUM (4 settings) | 530–531 / 9–46 | 891 / 3–4 | 318 / 8–28 | no |
| D14 Kneser-Ney, top 3 | 530 / 6, 1.56 s | 891 / **0** | 288 / 7 | yes, but fewer 2019 detections |
| D14 Kneser-Ney, top 10 | 491 / 6 | 891 / 0 | 287 / 5 | no |
| D16 GEV pooled shape, censor 1, α′ 0.00018 | 529 / 5 | 891 / 3 | 310 / **3** | yes, better than t3 |
| D16 GEV pooled shape, censor 1, α′ 0.0003 | 529 / 6 | 891 / 3 | 310 / 5 | yes |
| D16 censor 2–3 | 529–530 / 8–15 | 891 / 3–4 | 310 / 3–11 | no |

Pooled GEV shape (top 3, censor 1): −0.02 (2021), +0.01 (2019), close to Gumbel.

**Official check of the passing D16 (`improvement-official2021.json`)**, LID-DS 2021 official, same scores as the amendment-1 run
(t3 reproduces 1,236/1,271 with 15 false alarms):

| | Detected | False-alarm recordings | p95 |
|---|---|---|---|
| t3 | 1,236 / 1,271 | 15 / 7,938 | 1.54 s |
| D16 censor 1, α′ 0.00018 | 1,233 / 1,271 | 15 / 7,938 | 1.54 s |
| D16 censor 1, α′ 0.0003 | 1,236 / 1,271 | 16 / 7,938 | 1.54 s |

The development gain of D16 (fewer 2019 false alarms) does not hold on the official part (three detections fewer, no false
alarm fewer). **Not adopted; t3 stays.** D4, D14, D15 fail their criterion.
