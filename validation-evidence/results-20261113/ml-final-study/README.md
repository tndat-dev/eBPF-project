# ml-final-study-v1, parts A-D (12-13/11/2026)

Protocol `sentinel_pulse/protocol/ml-final-study-v1.json` (registered 12/11 21:50, before any code of the parts).
System under study: lidds-ml-v5 (token model alone) and the cluster models of `pulse-live-v5-fit-1110`.

| Part | Script | Receipt | Gate |
|---|---|---|---|
| A, B | `scripts/analysis/live_attribution.py` | `live-attribution.json` | 59,238 interval windows rescored, largest difference to the logged score 0.0 |
| C | `token_branch_fit.py --dump-maxima`, `scripts/analysis/cluster_threshold.py` | `refit-FIT.json`, `cluster-threshold.json` | refit Gumbel thresholds equal MODELS.json (difference 0.0) |
| D | `scripts/analysis/lidds_token_rate.py` | `rate-signal.json` | model arm reproduces 530/544, 6/3,403; CB-DS 891/891, 3/1,410 |

## A, live attribution (pulse-live-v5-1110)

| | Primary set (6, 12, 24/s) | All rates |
|---|---|---|
| As run | 314/314 | 521/522 |
| Attack-specific (grams of the same trial's benign and admin intervals removed) | 314/314 | 521/522 |
| Post-launch (alarm window ending >= 1.5 s after the start) | 302/314 | 414/522 |
| Detected only through launch grams | 0 | 0 |

Attack-specific first alarm from the interval start: p50 0.61 s, p95 0.73 s (primary). By rate, post-launch: 1/s 32/103,
3/s 80/105, 6/s 96/104, 12/s 103/105, 24/s 103/105. The live recall is not an artefact of the kubectl exec launch.

## B, operator activity learnt as normal, one admin command held out

Held-out admin flagged: 362/439 (82.5 %) against 422/439 (96.1 %) with the v5 models (all 439 admin intervals, including the
3 pairs without an attack interval; the arms analysis counts 419/436 on the pairs with one). Per command, flagged with the command held out vs with the v5 model, of n: cat 46 vs 49 of 49, date 33 vs 45 of 50, df 47 vs 51 of 51, env 31 vs 52 of 52, id 48 vs 51 of 51, ls 38 vs 44 of 44, ps 7 vs 7 of 7, python 33 vs 34 of 38, sh 45 vs 46 of 48, uname 34 vs 43 of 49.
With every command learnt: benign binary 285/314 (v5 314/314), attack 303/314 (v5 314/314), attack-specific 299/314, control 0/525.
Criteria (held-out admin <= 20 %, attack-specific within 2 points of v5) not met: negative result, the system is unchanged.

## C, cluster threshold

134,905 held-out 60 s blocks over 21 workloads; the v5 Gumbel leaves 350 above (0.259 %, design 0.018 %).

| Rule | Median threshold | Attack primary | Attack-specific primary | Benign primary | Admin all | Control | Burden (declared segments, episodes per replica-hour) | LID-DS development | CB-DS |
|---|---|---|---|---|---|---|---|---|---|
| Gumbel (v5) | 12.98 | 314/314 | 314/314 | 314/314 | 422/439 | 0/525 | 0.105 (10 in 94.9 h) | 530/544, 6 | 891/891, 3 |
| Empirical quantile at alpha' | 16.17 | 281/314 | 256/314 | 283/314 | 359/439 | 0/525 | 0.053 (5) | 498/544, 13 | 891/891, 2 |
| Matched quantile | 12.66 | 314/314 | 314/314 | 314/314 | 422/439 | 0/525 | 0.116 (11) | | |

The empirical quantile halves the burden but loses 33 primary attacks and, on LID-DS development, 32 recordings with more
false alarms: rejected. The Gumbel rule stays.

## D, rate signal over seen grams (LID-DS 2021 development, CB-DS)

| Arm | Development detected / 544 | False alarms / 3,403 | CB-DS detected / 891 | CB-DS false alarms / 1,410 |
|---|---|---|---|---|
| Model (v5) | 530 | 6 | 891 | 3 |
| Rate signal alone | 225 | 7 | 891 | 3 |
| Model or rate | 530 | 12 | 891 | 4 |

The rate score ignores unseen grams, so its 225/544 equals its result on the seen-only simulation, where the model detects
0/544. The registered criterion (model or rate: >= 530 with <= 12 false alarms, CB-DS 891 with <= 3, seen-only >= 6) fails on
one CB-DS false alarm: the signal does not join the model. Reported as a near miss; no change after the fact.

## Decision

No candidate of parts B-D met its registered criterion; the final ML model stays lidds-ml-v5. Next: part E (rules after the
ML) and the next live run (part F).

## Token probe load in pulse-live-v5-1110 (`scripts/analysis/token_load.py`, `token-load.json`)

Declared segments s00010, s00020, s00030, s00040, s00045 of the three workers.

| | p50 | p99 | Max |
|---|---|---|---|
| Events per container and 0.5 s window | 51 | 2,179 | 12,381 |
| Distinct 4-grams per container and window | 26 | 651 | 1,995 |
| Events per node and window (all watched containers) | 6,284 | 18,710 | 26,552 |
| Distinct 4-grams per node and window (map entries) | 1,950 | 5,450 | 6,901 |

The gram map holds 262,144 entries (about two windows live at once); the largest window used 2.6 % of it. The loader's
counters in the last segment of each worker (`token-drain-last-segment.json`; the loader restarts with each segment, so the
earlier segments' counters are not in the run's status files): 0 failed inserts, 0 cut directory walks, drain 3-7 ms.
The run did not drive the probe to its limit; the map-full load test is still to do (part F).

## Amendment 1: B2 and B3 (`scripts/analysis/session_model.py`, `session-model.json`)

B2, admin sessions of the other trial folds learnt into the workload model: held-out admin flagged 372/439 (84.7 %; v5 422/439).

B3, lineage proxy (session = grams unseen by the v5 workload model, native = the rest):

| Arm | Result |
|---|---|
| Native arm, v5 model and threshold | control 0/525, admin 0/439, benign 0/523, attack 1/522 |
| Session model, known tools (cross-fit) | 0/439 flagged, threshold 37.7 |
| Session model, unseen tool (one command out) | 0/439 |
| Unknown program (benign binary, tools-only model) | 0/523 |
| Learnt program (benign binary of other folds learnt) | 0/523, threshold 42.4 |
| Attack, tools-only model | 0/522 |
| Attack, tools and benign binary learnt | 0/522 |

Registered decision: native <= 5 % met, known tools <= 20 % met, attack >= 95 % not met (0 %): the lineage tag is not built on
this basis. The Gumbel rule on a few hundred short sessions gives a threshold above every measured score.

Exploratory (no decision uses it), held-out interval maxima under the tools + benign session model: benign binary median 0.96,
max 7.47; admin median 11.09, p99 22.14, max 23.81; primary attacks median 17.31, min above the largest benign (314/314), AUC
attack vs benign 1.00, attack vs admin 0.73; at the p99 of admin and benign maxima 105/314 primary attacks are above.
