# LID-DS 2019 with the final token model (lidds2019-confirmation-v2, 18/11/2026)

Protocol `sentinel_pulse/protocol/lidds2019-confirmation-v2.json` (registered 17/11 12:28, before any 2019 recording was
converted or scored). Run once on `.234` with `scripts/lidds2019_token_run.sh` (unit `lidds2019-v2`, 18/11 09:06–11:24
UTC, 2 h 55 min CPU, 14.5 GB peak): release sha256 checked (`c87e881d…56cf`: OK), 10 scenarios converted
(`sentinel_pulse/lidds/lidds2019.py`, per-scenario counts in `conversion/*.SUMMARY.json`), cross-fit token matrices
(`scripts/analysis/lidds_ml_token_crossfit.py`, unchanged; `crossfit-logs.txt`), one scoring
(`scripts/analysis/lidds2019_token.py score`) behind the gate of 17/11 (`gate.json`: the same code path reproduced the
registered LID-DS 2021 official result exactly). Model: lidds-ml-v5 token branch, alpha' = 0.00018, every parameter
unchanged.

## Result (`lidds2019.json`)

Criterion C1 (pooled recall ≥ 95 % AND false-alarm recordings ≤ 1.0 % AND latency p95 ≤ 3 s): **not met**.

| | Primary exploit time (first event + exploit_start_time) | Library convention (first event + warmup − 2 s), sensitivity |
|---|---|---|
| Detected | **723/1,162 (62.22 %)**, Wilson [59.40; 64.96] | 1,076/1,162 (92.60 %) [90.95; 93.97] |
| Normal recordings with a false alarm | **34/7,706 (0.44 %)** [0.32; 0.62] | same |
| Latency p50 / p95 | 1.22 s / **10.48 s** | 17.39 s / 34.19 s |
| Precision at the dataset's base rate | 95.51 % | 96.94 % |
| Detected within 3 s | 470 | 23 |

Per scenario, primary (detected, false alarms): Bruteforce_CWE-307 92/98, 5/744; CVE-2012-2122 91/155, 1/990;
CVE-2014-0160 24/100, 5/750; CVE-2017-7529 30/174, 0/733; CVE-2018-3760 52/137, 0/834; CVE-2019-5418 34/98, 0/731;
EPS_CWE-434 99/99, 8/722; PHP_CWE-434 103/103, 0/759; SQL_Injection_CWE-89 100/100, 13/728; ZipSlip 98/98, 2/715.
C2 names (recall < 90 % or false alarms > 3 %): CVE-2012-2122, CVE-2014-0160, CVE-2017-7529, CVE-2018-3760,
CVE-2019-5418.

Reported as registered: a failure, no re-run with other settings.

## Exploratory (not registered)

- Token detail is present in the 2019 conversion: on six attack recordings per scenario, the share of size tokens
  (2019 / 2021) is 0.352 / 0.324 for CVE-2017-7529, 0.272 / 0.183 for CVE-2014-0160, 0.234 / 0.203 for ZipSlip, and
  open tokens 0.071 / 0.080, 0.053 / 0.051, 0.039 / 0.015. Error-code tokens are rarer in 2019 for CVE-2017-7529
  (0.001 / 0.082) and CVE-2014-0160 (0.027 / 0.053): the 2019 traces may record failures differently.
- The library convention, which puts the exploit time earlier, lifts recall to 92.6 % with a median latency of 17 s:
  in many attack recordings the model alarms after the warm-up but before the registered exploit_start_time and not
  after it. Explaining this needs the exploit procedure of each scenario, which this project does not read (owner rule,
  15/11), so the cause is left open.

## Amendment 1 (registered 18/11 20:07, after the failure was seen): label resolution

Every exploit_start_time of the 2019 release is a whole number of seconds; of the 439 missed attack recordings, 353 had
an alarm window ending before the registered exploit time and none after it (mean gap 0.36 s), 86 had no alarm (76 of
them CVE-2014-0160). The amendment adds, beside the registered result, a tolerance equal to the label resolution: a
recording also counts as detected when an alarm window ends after (exploit time − 1 s). Normal recordings are unchanged.
Code: `scripts/analysis/lidds2019_token.py tolerance` (`tolerance.json`).

| | Registered rule | 1 s tolerance (post hoc) |
|---|---|---|
| LID-DS 2019 detected | 723/1,162 (62.22 %) | 1,056/1,162 (90.88 %), Wilson [89.08; 92.40] |
| LID-DS 2019 false-alarm recordings | 34/7,706 | 34/7,706 |
| LID-DS 2019 latency p50 / p95 | 1.22 / 10.48 s | 1.10 / 10.55 s |
| LID-DS 2021 official detected (same rule, same code path) | 1,238/1,271 | 1,238/1,271 (unchanged; latency +1 s by definition) |

Per scenario under the tolerance: Bruteforce_CWE-307 92/98, CVE-2012-2122 152/155, CVE-2014-0160 24/100,
CVE-2017-7529 157/174, CVE-2018-3760 133/137, CVE-2019-5418 98/98, EPS_CWE-434 99/99, PHP_CWE-434 103/103,
SQL_Injection_CWE-89 100/100, ZipSlip 98/98. C1 stays not met (recall 90.88 % < 95 %, p95 10.55 s > 3 s): CVE-2014-0160
(76 recordings without any alarm) and the latency of the brute-force and CVE-2014-0160 recordings remain. The registered
result above is the primary result.
