# LID-DS 2019 development study (protocol `lidds2019-development-v1`, registered 18/11 20:28)

Run on `.234` 18/11 13:31–13:48 UTC (unit `lidds2019-dev`, MemoryMax 20 GB, peak 614 MB), code
`scripts/analysis/lidds2019_dev.py` via `scripts/lidds2019_dev_run.sh`. Only the development part was cached and scored;
no holdout recording was read.

- **Split** (`split.json`, sha256 rule of the protocol): development 321 attack + 2,311 normal test recordings,
  holdout 841 attack + 5,395 normal.
- **Gate** (`gate.json`): the base spec on the development caches gives exactly the registered lidds-ml-v5 decisions on
  the same recordings (197/321, 6/2,311 false-alarm recordings, p95 10.22 s). Passed.
- **Study** (`study.json`): 23 candidates (n 3/5, top-k 1/3/5/20, seven α′ levels, four trims, add-one alphabet changes
  present in the 2019 data), each on the development part with the registered exploit time and with the 1 s label
  tolerance of amendment 1, beside its LID-DS 2021 development / CB-DS numbers from the token-design-study-v1 receipts.

| Candidate | 2019 development, 1 s tolerance | False-alarm recordings | p95 | LID-DS 2021 development / CB-DS | Must-rules |
|---|---|---|---|---|---|
| base (lidds-ml-v5) | 295/321 (91.9 %) | 6/2,311 | 10.08 s | 530 / 6, 891 / 3 | pass |
| top5 | 310/321 (96.6 %) | 6/2,311 | 11.13 s | 529 / 7, 891 / 3 | fail (2021) |
| n5 | 310/321 | 8/2,311 | 11.13 s | 526 / 6, 891 / 3 | fail (2021) |
| top3 | 310/321 | 8/2,311 | 11.13 s | 528 / 5, 891 / 3 | fail (2021) |
| α′ 0.001 | 310/321 | 18/2,311 | 11.13 s | 530 / 15, 891 / 3 | fail (2021) |
| add-size-select | 295/321 | 6/2,311 | 10.08 s | 530 / 6, 891 / 3 | pass (no gain) |

**Outcome under the protocol:** only base and add-size-select pass the must-rules, and neither improves the development
recall, so the system stays **lidds-ml-v5**; by the protocol's no-change rule nothing more is scored (no LID-DS 2021
official rerun, no holdout scoring).

Reading: every candidate that gains does so on CVE-2014-0160 only (development 7/23 → 22/23 with top5, n5, top3 or a lower
threshold); the other nine scenarios do not move. No candidate brings the p95 near 3 s (9.4–11.1 s): the latency of
Bruteforce_CWE-307 (p95 14.1 s) and CVE-2014-0160 (11.5 s) does not depend on these parameters, so C1 is out of reach for
every candidate tried, including the ones that fail the LID-DS 2021 rule.
