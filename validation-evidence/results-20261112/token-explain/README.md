# token-explain: worked examples of the token model on LID-DS 2021 development

`scripts/analysis/lidds_token_explain.py` on the development caches of token-design-study
(`/var/tmp/lid-ds-2021/token-study/cache` on .234), alphabet select1f, registered rule
(5-fold cross-fit, held-out maximum per recording, top 1 % dropped, moment Gumbel, alpha' = 0.00018).
Read only: nothing here feeds a decision.

The example recording is the first attack recording in name order that fires after its exploit (no choice by result).
Each file holds the threshold and its parts, the example's alarm window (10 events that make the score and the
Witten-Bell backoff of the most surprising one), the same recording's highest window before the exploit, and the
highest window of all development normal test recordings.

Reproduction check (the registered development result of lidds-ml-v5, gate.json of token-design-study):

| Scenario | Detected | False alarm recordings | Threshold | Example | Alarm after exploit | Score |
|---|---|---|---|---|---|---|
| CVE-2019-5418 | 36/36 | 0/228 | 27.61 | aggressive_torvalds_8369 | 0.25 s | 31.68 |
| ZipSlip | 35/35 | 0/228 | 18.98 | black_colden_5565 | 0.54 s | 28.01 |
| CVE-2014-0160 | 36/36 | 0/227 | 6.05 | big_hypatia_2386 | 0.49 s | 9.27 |
