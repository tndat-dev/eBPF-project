# Partial deep-learning baselines (stopped by the owner, 02/11)

Totals over all test recordings of each scenario (not split into development/official, not a comparison). Paused before the full run finished; `parts.tar.gz` keeps every per-recording row. Commits of the LID-DS library and ContainerHIDS: `library-commits.txt`.

| Scenario | Arm | Detected | False-alarm normal recordings | Note |
|---|---|---|---|---|
| Bruteforce_CWE-307 | chids | 134/139 | 120/768 |  |
| Bruteforce_CWE-307 | chids_maxval | 130/139 | 11/768 |  |
| Bruteforce_CWE-307 | lstm | 40/139 | 4/768 |  |
| Bruteforce_CWE-307 | mlp | 127/139 | 3/768 |  |
| CVE-2012-2122 | chids | 120/120 | 0/762 |  |
| CVE-2012-2122 | chids_maxval | 120/120 | 1/762 |  |
| CVE-2012-2122 | lstm | 120/120 | 31/762 |  |
| CVE-2012-2122 | mlp | 120/120 | 4/762 |  |
| CVE-2014-0160 | chids | 0/120 | 8/758 |  |
| CVE-2014-0160 | chids_maxval | 2/120 | 33/758 |  |
| CVE-2014-0160 | lstm | 120/120 | 32/758 |  |
| CVE-2014-0160 | mlp | 0/120 | 1/758 |  |
| CVE-2017-12635_6 | chids | 119/119 | 0/753 |  |
| CVE-2017-12635_6 | chids_maxval | 119/119 | 12/753 |  |
| CVE-2017-7529 | lstm | 0/119 | 0/729 |  |
| CVE-2017-7529 | mlp | 10/119 | 2/729 |  |
| CVE-2018-3760 | chids | 122/122 | 1/737 |  |
| CVE-2018-3760 | chids_maxval | 122/122 | 3/737 |  |
| CVE-2018-3760 | lstm | - | - | stopped at the 8 CPU-hour cap |
| CVE-2018-3760 | mlp | 0/122 | 1/737 |  |
| CVE-2019-5418 | chids | 120/120 | 11/760 |  |
| CVE-2019-5418 | chids_maxval | 120/120 | 14/760 |  |
| CVE-2019-5418 | mlp | 0/120 | 0/760 |  |
| CVE-2020-13942 | chids | 118/118 | 748/756 |  |
| CVE-2020-13942 | chids_maxval | 0/118 | 0/756 |  |
| CVE-2020-23839 | chids | 120/120 | 4/760 |  |
| CVE-2020-23839 | chids_maxval | 120/120 | 27/760 |  |
| CVE-2020-23839 | lstm | 120/120 | 10/760 |  |
| CVE-2020-23839 | mlp | 120/120 | 24/760 |  |
| CVE-2020-9484 | chids | 120/120 | 0/759 |  |
| CVE-2020-9484 | chids_maxval | 120/120 | 4/759 |  |
| CVE-2020-9484 | mlp | 120/120 | 9/759 |  |
| CWE-89-SQL-injection | chids | 120/120 | 1/760 |  |
| CWE-89-SQL-injection | chids_maxval | 120/120 | 7/760 |  |
| CWE-89-SQL-injection | lstm | - | - | stopped at the 8 CPU-hour cap |
| CWE-89-SQL-injection | mlp | 0/120 | 7/760 |  |
| EPS_CWE-434 | chids | 121/121 | 497/759 |  |
| EPS_CWE-434 | chids_maxval | 121/121 | 0/759 |  |
| Juice-Shop | chids | 75/121 | 1/760 |  |
| Juice-Shop | chids_maxval | 75/121 | 8/760 |  |
| PHP_CWE-434 | chids | 118/118 | 0/760 |  |
| PHP_CWE-434 | chids_maxval | 118/118 | 5/760 |  |
| PHP_CWE-434 | lstm | - | - | stopped at the 8 CPU-hour cap |
| PHP_CWE-434 | mlp | 118/118 | 6/760 |  |
| ZipSlip | chids | 115/118 | 0/760 |  |
| ZipSlip | chids_maxval | 116/118 | 12/760 |  |

Not finished: MLP and LSTM on Juice-Shop, ZipSlip, EPS_CWE-434, CVE-2017-12635_6, CVE-2020-13942; LSTM on CVE-2020-9484 and CVE-2019-5418 (killed at the unit's 40 GB memory cap); CHIDS on CVE-2017-7529 (runner fixed, not rerun); nothing on CB-DS.
