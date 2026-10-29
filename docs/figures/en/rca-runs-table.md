| Run | Attacks with their own case | Grouped after the benign case | Top-1 / top-3 | Preview → case p95 (s) | Normal cases |
|---|---|---|---|---|---|
| pulse-stable-candidate | 86.7% (273/315) | 31 | 99.6% / 99.6% | 2.52 | 4765 |
| pulse-stable-refreshed | 86.7% (273/315) | 37 | 100.0% / 100.0% | 2.52 | 4867 |
| pulse-stable-confirm | 86.9% (456/525) | 56 | 99.8% / 99.8% | 2.50 | 3666 |
| pulse-peer-discount-confirm | 87.6% (459/524) | 44 | 99.8% / 100.0% | 2.59 | 575 |
| pulse-final-system-confirm | 89.3% (469/525) | 40 | 14.1% / 100.0% | 2.67 | 744 |

Top-1 / top-3: the attack fixture binary is the first / among the first three suspects (ranking recomputed with the frozen binary baseline, privilege-drop rule in every run). In the first four runs the benign and the attack binary shared one path, which inflates top-1; the last run ran the benign binary under its own name (RCA 5.17). The last run built cases from alerts Alertmanager delivered, the earlier ones from previews.
