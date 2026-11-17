# Gate of lidds2019-confirmation-v2 (17/11/2026)

`scripts/analysis/lidds2019_token.py gate` on `.234` (unit `lidds2019-gate`, 2 MB peak, 6 s), inputs: the LID-DS 2021
cross-fit token matrices `/var/tmp/lid-ds-2021/ml-v4-tokens` (column xfit, the matrices of the registered lidds-ml-v5
official result) and the alarms inventory `validation-evidence/results-20261101/lidds-v4/lidds-evaluation-v2-alarms.json.gz`.

| | Registered (lidds-ml-v5 official) | Reproduced by the 2019 driver |
|---|---|---|
| Detected | 1,238/1,271 | 1,238/1,271 |
| Normal recordings with a false alarm | 26/7,938 | 26/7,938 |
| Latency p95 | 1.47 s | 1.47 s |

Passed: the decision and metric path of the driver equals the one of the registered result. What the gate does not cover:
the 2019 conversion (`sentinel_pulse/lidds/lidds2019.py`, tested) and the token extraction, which is
`lidds_ml_token_crossfit.py` unchanged. Nothing of LID-DS 2019 has been converted or scored; the run comes after
pulse-live-v6-1117.
