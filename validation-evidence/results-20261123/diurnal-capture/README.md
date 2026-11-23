# Diurnal capture and fit (protocol `sentinel_pulse/protocol/load-diurnal-v1.json`, steps C, A, F)

**C, capture** `pulse-token-capture-diurnal-1121`: 21/11 19:56:57 → 22/11 19:56:57 (+07), 86,400 s on each worker,
probe `pulse-tokens-final-f8ccbb2`, snapshot `runtime-2c8769f-20261121`, diurnal profile seed 65817 (19/19 phases
applied, 0 errors), `insert_fail` 0 on all workers, issues only `cadence_gap` (3 / 7 / 0), 2,966 Kubernetes events.
Hours per regime: peak 5.72, steady 5.78, night 5.86, toolmix 3.41, recovery 2.76, burst 0.47.

**A, steady-trained t3 on diurnal data** (`aging.json`, `scripts/analysis/model_aging.py --by-regime --design-alpha
0.0003`, models `pulse-live-v7-fit-1118`, unit `diurnal-aging-1122`; the first run of this step scored t3 with top 10
because the script ignored MODELS.json `top`; fixed, rerun, the wrong output discarded):

| Regime | 60 s blocks | Above threshold | Share | Replica-hours | Episodes | Per replica-hour |
|---|---|---|---|---|---|---|
| burst | 3,216 | 151 | 4.70 % | 52.8 | 151 | 2.86 |
| peak | 20,904 | 321 | 1.54 % | 344.7 | 337 | 0.98 |
| toolmix | 11,457 | 76 | 0.66 % | 187.9 | 76 | 0.40 |
| recovery | 11,129 | 68 | 0.61 % | 181.6 | 68 | 0.37 |
| steady | 24,731 | 132 | 0.53 % | 403.4 | 127 | 0.32 |
| night | 23,867 | 120 | 0.50 % | 386.0 | 121 | 0.31 |
| pooled | 95,499 | 869 | 0.91 % (design 0.03 %) | 1,559.3 | 880 | 0.56 |

The steady level (0.32) matches the final run's normal tail (0.36); peak and burst carry 3 and 9 times as many alarms.

**F, diurnal t3 fit** `pulse-live-diurnal-fit-1122` (`diurnal-fit-FIT.json`; capture train 80 % / validation 20 % plus
the final run's normal tail, 5-fold cross-fit over 30 min chunks, top 3, trim 0.005, α′ 0.0003; 4 h 47 min CPU; 21
models). Held-out block exceedance per regime (`fit-regime.txt`, `scripts/analysis/fit_regime_exceedance.py`): burst
4.10 %, peak 1.10 %, toolmix 0.69 %, final-run tail (steady) 0.56 %, steady 0.53 %, recovery 0.49 %, night 0.43 %,
pooled 0.71 %. One capture day holds two bursts, each in one 30 min chunk, so a held-out burst learns from the other
one only (the protocol's stated limit).
