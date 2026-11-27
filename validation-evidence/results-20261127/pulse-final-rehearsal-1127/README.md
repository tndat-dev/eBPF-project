# Rehearsal of the final live run (27/11)

`pulse-final-rehearsal-1127`, snapshot `runtime-9f2d90b-20261127`, launched 27/11 18:37 (+07) with the final run's options:
- alert path S1a + A6 (`TOKEN_SESSION=pulse-live-diurnal3-fit-1126/SESSION-S1a-A6.json`, three-day t3 models);
- probe `pulse-tokens-prog-bee57bf`;
- diurnal traffic profile;
- campaign options of pulse-live-final-v1;
- `REHEARSAL=1`: 2-min selection, 6 trials on workloads with unusual paths or images;
- 1800 s.

It only checks that every step runs and sets the duration. It is not evidence for any hypothesis.

**Worker data.**
- Every decision row carries the native score and threshold, which is the t3 threshold times the A6 factor.
- Every decision row carries the session score and the pooled session threshold (13.103).
- Every decision row carries the alert stream.
- `tokens.jsonl` has `session_prog` rows and `prog_names` lines (sh, hostname, redis-cli).

**Token alerts inside each step's own span** (start to the next step's start). The time is from the step start to the end of the first alarm window. Every alarm came from the session stream.

| step | flagged | first alarm |
|---|---|---|
| attack | 6/6 | 0.22-0.57 s |
| event generator | 6/6 | 0.31-0.64 s |
| living off the land | 5/6 | 0.31-0.64 s |
| harmless binary | 6/6 | 0.24-0.70 s |
| operator command | 3/6 | 0.47-0.58 s |
| idle control | 0/6 | - |

**Other steps.**
- The event generator gave 4 executed, 1 error and 1 skipped (expected outcomes).
- Kubernetes events were recorded (157 lines).
- The bridge pushed alerts to Alertmanager (32 pushes) and RCA built cases (31).
- Trial spacing was 136.9-139.3 s, as for pulse-final-rehearsal-1119 (138 s).

**Duration of the final run.** The campaign takes 945 trials × about 138.5 s ≈ 36.4 h, after a 1.5 h selection span. With 12 h of normal tail after it, `SECONDS_TOTAL` = 180000 (50 h).
