# Model selection and false-positive stabilization

Date: 2026-07-22. All candidates used real Tetragon windows. Candidate models
were isolated from the active systemd service until validation completed.

| Candidate | Change | Observed result | Decision |
|---|---|---|---|
| Legacy V1 | Teacher-forced decoder, unconstrained StandardScaler, z-score at mean | Runtime normal scores could saturate at 1.0 | Reject |
| V2 | Remove decoder identity shortcut; chronological holdout | First clean Nginx window scored 0.9785 | Reject |
| V3 | Add 1% frequency variance floor | Nginx stabilized, but clean Redis reached 0.9861 | Reject |
| V4 | Robust p99/MAD reconstruction tail | 12-window live normal control had zero alerts; Redis max 0.8285 | Superseded |
| V5 (31 windows) | Map empirical normal tail to score 0.20 | Redis stabilized; one legitimate Postgres load window still scored 1.0 | More data required |
| V6 ablation | Calibrated 0.8 LSTM + 0.2 Isolation Forest mixture | Synthetic attack margins fell to 0.826–0.844 because IF cannot split dimensions constant in baseline | Reject |
| V5 temporal multiphase | Merge 31 + 41 windows across 1x/2x/high load | Holdout consisted mostly of unseen high-load Postgres; median score 0.945 | Correctly reject; split was not phase-balanced |
| V5 phase-stratified | Deterministic 20% holdout from every load phase | Offline max: Postgres 0.098, Nginx 0.153, Redis 0.461; no threshold exceedance | Stable predecessor |
| V7 transition/drift baseline | Expanded 210-feature vocabulary and workload-conditioned gates over 125 windows/workload | A strict live matrix found one legitimate Postgres raw score crossing at 0.833, although the behavior gate prevented an alert | Reject under zero-crossing gate |
| V7 four-regime current baseline | 100/100/95 qualifying windows from independently captured 1x, `wrk -c50`, high-mixed and recovery phases | Holdout maxima: Postgres 0.153, Nginx 0.203, Redis 0.228; zero score/gate crossings and zero actionable pairs | Selected and promoted |

The final normal-control run used an independent live stream after training.
Every one of the four regimes supplied 10 gated windows per workload; the
aggregate report also retained transition windows, for 44 per workload (132
total). It recorded zero detections, zero score-only crossings, zero
workload-conditioned gate crossings and zero actionable consecutive pairs.
Aggregate score maxima were 0.2664 (Postgres), 0.6435 (Nginx) and 0.2246
(Redis). Median inference time was 19.284, 21.532 and 20.783 ms; p99 ingest lag
remained below 1.76 seconds.

The deterministic final retrain produced byte-identical weights and bundles to
the earlier candidate trained from the same immutable phase data. The final
kernel-to-model matrix is reported in `REGRESSION_RESULTS.md`; promotion
requires both the normal and attack reports to bind the exact same nine-file
model release and seven runtime source hashes.

## Why V6/MoE was not selected

Isolation Forest trees trained on normal data never split syscall dimensions
that remain exactly zero. An attack introducing those syscalls is obvious to
the autoencoder but can appear normal to IF. Averaging the experts therefore
reduced recall margin. With no labeled corpus large enough to learn a reliable
gate, selecting the calibrated LSTM and retaining IF only as an ablation is the
defensible result. Conditional normalization, workload embeddings and flows
remain research candidates; they are not described as production models until
evaluated on the same immutable baseline and kernel regression protocol. The
current data size does not support a defensible learned MoE gate or a general
claim for unseen workload types.

## Reproducibility controls

- deterministic per-workload seeds derived from SHA-256;
- preprocessing fitted on train only;
- phase-stratified, manifest-recorded row indexes;
- dataset and vocabulary SHA-256 checksums in every training report;
- immutable candidate directories and atomic production promotion;
- validated normal calibration installed only with its exact model release;
- independent normal-control and real in-container syscall tests;
- release-wide SHA-256 binding across training, normal, attack and promotion;
- invalid evaluation telemetry is retained but excluded only by rerunning a
  clean, process-isolated experiment—not by deleting individual outliers.
