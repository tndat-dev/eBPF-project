# Published ML / DL host-intrusion-detection results on LID-DS 2021 and LID-DS 2019, per scenario

Research date: 2026-11-01. This file builds on `research_notes/Cải thiện Pulse trên LID DS/published_results.md` (2026-10-29) and adds sources found since: TextRank full text, LIGHT-HIDS, the Porto 2024 thesis, the McMaster 2026 thesis abstract, the IEEE Access 2025 abstract, and the full EISA 2021 Tables 5–8 re-extracted from the PDF.

How each result was read:
- **[FT]**: full text read in this session (PDF text extracted with `pdftotext`, or arXiv HTML).
- **[FT-prev]**: full text read in the 2026-10-29 session and recorded in the earlier notes file; not reopened today.
- **[ABS]**: abstract only, read through the OpenAlex API (`api.openalex.org/works/doi:<doi>`) or the publisher page.

Abbreviations:
- DR: detection rate (share of attack recordings detected).
- FA: false alarms.
- CFA: consecutive false alarms (a run of consecutive anomalous calls counts as one alarm).
- TI: thread information (thread-aware n-grams).
- OHE: one-hot encoding.
- W2 / W5: word2vec embedding of size 2 / 5.
- n: n-gram length.
- l: streaming-window length, in system calls.

Scenario codes on LID-DS 2019, as used in EISA 2021:
- BF = Bruteforce_CWE-307
- 2012 = CVE-2012-2122
- 2014 = CVE-2014-0160 (Heartbleed)
- 2017 = CVE-2017-7529
- 2018 = CVE-2018-3760
- 2019 = CVE-2019-5418
- EPS = EPS_CWE-434
- PHP = PHP_CWE-434
- SQL = SQL injection (CWE-89)
- ZIP = ZipSlip

Juice-Shop exists only in LID-DS 2021.

## Q1. Which ML/DL algorithms from the LID-DS library have published numbers, with which features, per scenario?

### Takeaway
Only one paper publishes per-scenario numbers for the LID-DS library's learned models under the library protocol: EISA 2021 (Grimmer, Kaelble, Rahm). It covers **LID-DS 2019 only** (10 scenarios) and evaluates SVM, MLP, CNN, AE, SCG, STIDE and BOSC, using n-grams in OHE or word2vec encoding, with or without TI. No published LID-DS 2021 numbers exist for the library's MLP, LSTM, Transformer, SOM, Torus-SOM, AE, CNN, SCG, OC-SVM, k-center, nearest-neighbour or AABB engines. Among learned models on 2019, the best low-alarm one is the MLP with TI (mean DR 0.789, mean FA 4.2). No learned model gets near 0.99 mean DR; only the non-learned STIDE and BOSC with TI reach about 0.986.

### Cited Findings
**EISA 2021: "Improving Host-based Intrusion Detection Using Thread Information" [FT]** — [EISA 2021 PDF](https://dbs.uni-leipzig.de/files/research/publications/2021-11/pdf/EISA2021_Improving%20Host-based%20Intrusion%20Detection%20Using%20Thread%20Information.pdf)

Protocol:
- Data: LID-DS 2019. Per scenario, the first 200 normal recordings are training, the next 50 are validation, and the rest are test.
- Threshold: "we use the maximum anomaly score from the corresponding validation part of the normal behavior as the threshold".
- A true positive needs at least one score above threshold after t′attack = tattack − 2 s. FA counts alarms before t′attack, with consecutive alarms counted once (CFA style). DR = TP/A.
- More than 30,000 configurations were grid-searched, and the best ones were reported, so these are test-selected optima.

Table 5, best average configuration per algorithm over 10 scenarios (2019):

| Algorithm | Configuration | Encoding | TI | n | l | Mean DR | Mean FA |
|---|---|---|---|---|---|---|---|
| BOSC | 1 | – | – | 11 | 10000 | 0.885 | 17.4 |
| BOSC | 2 | – | + | 11 | 10000 | 0.949 | 519.5 |
| BOSC | 3 | – | + | 7 | 1000 | 0.986 | 110.4 |
| STIDE | 1 | – | – | 3 | 10000 | 0.879 | 12.5 |
| STIDE | 2 | – | + | 3 | 10000 | 0.981 | 118.6 |
| STIDE | 3 | – | + | 5 | 1000 | 0.986 | 61.5 |
| SCG | 1 | – | – | 9 | 10000 | 0.711 | 43.9 |
| SCG | 2 | – | + | 9 | 10000 | 0.686 | 166.4 |
| SCG | 3 | – | + | 5 | 10 | 0.895 | 29.1 |
| SVM (one-class) | 1 | OHE | – | 5 | 100 | 0.562 | 13.3 |
| SVM | 2 | OHE | + | 5 | 100 | 0.292 | 13.3 |
| SVM | 3 | OHE | + | 9 | 100 | 0.595 | 42.7 |
| MLP | 1 | OHE | – | 11 | 100 | 0.614 | 18.1 |
| MLP | 2 | OHE | + | 11 | 100 | 0.605 | 34.7 |
| MLP | 3 | OHE | + | 7 | 1 | 0.789 | 4.2 |
| CNN | 1 | OHE | – | 7 | 100 | 0.686 | 35.4 |
| CNN | 2 | OHE | + | 7 | 100 | 0.694 | 28.2 |
| CNN | 3 | OHE | + | 22 | 10 | 0.702 | 20.0 |
| AE | 1 | W5 | – | 5 | 1 | 0.629 | 16.4 |
| AE | 2 | W5 | + | 5 | 1 | 0.622 | 2.3 |
| AE | 3 | W5 | + | 7 | 1 | 0.622 | 2.2 |

The authors' summary: "The overall best detection rates are achieved for the BOSC and the STIDE approaches (98,6%) and the lowest number of false alarms for AE and MLP", and "the SVM approach is not among the top-performing approaches".

Table 7, per scenario (2019). Each cell is DR / FA. "With TI" is configuration 3; "no TI" is the same configuration with the thread flag off.

| Scenario | SCG no TI | SCG with TI | MLP no TI | MLP with TI | AE no TI | AE with TI |
|---|---|---|---|---|---|---|
| BF | 0.04 / 2 | 0.94 / 1 | 0.00 / 0 | 0.94 / 1 | 0.00 / 1 | 0.00 / 0 |
| 2012 | 0.01 / 25 | 0.10 / 67 | 0.01 / 16 | 0.98 / 10 | 0.03 / 19 | 0.00 / 0 |
| 2014 Heartbleed | 0.01 / 33 | 0.95 / 25 | 0.00 / 0 | **0.01** / 7 | 0.00 / 0 | **0.00** / 0 |
| 2017 (CVE-2017-7529) | 0.97 / 17 | 0.97 / 9 | 0.97 / 11 | 0.97 / 14 | 0.97 / 8 | 0.97 / 8 |
| 2018 | 0.00 / 4 | 0.99 / 35 | 0.00 / 0 | 0.99 / 2 | 0.99 / 79 | 0.99 / 11 |
| 2019 (CVE-2019-5418) | 0.00 / 9 | 1.00 / 11 | 1.00 / 36 | 1.00 / 0 | 1.00 / 0 | 1.00 / 3 |
| EPS | 0.27 / 5 | 1.00 / 40 | 0.00 / 0 | 1.00 / 0 | 1.00 / 0 | 1.00 / 0 |
| PHP | 0.02 / 0 | 1.00 / 19 | 1.00 / 31 | 1.00 / 6 | 1.00 / 169 | 1.00 / 0 |
| SQL | 0.09 / 113 | 1.00 / 84 | 1.00 / 31 | 1.00 / 2 | 1.00 / 25 | 1.00 / 0 |
| ZIP ZipSlip | 0.03 / 12 | 1.00 / 0 | 0.00 / 0 | **0.00** / 0 | 0.27 / 0 | **0.27** / 0 |
| Mean | 0.14 / 22.0 | 0.90 / 29.1 | 0.40 / 12.5 | 0.79 / 4.2 | 0.63 / 30.1 | 0.62 / 2.2 |

Table 6, non-learned reference (2019). Each cell is DR / FA.

| Scenario | BOSC no TI (conf. 1) | BOSC with TI (conf. 2) | STIDE no TI | STIDE with TI (conf. 3) |
|---|---|---|---|---|
| BF | 0.94 / 32 | 0.94 / 29 | 0.94 / 66 | 0.94 / 24 |
| 2012 | 0.95 / 11 | 0.99 / 201 | 0.03 / 4 | 0.99 / 26 |
| 2014 | 0.00 / 1 | 0.59 / 210 | 0.00 / 3 | 0.95 / 44 |
| 2017 | 0.97 / 9 | 0.99 / 5 | 0.97 / 9 | 0.99 / 5 |
| 2018 | 0.99 / 19 | 0.99 / 5 | 0.99 / 25 | 0.99 / 12 |
| 2019 | 1.00 / 4 | 0.99 / 22 | 1.00 / 8 | 1.00 / 18 |
| EPS | 1.00 / 20 | 1.00 / 604 | 1.00 / 4 | 1.00 / 12 |
| PHP | 1.00 / 2 | 1.00 / 119 | 0.95 / 1 | 1.00 / 93 |
| SQL | 1.00 / 40 | 1.00 / 3183 | 0.15 / 18 | 1.00 / 380 |
| ZIP | 1.00 / 36 | 1.00 / 817 | 0.34 / 1 | 1.00 / 1 |
| Mean | 0.89 / 17.4 | 0.95 / 519.5 | 0.64 / 13.9 | 0.99 / 61.5 |

Table 8, best configuration per scenario over all algorithms (2019; each scenario tuned separately on test):

| Scenario | Without TI | With TI |
|---|---|---|
| BF | CNN OHE n = 9, l = 100: 0.95 / 97 | MLP OHE n = 5, l = 1: 0.94 / 0 |
| 2012 | AE OHE n = 5, l = 100: 0.97 / 33 | STIDE n = 5, l = 1000: 0.99 / 26 |
| 2014 | MLP OHE n = 22, l = 10000: **0.06 / 22** | STIDE n = 9, l = 10: 0.95 / 18 |
| 2017 | CNN OHE n = 5, l = 100: 0.99 / 13 | CNN OHE n = 9, l = 100: 0.99 / 4 |
| 2018 | CNN OHE n = 7, l = 100: 1.00 / 5 | MLP OHE n = 7, l = 100: 1.00 / 28 |
| 2019, EPS, PHP, SQL | AE W2 n = 3, l = 1: 1.00 / 0 | AE W2 n = 3 or 7, l = 1: 1.00 / 0 |
| ZIP | STIDE n = 5, l = 10000: 1.00 / 4 | BOSC n = 3, l = 10: 1.00 / 0 (SCG too) |

- The paper also says: "Overall the best results are mostly achieved by the AE, CNN, MLP and STIDE algorithms". With TI there are "0 false alarms for 6 of the ten scenarios". "DR is especially increased for scenario 2014 (from 0.06 to 0.95)" — [EISA 2021 PDF](https://dbs.uni-leipzig.de/files/research/publications/2021-11/pdf/EISA2021_Improving%20Host-based%20Intrusion%20Detection%20Using%20Thread%20Information.pdf)
- Table 9, at FA budgets (2019, with TI): FA < 10 and FA < 5 → MLP n = 7, l = 1: DR 0.788, FA 4.2; FA < 2.5 → AE n = 7, l = 1: DR 0.622, FA 2.2. Without TI, the MLP reaches DR 0.526–0.528 at FA 2.3–3.1 — [EISA 2021 PDF](https://dbs.uni-leipzig.de/files/research/publications/2021-11/pdf/EISA2021_Improving%20Host-based%20Intrusion%20Detection%20Using%20Thread%20Information.pdf) [FT-prev]

**Library engines without published LID-DS 2021 numbers**
- The repo ships decision engines for AE, AE-TF, CNN, LSTM, MLP, OCSVM, SCG, SOM, STIDE and Torus-SOM, plus `ids_*_main.py` scripts. No result tables are published in the repo or wiki — [LID-DS algorithms/](https://github.com/LID-DS/LID-DS/tree/master/algorithms) [FT-prev]
- The only per-scenario library output on 2021 is the wiki example, and it uses STIDE, not ML: CVE-2017-7529, DR 1.0 (119 of 119), CFA normal 5, f1_cfa 0.9794 — [wiki ids_example](https://github.com/LID-DS/LID-DS/wiki/ids_example) [FT-prev]
- **Transformer:** the master's thesis repo "Transformer-based Anomaly Detection on Streams of System Calls" (GitHub `tinsaye/LID-DS-TF`) uses stacked decoders as a language model over n-grams. Its instructions download **LID-DS 2019** (CVE-2017-7529), and it publishes no results and no thesis PDF — [tinsaye/LID-DS-TF](https://github.com/tinsaye/LID-DS-TF) [FT]
- **LSTM via the library:**
  - Who and what: a Porto master's thesis (H. P. Léo, 2024) used the LID-DS library with word2vec embeddings, n-grams and an LSTM decision engine, trained on **LID-DS 2019** pooled over all scenarios. It chose 2019 because "the 2021 version is six times bigger".
  - Results: "Truly Random" training split: DR 81.303%, precision 85.290%, FAR 14.022%. "Evenly Distributed" split: DR 72%, precision 98.630%, FAR 1%.
  - Missing: no per-scenario breakdown, and FAR is not defined per recording.
  — [Léo 2024, Univ. Porto thesis PDF](https://repositorio-aberto.up.pt/bitstream/10216/164023/2/699826.pdf) [FT]

### Inferences
- On 2019, learned next-call or reconstruction models (MLP, AE, CNN) win on FA when TI is on. They fail outright on Heartbleed (MLP 0.01, AE 0.00) and ZipSlip (MLP 0.00, AE 0.27). Only the graph or count models (SCG, STIDE, BOSC) with TI solve those two. So the "few false alarms" learned designs are exactly the ones that miss the two scenarios Pulse also misses.
- Per-scenario best results (Table 8) are tuned separately for each scenario on test data. No single learned configuration reaches them.

### Gaps
- No LID-DS 2021 numbers were found, published or in the repo, for MLP, LSTM, Transformer, SOM, Torus-SOM, OC-SVM, k-center, nearest-neighbour or AABB, nor for AE or CNN.
- No Leipzig thesis with LID-DS 2021 ML results was found. ScaDS.AI lists a 2019 bachelor's thesis and an in-progress master's thesis tagged LID-DS, without results — [scads.ai thesis listing](https://scads.ai/?p=2475), [scads.ai](https://scads.ai/?p=2663).

## Q2. Leipzig group papers 2021–2026: what DR and false alarms per scenario?

### Takeaway
The group published EISA 2021 (2019 data, Q1) and the LID-DS 2021 Dataset Report together with its CRITIS 2022 extended abstract. The 2021 report evaluates only STIDE, gives only the 15-scenario average (DR 0.59, F-score 0.57, average FA 24.47), and has no per-scenario table. No Leipzig transformer, out-of-distribution, ensemble, mixture-of-experts or new system-call-graph paper on LID-DS 2021 was found up to 2026-11-01.

### Cited Findings
- **LID-DS 2021:** STIDE, n = 7, window 100, maximum-validation threshold; F-score 0.57, DR 0.59, average false alarms 24.47. For comparison, LID-DS 2019 under the same set-up: 0.63 / 0.65 / 19.80. The 2021 dataset has about 8.5 times more system calls — [CRITIS 2022 extended abstract](https://dbs.uni-leipzig.de/files/research/publications/2023-07/pdf/CRITIS_2022_Extended_Abstract_LID-DS-2021.pdf) [FT-prev]
- The Dataset Report (LNCS 13723, 2023) uses the same STIDE baseline and evaluates no other algorithm — [Dataset Report PDF](https://dbs.uni-leipzig.de/file/978-3-031-35190-7_6.pdf), [DOI](https://doi.org/10.1007/978-3-031-35190-7_6) [FT-prev]
- Citations of the Dataset Report on OpenAlex, queried 2026-11-01: 4 works. They are TextRank (Electronics 2026), CSCWD 2026 multi-scale fusion, the CHASE dataset preprint (Research Square 2026), and an IJCNN 2026 log-failure paper. None is from Leipzig — [OpenAlex cites:W4379620736](https://api.openalex.org/works?filter=cites:W4379620736)
- The 2018 "Intrusion Detection on System Call Graphs" paper is evaluated on ADFA-LD, not LID-DS — [Leipzig DBS publications](https://dbs.uni-leipzig.de/research/publications) [FT-prev]

### Inferences
- The only "official" learned-model numbers from the dataset authors are on 2019. Any LID-DS 2021 per-scenario ML table would be a new contribution.

### Gaps
- No per-scenario STIDE breakdown on 2021 is published behind the 0.59 average.
- Whether DBLP or Google Scholar lists any 2025–2026 Grimmer or Kaelble paper could not be checked. Semantic Scholar and DBLP rate-limited us in the earlier session, and web searches returned nothing.

## Q3. Other 2022–2026 papers on LID-DS: scenarios kept, scenarios dropped, results

### Takeaway
Every 2021 result outside Leipzig uses a scenario subset and a non-library unit (window, chunk, sample or file). Most are supervised or calibrated on test data. The one full-text DL result that looks strong, TextRank 2026 with F1 0.90–0.94, is close to what an "everything is an attack" predictor scores (worked out below). The five scenarios Pulse misses are either dropped (Heartbleed, ZipSlip, CVE-2019-5418 and Juice-Shop in TextRank) or reported weak (Juice-Shop window-level F1 0.13 in Kozachok).

### Cited Findings
Master table of LID-DS results from learned models (2019 entries are marked):

| Paper (year) | LID-DS version and scenarios | Model and input | Unit / metric / threshold | Headline numbers | Read |
|---|---|---|---|---|---|
| EISA 2021 | 2019, 10 scenarios | SVM, MLP, CNN, AE, SCG on n-grams (OHE / W2V), with or without TI | Recording-level DR, CFA count; maximum validation score; test-selected config | MLP+TI 0.789 / 4.2; AE+TI 0.622 / 2.2; CNN+TI 0.702 / 20.0 (full tables in Q1) | [FT] [PDF](https://dbs.uni-leipzig.de/files/research/publications/2021-11/pdf/EISA2021_Improving%20Host-based%20Intrusion%20Detection%20Using%20Thread%20Information.pdf) |
| CHIDS, CCSW 2022 | 2019, 9 scenarios (Heartbleed missing; listed as a failure) + CB-DS | Autoencoder on scap graph features: USI / UAI / FI | Trace-level P / R / F1; threshold 1.4 × max training error; 4-fold CV | Recall 0.79–0.9998; ZipSlip 0.9987, CVE-2019-5418 0.9989, CVE-2017-7529 0.9885 | [FT-prev] [PDF](https://conand.me/publications/elkhairi-ccsw-2022.pdf) |
| CDL, re-implemented in CHIDS 2022 | 2019, 9 scenarios | Frequency-vector autoencoder, 100 ms | Trace-level; 99.99th percentile threshold | Recall: CVE-2017-7529 0.0057, CVE-2019-5418 0.0102, ZipSlip 0.1224, EPS 0.4848 | [FT-prev] [PDF](https://conand.me/publications/elkhairi-ccsw-2022.pdf) |
| Cross-domain HIDS, Electronics 2022 | version not stated (probably 2019) | Supervised transfer learning | F2 | In-domain F2: CVE-2014-0160 13% → 85% cross-domain; CWE-307 80% → 87% | [ABS] [DOI](https://doi.org/10.3390/electronics11213631) |
| Léo thesis 2024 | 2019, all scenarios pooled | LSTM on word2vec n-grams (LID-DS library) | DR / precision / FAR, pooled | DR 72%, FAR 1% (or DR 81.3%, FAR 14.0%) | [FT] [PDF](https://repositorio-aberto.up.pt/bitstream/10216/164023/2/699826.pdf) |
| Guo, DSAI 2024 | "LID-DS across 13 scenarios", about 14,950 samples (version not stated; Kozachok calls it LID-DS 2021) | Autoencoder over a directed graph of syscalls, process names, TIDs, return values, parameters | Sample-level accuracy and F1 | Accuracy 96.8%, F1 97.7%; FA "significantly reduced" (no number) | [ABS] [DOI](https://doi.org/10.1145/3677892.3677893) |
| Ab-HIDS, CPE 2024 | version not stated | n-gram frequency + voting / XGBoost + SMOTE (supervised) | Accuracy, FPR | "+4% / +6%" accuracy, FPR −0.9 / −0.8 points vs prior work | [ABS] [DOI](https://doi.org/10.1002/cpe.8249) |
| Kim et al., IEEE Access 2025 | ADFA-LD and **LID-DS 2021** (scenarios not in abstract) | TextRank keywords + Seq2Seq + Actor-Critic RL that generates rules | Accuracy | "high accuracy rate of 96.5% average when faced with different attacks" | [ABS] [DOI](https://doi.org/10.1109/access.2025.3532353) |
| LIGHT-HIDS, arXiv 2509.13464 (2025) | LID-DS, Bruteforce and SQL injection only (cites the 2021 report; version not stated) | CNN feature extractor + Deep SVDD + Isolation Forest; baselines LSTM, WaveNet, CNN-RNN (next-call), COUTA, TimesNet, Deep SVDD, IF, OCSVM | P / R / F1, unit not stated; threshold = validation mean + 2σ | BF: LIGHT-HIDS F1 0.973, LSTM 0.958, OCSVM 0.955, CNN-RNN 0.942. SQLi: LIGHT-HIDS 0.766, CNN-RNN 0.735, OCSVM 0.732, WaveNet 0.726 | [FT] [arXiv](https://arxiv.org/html/2509.13464v1) |
| TextRank + DL, Electronics 15(9):1856 (2026) | **2021**, 3 of 15: Bruteforce_CWE-307, CVE-2012-2122, CVE-2017-7529 | Supervised RF (TF-IDF), LSTM, CNN+LSTM, BiLSTM, CNN+BiGRU on 50-call chunks + 5 TextRank keywords | Chunk-level; labels from the recording's exploit flag; 70/15/15 file-level split; attack:benign 1:3 undersampling; threshold maximises validation F1 with FPR ≤ 0.10 | F1: DL 0.9018–0.9395, RF 0.5538–0.6274; MCC ≤ 0.462; ROC-AUC 0.80–0.83 (BF, 2012), 0.67–0.73 (CVE-2017-7529) | [FT] [PDF](https://mdpi-res.com/d_attachment/electronics/electronics-15-01856/article_deploy/electronics-15-01856.pdf) |
| Kozachok, Vyugov, Magomedov, arXiv 2606.22581 (2026) | **2021**, 6: Bruteforce, CVE-2012-2122, SQLi, Juice-Shop, EPS_CWE-434, PHP_CWE-434 | Isolation Forest and SGD-OCSVM on 66 window features (unseen arguments / syscalls, negative returns, frequency, data volume, PID/TID, time-delta histograms), 1 s windows, 300 ms step | Window-level P / R / F1 / realised FPR; threshold calibrated on normal data to target α | Self-detection F1 ≤ 0.31 everywhere; Juice-Shop F1 0.1336 at FPR 0.0518; best combined CWE-307 F1 0.6976 at FPR 0.0702 | [FT-prev] [arXiv](https://arxiv.org/abs/2606.22581) |
| Inter-PSSG, Bezopasnost IT 2026 (same group) | **2021**, CWE-307 / 434 / 89 / 22 classes | Inter-process semantic graph, 18 features | Window-level F1 / FPR | Transfer within the same class: F1 0.882 at FPR 0.048 | [ABS] [DOI](https://doi.org/10.26583/bit.2026.5.15) |
| ICOECA 2026 (K8s eBPF + ML) | "LID-DS system call traces" (version not stated) + CICIDS2018 + K8s audit logs | ML, details not in abstract | Not broken down per dataset | "detection rates of 94–95%, less than 2% false positive rate" | [ABS] [DOI](https://doi.org/10.1109/icoeca68095.2026.11485567) |
| Gurbuz, McMaster thesis 2026 | **2021, all 15 scenarios** | STIDE (not ML) + learned strict-partial-order explanation layer | Explanation coverage | Explanation fires in 6 of 15 scenarios; 99.71% of reversed observations fall inside the attack window; DR / FA not in abstract | [ABS] [DOI](https://doi.org/10.71548/25675) |
| CSCWD 2026 multi-scale feature fusion | cites the 2021 report | Unknown | Unknown | Unknown (no abstract, paywalled) | none — [DOI](https://doi.org/10.1109/cscwd68734.2026.11581451) |

Detail for the TextRank paper (Electronics 2026) [FT] — [PDF](https://mdpi-res.com/d_attachment/electronics/electronics-15-01856/article_deploy/electronics-15-01856.pdf)

Authors: H. You, C. Park, D. Shin and D. Shin (Sejong University).

Scenario exclusions (Table 3):
- "six multi-stage attacks were excluded": Juice Shop, EPS_CWE-434, ZipSlip, CVE-2017-12635_6, CVE-2020-13942 and CVE-2020-23839.
- CVE-2014-0160 was excluded as "Heavily dependent on network-packet behavior".
- CWE-89 was excluded because it overlaps the database category.
- PHP_CWE-434, CVE-2018-3760, CVE-2019-5418 and CVE-2020-9484 were excluded because they overlap the web-server category.
- Their multi-stage list labels EPS and ZipSlip as multi-stage. The LID-DS wiki marks only four scenarios as multi (CVE-2017-12635_6, CVE-2020-23839, Juice-Shop, CVE-2020-13942) — [wiki Scenarios](https://github.com/LID-DS/LID-DS/wiki/Scenarios)

Table 6 (accuracy) and Table 7 (F1):

| Scenario | RF acc / F1 | LSTM | CNN+LSTM | BiLSTM | CNN+BiGRU |
|---|---|---|---|---|---|
| Bruteforce_CWE-307 | 0.8753 / 0.6274 | 0.8211 / 0.9018 | 0.8217 / 0.9021 | 0.8219 / 0.9022 | 0.8219 / 0.9023 |
| CVE-2012-2122 | 0.7973 / 0.5699 | 0.8320 / 0.9053 | 0.8334 / 0.9071 | 0.8322 / 0.9065 | 0.8358 / 0.9103 |
| CVE-2017-7529 | 0.7445 / 0.5538 | 0.8859 / 0.9395 | 0.8859 / 0.9395 | 0.8859 / 0.9395 | 0.8859 / 0.9395 |

- Table 9 gives MCC: DL 0.285–0.462, RF ≤ 0.295. Without TextRank keywords the DL F1 falls by 0.07–0.16 (Table 8).
- The authors' own caveat: "strong F1-scores do not imply uniformly strong discrimination". CVE-2017-7529 is only "moderately rather than strongly separable" (AUC 0.67–0.73).

Other notes:
- The Russian review "Comparative analysis of current methods for detecting anomalies in container environments based on system calls" (Vyugov, 2026) may hold a comparison table. The publisher link returned 404 — [DOI 10.21681/3034-4050-2026-2-58-69](https://doi.org/10.21681/3034-4050-2026-2-58-69)
- REPLICAWATCHER (NDSS 2024) uses its own microservice data and re-implements CHIDS and STIDE-BoSC, so it has no LID-DS numbers. A Dual-head CNN (WiPiEC 2026) uses ADFA-LD only; LID-DS is listed as future work — [NDSS 2024 PDF](https://www.ndss-symposium.org/wp-content/uploads/2024-286-paper.pdf), [WiPiEC](https://wipiec.digitalheritage.me/index.php/wipiecjournal/article/download/143/101) [FT-prev]

### Inferences
- **The TextRank DL F1s are close to what labelling every chunk as an attack would score.** For an all-positive predictor, accuracy equals the attack prevalence p and F1 = 2p/(1+p). Applying that to the reported accuracies (my computation, not in the paper):
  - CVE-2017-7529: 2·0.8859/1.8859 = 0.9395 for all four DL models, exactly the reported F1.
  - Bruteforce: 0.9018–0.9022, against reported 0.9018–0.9023.
  - CVE-2012-2122: 0.9083–0.9106, against reported 0.9053–0.9103.
  - The low MCC (≤ 0.46) and AUC (0.67–0.83) point the same way. The "0.90–0.94" headline is therefore not evidence of real discrimination.
  - The test set seems to hold about 82–89% attack-labelled chunks, despite the stated 1:3 attack:benign undersampling. Labels come from the recording's exploit flag, so pre-exploit normal activity inside attack recordings is also labelled as attack.
- Scenario dropping is systematic. Heartbleed, ZipSlip, Juice-Shop and the multi-step scenarios are the ones excluded, which matches Pulse's hard set. The papers that keep Juice-Shop (Kozachok) report it as weak.
- Accuracy claims of 95% or more (Guo 96.8%, Kim 96.5%, ICOECA 94–95%) are abstract-only. They are sample- or accuracy-based, use subsets or an unstated dataset version, and, for Guo and Ab-HIDS, at least partly supervised or with unclear calibration. They cannot be set beside recording-level DR with a normal-recording false-alarm rate.

### Gaps
- Full texts could not be opened for:
  - Guo 2024: ACM, paywalled.
  - Kim et al. 2025: IEEE Access is open access, but IEEE Xplore returned empty pages to the fetcher.
  - Ab-HIDS 2024: Wiley.
  - ICOECA 2026 and CSCWD 2026: IEEE.
  - Gurbuz 2026: the McMaster repository's bot check blocked the fetcher.
  - Vyugov 2026: 404.
  - For all of these, per-scenario numbers, thresholds and the LID-DS version are unverified.
- The Gurbuz thesis is the only work found that runs something on all 15 LID-DS 2021 scenarios besides the dataset authors. Its per-scenario STIDE DR / FA table, if it has one, would be the closest public per-scenario baseline. A browser download or an email to library@mcmaster.ca would be needed to get it.

## Q4. Metric definitions, thresholds, and whether Heartbleed, ZipSlip, CVE-2019-5418, CVE-2017-7529 and Juice-Shop were detected

### Takeaway
Only EISA 2021 (2019) and the Leipzig STIDE baseline (2021) use the library protocol: recording-level DR, CFA counts, and a maximum-validation-score threshold. CHIDS uses a trace-level rule (a trace is malicious if any sequence is). Everyone else uses windows or chunks, with thresholds tuned to a target FPR or to validation F1.

Per scenario across sources:
- **Heartbleed** is the scenario learned models miss most consistently. The exceptions are thread-aware graph and count methods (SCG / STIDE with TI, 0.95 on 2019) and one transfer-learning abstract.
- **ZipSlip** defeats the MLP and AE but not the n-gram methods or CHIDS's argument features.
- **CVE-2019-5418 and CVE-2017-7529** are easy for sequence or argument models on 2019 (0.97–1.00) but are missed by frequency-only CDL (recall about 0.01).
- **Juice-Shop** has no published detection anywhere except a 0.13 window-level F1.

### Cited Findings
Per-scenario status for the five scenarios Pulse misses:

| Scenario | 2019 learned models (EISA, DR / FA) | 2019 CHIDS / CDL recall | 2021 results |
|---|---|---|---|
| CVE-2014-0160 Heartbleed | MLP+TI 0.01 / 7; AE+TI 0.00 / 0; SCG+TI 0.95 / 25; best without TI 0.06 / 22 (MLP); STIDE+TI 0.95 / 44 | CHIDS: not in table, "Failure to detect Heartbleed" | Excluded by TextRank ("network-packet behavior"); not in Kozachok's 6; no number anywhere |
| ZipSlip | MLP+TI 0.00 / 0; AE+TI 0.27 / 0; SCG+TI 1.00 / 0; BOSC+TI n = 3, l = 10: 1.00 / 0 | CHIDS 0.9987; CDL 0.1224 | Excluded by TextRank ("multi-stage"); no number |
| CVE-2019-5418 | MLP+TI 1.00 / 0; AE W2 1.00 / 0; SCG+TI 1.00 / 11 | CHIDS 0.9989; CDL 0.0102 | Excluded by TextRank ("overlap"); no number |
| CVE-2017-7529 | MLP / AE / SCG 0.97; CNN+TI 0.99 / 4 | CHIDS 0.9885; CDL 0.0057 | STIDE wiki DR 1.0, 5 CFA (not ML); TextRank DL F1 0.9395 but AUC 0.67–0.73 (near-trivial) |
| Juice-Shop | not in 2019 | not in 2019 | Kozachok self-detection, window-level: P 0.1809, R 0.1059, F1 0.1336 at FPR 0.0518 |

Sources for the table:
- EISA rows — [EISA 2021 PDF](https://dbs.uni-leipzig.de/files/research/publications/2021-11/pdf/EISA2021_Improving%20Host-based%20Intrusion%20Detection%20Using%20Thread%20Information.pdf) [FT]
- CHIDS / CDL rows — [CHIDS PDF](https://conand.me/publications/elkhairi-ccsw-2022.pdf) [FT-prev]
- TextRank — [Electronics 2026 PDF](https://mdpi-res.com/d_attachment/electronics/electronics-15-01856/article_deploy/electronics-15-01856.pdf) [FT]
- Kozachok — [arXiv 2606.22581](https://arxiv.org/abs/2606.22581) [FT-prev]
- STIDE wiki — [wiki ids_example](https://github.com/LID-DS/LID-DS/wiki/ids_example) [FT-prev]

Metric and threshold rules by source:
- **EISA 2021:**
  - DR = TP / A per scenario. A TP is any alarm after tattack − 2 s.
  - FA = number of alarms before t′attack, with consecutive alarms merged.
  - Threshold = maximum score on validation normal data.
  — [EISA 2021 PDF](https://dbs.uni-leipzig.de/files/research/publications/2021-11/pdf/EISA2021_Improving%20Host-based%20Intrusion%20Detection%20Using%20Thread%20Information.pdf)
- **Library code:**
  - DR counts the first alarm at or after the exploit time, with no −2 s.
  - It keeps two CFA counters, for normal recordings and for pre-exploit parts of attack recordings.
  - Threshold = `MaxScoreThreshold`.
  — [performance_measurement.py](https://github.com/LID-DS/LID-DS/blob/master/algorithms/performance_measurement.py) [FT-prev]
- **CHIDS:** threshold = 1.4 × maximum training reconstruction error, "empirically" chosen; a trace counts as malicious if one sequence is — [CHIDS PDF](https://conand.me/publications/elkhairi-ccsw-2022.pdf)
- **Kozachok 2026:** α-calibrated on normal data, but the model and scaler candidate is chosen on the labelled test frame, which the authors call "a mild form of selection bias" — [arXiv 2606.22581](https://arxiv.org/abs/2606.22581)
- **TextRank 2026:** threshold maximises validation F1 subject to FPR ≤ 0.10, on undersampled data — [PDF](https://mdpi-res.com/d_attachment/electronics/electronics-15-01856/article_deploy/electronics-15-01856.pdf)
- **LIGHT-HIDS 2025:** validation mean + 2σ; the metric unit is not stated — [arXiv 2509.13464](https://arxiv.org/html/2509.13464v1)

### Inferences
- Pulse reports the share of normal recordings falsely alarmed. EISA and the library report alarm counts. To compare with EISA, Pulse would need CFA counts per scenario test set, or the other paper's alarm counts converted to a per-recording rate, which none publishes.
- Heartbleed is caught only with thread-aware sequence context: STIDE n = 9, l = 10 with TI reaches 0.95 on 2019. That is consistent with the attack hiding inside a normal-looking per-window count profile, which would explain why Pulse's per-0.5 s count features miss it. This is an inference from the 2019 tables; it is not tested on 2021.
- ZipSlip, CVE-2019-5418 and CVE-2017-7529 are caught by argument-aware or unseen-syscall features (CHIDS UAI / USI) and by n-grams with TI, and missed by frequency vectors (CDL). This matches Pulse's count-only representation missing them.

### Gaps
- No 2021 per-scenario number exists for Heartbleed, ZipSlip, CVE-2019-5418 or (from ML) CVE-2017-7529 in any accessible source.
- Whether SQLInjectionUser-style Juice-Shop steps were detected by anyone is not reported.

## Q5. Does any learned model get near 95% detection on LID-DS 2021 with low false alarms, and with what representation?

### Takeaway
No verifiable source shows a learned model near 95% recording-level detection on all or most LID-DS 2021 scenarios with low false alarms.
- **Verified 2021 full-text results are weak:** window-level F1 ≤ 0.31 for one-class IF / OCSVM on 66 count / argument / time features; a best combined CWE-307 F1 of 0.70 at 7% FPR; and near-trivial supervised DL on three easy scenarios.
- **Claims of 95% or more** (Guo AE on a directed graph of syscalls + process names + TIDs + return values + parameters, 96.8% accuracy on 13 scenarios; Kim RL rules 96.5% accuracy; ICOECA 94–95% DR at < 2% FPR) are abstract-only and not protocol-comparable.
- **Closest verified analogue on 2019:** thread-aware n-gram models, where STIDE / BOSC reach DR 0.986 at FA 61–110 and the learned MLP+TI reaches 0.79 at FA 4.2.

### Cited Findings
- On LID-DS 2021, all 15 scenarios, the only published number is STIDE at DR 0.59 with average FA 24.47 — [CRITIS 2022 extended abstract](https://dbs.uni-leipzig.de/files/research/publications/2023-07/pdf/CRITIS_2022_Extended_Abstract_LID-DS-2021.pdf)
- Guo 2024: "average accuracy reached 96.8%, and the average F1 score increased to 97.7%" on "LID-DS across 13 scenarios". The representation is "system calls, process names, thread IDs, return values, and parameters" in a directed graph, fed to an autoencoder [ABS] — [DOI 10.1145/3677892.3677893](https://doi.org/10.1145/3677892.3677893)
- Kim et al. 2025: "high accuracy rate of 96.5% average" on ADFA-LD and LID-DS 2021, using rules generated with RL from TextRank keywords [ABS] — [DOI 10.1109/access.2025.3532353](https://doi.org/10.1109/access.2025.3532353)
- ICOECA 2026: "detection rates of 94–95%, less than 2% false positive rate", not separated by dataset [ABS] — [DOI 10.1109/icoeca68095.2026.11485567](https://doi.org/10.1109/icoeca68095.2026.11485567)
- Kozachok 2026: self-detection F1 ≤ 0.31 on all 6 scenarios; combined CWE-307 F1 0.6976 at realised FPR 0.0702 [FT-prev] — [arXiv 2606.22581](https://arxiv.org/abs/2606.22581)
- LIGHT-HIDS 2025: Bruteforce F1 0.973 and SQLi F1 0.766, two scenarios only, unit not stated [FT] — [arXiv 2509.13464](https://arxiv.org/html/2509.13464v1)
- LID-DS 2019, the best learned model in the strict protocol: MLP OHE n = 7, l = 1 with TI, mean DR 0.789 at FA 4.2. Per scenario it detects 8 of 10 at ≥ 0.94 and misses Heartbleed (0.01) and ZipSlip (0.00) [FT] — [EISA 2021 PDF](https://dbs.uni-leipzig.de/files/research/publications/2021-11/pdf/EISA2021_Improving%20Host-based%20Intrusion%20Detection%20Using%20Thread%20Information.pdf)
- LID-DS 2019, trace level: CHIDS (AE on unseen syscalls, unseen arguments and frequency) reaches recall ≥ 0.92 on 7 of 9 scenarios, precision ≥ 0.93, with Heartbleed excluded [FT-prev] — [CHIDS PDF](https://conand.me/publications/elkhairi-ccsw-2022.pdf)

### Inferences
- The input representations behind the strongest learned results share the same ingredients: thread or process context (TI, TIDs, process names), argument or return-value novelty (UAI, return values, parameters), and unseen-syscall indicators. Pure per-window syscall counts (CDL, BOSC without TI, and Kozachok's frequency group) are the representations that fail on information-disclosure and path attacks.
- Pulse at 63.9% (77.4% with tripwire) of attack recordings and about 2.7% of normal recordings falsely alarmed, across all 15 LID-DS 2021 scenarios, is at least not below any verifiable published learned-model result on 2021. The only like-for-like scale reference is STIDE at DR 0.59. A paper can say that no published learned model reports all-15-scenario LID-DS 2021 recording-level results. That statement is limited by the unread full texts listed in the Gaps, especially Guo 2024 and Gurbuz 2026.
- The low-alarm learned designs on 2019 (MLP or AE on thread-aware n-grams with l = 1) are next-call or reconstruction models. Their false-alarm advantage comes from TI. Their blind spots are Heartbleed and ZipSlip, the same as Pulse's, so adding such a model would not close those gaps. Thread-aware STIDE / SCG-style n-gram novelty or argument-novelty features would.

### Gaps
- Whether Guo 2024 reaches about 95% recording-level DR with low per-recording FA under a normal-only threshold cannot be checked without the ACM full text. Its 13-scenario list, and which 2 scenarios it dropped, are unknown.
- No LID-DS 2021 result with thread-aware n-grams under the library protocol was found.
