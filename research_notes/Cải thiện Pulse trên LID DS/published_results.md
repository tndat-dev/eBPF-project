# Published detection results on LID-DS 2021 (and LID-DS 2019 for context)

Research date: 2026-10-29. Every number below comes from a page or PDF opened during this session unless it is marked "abstract only" or "unverified". "2019" is marked wherever a result is on LID-DS 2019, not LID-DS 2021. FA = false alarms; DR = detection rate; CFA = consecutive false alarms (a run of consecutive anomalous system calls counted as one alarm); TI = thread information.

Papers and abstracts that could not be read in full: TextRank/Electronics 2026 and Cross-domain/Electronics 2022 (MDPI returned HTTP 403), Ab-HIDS/CPE 2024 (Wiley blocked), Guo/DSAI 2024 (ACM, paywalled), ICOECA 2026 and CSCWD 2026 (IEEE, paywalled), and Computers & Security 2025 (Elsevier, paywalled). For these, only the abstracts were read, through the OpenAlex API (`api.openalex.org/works/doi:<doi>`).

## Q1. Which papers report results on LID-DS 2021, with which method, input, threshold and metrics?

### Takeaway
Very few papers report LID-DS 2021 results. The only full 15-scenario number published by the dataset authors is a STIDE baseline: DR 0.59, average 24.47 false alarms, F-score 0.57. The LID-DS group's detailed multi-algorithm study (EISA 2021) and CHIDS (CCSW 2022) both use **LID-DS 2019**, not 2021. The 2021 results found in 2024–2026 come from other groups. They use their own protocols (window-level, file-level or "sample"-level) and scenario subsets, so they cannot be compared with the library protocol.

### Cited Findings

**LID-DS group (Leipzig University / ScaDS)**
- **Extended Abstract: LID-DS 2021 (CRITIS 2022).** The baseline is "a variant (as described in [1]) of the STIDE algorithm" with n = 7 and window w = 100. The paper reports "average results … over all scenarios". On **LID-DS 2021**: F-score 0.57, detection rate 0.59, avg. false alarms 24.47. On **LID-DS 2019**: F-score 0.63, DR 0.65, avg. false alarms 19.80. Its conclusion is that "the 2021 version is more difficult to solve with the base algorithm than the 2019 version" (Fig. 2) — [CRITIS 2022 extended abstract](https://dbs.uni-leipzig.de/files/research/publications/2023-07/pdf/CRITIS_2022_Extended_Abstract_LID-DS-2021.pdf)
- The same Fig. 2 gives system call counts per scenario for 2021, in millions: CVE-2012-2122 20.7; CVE-2014-0160 1.9; CVE-2017-7529 1.3; CVE-2017-12635_6 1311.7; CVE-2018-3760 115.1; CVE-2019-5418 400.9; CVE-2020-9484 223.6; CVE-2020-13942 849.1; CVE-2020-23839 33.9; Bruteforce 9.5; EPS_CWE-434 296.3; Juice-Shop 484.9; PHP_CWE-434 97.5; SQL_Injection 96.2; ZipSlip 111.1. The 2021 version "contains about 8.5 times as many system calls as the old one" — [CRITIS 2022 extended abstract](https://dbs.uni-leipzig.de/files/research/publications/2023-07/pdf/CRITIS_2022_Extended_Abstract_LID-DS-2021.pdf)
- **Dataset Report: LID-DS 2021** (CRITIS 2022, LNCS 13723, pp. 63–73, 2023) runs the same STIDE baseline (Listing 1.1: `Ngram(..., ngram_length=7)`, StreamSum window 100). It phrases the result as "the 2021 version is slightly more difficult to solve with the base algorithm than the 2019 version". It states that "the method used in the paper by Grimmer et al. [6] for system call accurate evaluation is applied here". No other algorithm is evaluated in it — [Dataset Report PDF](https://dbs.uni-leipzig.de/file/978-3-031-35190-7_6.pdf) / [DOI](https://doi.org/10.1007/978-3-031-35190-7_6)
- The Dataset Report criticises earlier work. Some papers "did not stick to the partition of training, validation and test data", used "different definitions of detection and false alarm rates", or (Wunderlich et al.) evaluated "entire records … although both normal and abnormal ranges can exist within a record" — [Dataset Report PDF](https://dbs.uni-leipzig.de/file/978-3-031-35190-7_6.pdf)
- Changes from 2019 to 2021 listed in the Dataset Report:
  - Attack time was re-derived by matching attacker pcap packets to victim system calls.
  - Data buffers are stored in base64.
  - User timing is sampled from real web-server logs.
  - Resource statistics are recorded once per second.
  - pcap is included, and each actor has its own container IP.
  - Multi-step scenarios were added, with every step labelled. Example: CVE-2017-12635_6 runs an Nmap scan, then an optional hydra brute force, then privilege escalation (CVE-2017-12635), then RCE (CVE-2017-12636).
  - Source code of all 15 scenarios is released.
  — [Dataset Report PDF](https://dbs.uni-leipzig.de/file/978-3-031-35190-7_6.pdf)
- **"Improving Host-based Intrusion Detection Using Thread Information"** (Grimmer, Kaelble, Rahm; EISA 2021, Springer CCIS 1403) — **LID-DS 2019, 10 scenarios**. It evaluates 7 algorithms: BOSC, STIDE, SCG (n-gram probability graph), one-class SVM, MLP and CNN (next-syscall prediction), and an autoencoder (AE). Inputs are n-grams of syscall IDs (OHE or word2vec W2/W5 encodings), with or without thread-aware n-grams, and a streaming window l. The authors trained and evaluated "more than 30,000 different configurations" by grid search — [EISA 2021 PDF](https://dbs.uni-leipzig.de/files/research/publications/2021-11/pdf/EISA2021_Improving%20Host-based%20Intrusion%20Detection%20Using%20Thread%20Information.pdf)
- **"Intrusion Detection on System Call Graphs"** (Grimmer et al., DFN "Sicherheit in vernetzten Systemen" 2018) was evaluated on ADFA-LD, not on LID-DS. A search summary says it was "comparable" to STIDE; that page was not opened, so this is unverified — [publication listing](https://dbs.uni-leipzig.de/node/10773)
- The Leipzig DBS publication list, filtered by the tags "lid-ds", "hids", "host based intrusion detection", "system calls" and "intrusion detection", shows only five HIDS papers: SCG 2018, the BSI 2019 dataset paper, FedCSIS 2019, EISA 2021 and the two CRITIS 2022 items. No Leipzig transformer, LSTM or "ensemble" paper on LID-DS 2021 is listed — [dbs.uni-leipzig.de publications (tag filter)](https://dbs.uni-leipzig.de/research/publications)
- The LID-DS repository does contain decision engines for AE, AE-TF, CNN, LSTM, MLP, OCSVM, SCG, SOM, STIDE and Torus-SOM, plus `ids_lstm_main.py`, `ids_mlp_main.py`, `ids_som_main.py` and similar scripts. No result tables for them are published in the repo or the wiki — [LID-DS repo, algorithms/](https://github.com/LID-DS/LID-DS/tree/master/algorithms)

**Other groups, LID-DS 2021**
- **"From CVE to CWE: Syscall-Based HIDS Generalisation"** (Kozachok, Vyugov, Magomedov; arXiv 2606.22581, June 2026) — **LID-DS 2021**, six scenarios: Bruteforce_CWE-307, CVE-2012-2122, CWE-89-SQL-injection, Juice-Shop, EPS_CWE-434 and PHP_CWE-434. — [arXiv 2606.22581](https://arxiv.org/abs/2606.22581)
  - Input: a 66-dimensional per-window vector over 1 s windows with a 300 ms step. The six feature groups are: unseen-argument/unseen-syscall influence (UAI/USI), counts of negative return values, per-window syscall frequency (FI), maximum data volume of resource syscalls, PID/TID statistics, and time-delta histograms.
  - Models: Isolation Forest and SGD one-class SVM.
  - Threshold: calibrated on normal-only validation data to a target FPR α.
  - Metrics: window-level precision, recall, F1 and realised FPR.
  - Self-detection is weak: F1 ≤ 0.31 for all six scenarios even at α = 0.05.
  - The authors admit "a mild form of selection bias", because the model/scaler candidate is picked on the labelled test frame.
- Reliability flag for this paper: its dataset citation [8] reads "Grimmer, M., Kaelble, T., Rucks, F., Pirl, J.: LID-DS 2021 – … Mendeley Data, v3 (2021)". That does not match the canonical authors or venue (the CRITIS 2022 Dataset Report) — [arXiv 2606.22581](https://arxiv.org/abs/2606.22581) vs [Dataset Report](https://doi.org/10.1007/978-3-031-35190-7_6)
- **Inter-PSSG** (same Kozachok group; Bezopasnost Informacionnyh Tehnology 2026, Russian; abstract only).
  - Method: an inter-process semantic graph of system calls, 1 s window with 0.3 s step, an ablation-selected core of 18 features (U1+U5).
  - Data: **LID-DS 2021**, classes CWE-307, CWE-434, CWE-89 and CWE-22.
  - Result: "When the model is transferred between vulnerabilities of the same class, the F1-score reaches 0.882 at a false-positive rate of 0.048".
  — [DOI 10.26583/bit.2026.5.15](https://doi.org/10.26583/bit.2026.5.15)
- **Guo, "Intrusion Detection Based on Complete System Call Information"** (DSAI 2024, ACM; abstract only, paywalled).
  - Method: an autoencoder over directed-graph contextual features built from syscalls, process names, thread IDs, return values and parameters.
  - Data: "LID-DS across 13 scenarios, comprising approximately 14,950 samples".
  - Result: "average accuracy reached 96.8%, and the average F1 score increased to 97.7%"; the false alarm rate is "significantly reduced", with no number in the abstract.
  — [DOI 10.1145/3677892.3677893](https://doi.org/10.1145/3677892.3677893)
  - Kozachok et al. call Guo's pipeline "the reference HIDS pipeline [that] uses on LID-DS-2021", with 1 s windows and a 300 ms step — [arXiv 2606.22581](https://arxiv.org/abs/2606.22581)
- **TextRank + deep learning** (Electronics 15(9):1856, 2026; abstract only, MDPI returned 403). **LID-DS 2021**.
  - "Of the 15 scenarios in the dataset, six multi-stage attacks were excluded, and three representative scenarios were selected".
  - Splits are same-scenario and file-level.
  - Models: RF, LSTM, CNN+LSTM, BiLSTM and CNN+BiGRU.
  - Results: deep learning pipelines F1 0.90–0.94, RF 0.55–0.63, CNN+BiGRU best. The authors say generalisation "to the full LID-DS 2021 scenario set remains unverified".
  — [DOI 10.3390/electronics15091856](https://doi.org/10.3390/electronics15091856)
- **Ab-HIDS** (Concurrency and Computation: Practice and Experience, 2024; abstract only).
  - Method: frequency of n-gram syscall features with voting-ensemble and XGBoost classifiers (supervised), plus SMOTE for class imbalance.
  - Data: "evaluated using the Leipzig Intrusion Detection Data Set (LID-DS)"; the version is not stated in the abstract.
  - Results: "+4%" accuracy (voting) and "+6%" (XGBoost); FPR lower by 0.9% and 0.8% "compared to existing state-of-the-art methods".
  — [DOI 10.1002/cpe.8249](https://doi.org/10.1002/cpe.8249)
- **"Adaptive Runtime Security for Kubernetes using eBPF Telemetry and Machine Learning"** (ICOECA 2026; abstract only).
  - Data: "LID-DS system call traces" (version not stated), CICIDS2018 flows and Kubernetes audit logs.
  - Results: "detection rates of 94–95%, less than 2% false positive rate". These figures are not broken down per dataset.
  — [DOI 10.1109/icoeca68095.2026.11485567](https://doi.org/10.1109/icoeca68095.2026.11485567)
- **Computers & Security 2025**, "Enhancing intrusion detection in containerized services…" (abstract only).
  - Method: a graph representation of system calls with ML classifiers.
  - Results: "an increase in detection rates by at least 193% … while maintaining false alarms … below a mean of 0.4%", with sliding-window post-processing.
  - The abstract does not name the dataset, so it is not confirmed as LID-DS.
  — [DOI 10.1016/j.cose.2025.104438](https://doi.org/10.1016/j.cose.2025.104438)
- **"Multi-Scale Feature Fusion Architecture for Linux Process Behavior Anomaly Detection"** (CSCWD 2026) cites the Dataset Report. OpenAlex has no abstract and the full text is paywalled, so its results are unknown — [DOI 10.1109/cscwd68734.2026.11581451](https://doi.org/10.1109/cscwd68734.2026.11581451)

**Other groups, LID-DS 2019 (context only)**
- **CHIDS** (El Khairi, Caselli, Knierim, Peter, Continella; ACM CCSW 2022). This is **LID-DS 2019**, not 2021.
  - The paper cites [24] Grimmer et al. 2019. It describes "10 different attack scenarios … 1,000 normal and 99 attack syscall traces … 30 seconds" each, plus the authors' own CB-DS with 10 container-breakout scenarios, for 20 scenarios in total.
  - Method: system calls are chunked into "scaps" (τ = 1 s) and turned into a syscall sequence graph. Three features — USI (unseen syscalls), UAI (unseen arguments) and FI (frequency, upper limit β = 5) — feed an autoencoder.
  - Threshold: D_thresh = γ × max(training reconstruction error), with "γ = 1.4, which we empirically define".
  - Evaluation: 4-fold cross-validation; "we consider a trace malicious if one of its sequences is malicious".
  - Metrics: trace-level precision, recall, F1, accuracy and AUC.
  — [CHIDS PDF (author site)](https://conand.me/publications/elkhairi-ccsw-2022.pdf); code: [Asbatel/ContainerHIDS](https://github.com/Asbatel/ContainerHIDS)
- **Cross-domain HIDS** (Electronics 11(21):3631, 2022; abstract only). Data: LID-DS, version not stated (by its date, probably 2019). Method: supervised transfer learning. Results: F2 for CWE-307 rose from 80% to 87%, and for CVE-2014-0160 from 13% to 85%, from the in-domain to the cross-domain setting — [DOI 10.3390/electronics11213631](https://doi.org/10.3390/electronics11213631)
- **Multi-layer Cloud-IDS with LLM / Q-learning** (arXiv 2605.15889) uses "the LID-DS 2019 dataset" for its HIDS layer — [arXiv 2605.15889](https://arxiv.org/abs/2605.15889)
- Papers checked that do not evaluate on LID-DS:
  - Dual-head CNN HIDS (WiPiEC 2026): ADFA-LD only; LID-DS is listed as future work — [WiPiEC](https://wipiec.digitalheritage.me/index.php/wipiecjournal/article/download/143/101)
  - RF+IF ensemble for containers (arXiv 2306.14750): uses its own and other data — [arXiv 2306.14750](https://arxiv.org/abs/2306.14750)
  - REPLICAWATCHER (NDSS 2024): uses its own microservice data and re-implements CHIDS and STIDE-BoSC — [NDSS 2024 PDF](https://www.ndss-symposium.org/wp-content/uploads/2024-286-paper.pdf)
  - CHASE dataset preprint (2026): a new dataset; LID-DS appears only in a comparison table — [Research Square](https://www.researchsquare.com/article/rs-11351546/latest.pdf)

### Inferences
- No 2022–2026 paper was found (searches plus the OpenAlex citation list) that reruns the LID-DS library protocol on all 15 LID-DS 2021 scenarios with a method other than STIDE. OpenAlex shows only 4 citing works for the Dataset Report. So the field has no agreed "state of the art" table for LID-DS 2021.
- The strong numbers on LID-DS 2021 (Guo 96.8% accuracy / 97.7% F1; TextRank F1 0.90–0.94; ICOECA DR 94–95%) are all abstract-level. Each uses a different unit (samples, files, windows) and a scenario subset (13, 3, unknown), and some are supervised. None of them reports recording-level DR together with CFA counts.

### Gaps
- Full text of Guo 2024, TextRank 2026, Ab-HIDS 2024, ICOECA 2026, CSCWD 2026 and C&S 2025 could not be read (paywalls or 403). Their per-scenario numbers, thresholds and LID-DS version are unverified.
- No transformer, LSTM, MLP-on-n-gram or "ensemble/mixed" paper by the LID-DS group on LID-DS 2021 was found, even though the code has those engines. A Leipzig thesis or dissertation by Grimmer may exist but was not found.
- Semantic Scholar and dblp APIs were rate-limited (HTTP 429), so citation coverage depends on OpenAlex and web search.

## Q2. Evaluation protocol of the LID-DS library (exact definitions)

### Takeaway
The library scores at system-call level, inside the time structure of each recording. There is a fixed training/validation/test split. The threshold is the **maximum anomaly score seen on the validation data** (normal only). An exploit recording counts as detected once, at its first alarm at or after the labelled exploit time. False alarms are counted as **consecutive runs** (CFA) in normal recordings and in the pre-exploit part of exploit recordings. Precision and F1 are computed from those alarm counts.

### Cited Findings
- **Threshold (code).** `determine_threshold()` docstring: "decision engine calculates anomaly scores using validation data, saves biggest score as threshold for detection phase". `max_score = max(anomaly_score over validation_data())` — [algorithms/ids.py](https://github.com/LID-DS/LID-DS/blob/master/algorithms/ids.py)
- **Decider.** `MaxScoreThreshold` docstring: "Saves maximum anomaly score of validation data as threshold". `_calculate` returns True "if anomaly_score > self._threshold" — [features/impl/max_score_threshold.py](https://github.com/LID-DS/LID-DS/blob/master/algorithms/features/impl/max_score_threshold.py)
- **Same rule in the paper.** EISA 2021 (2019 data): "we use the maximum anomaly score from the corresponding validation part of the normal behavior as the threshold … By using the validation data, we prevent overfitting compared to using the actual training data" — [EISA 2021 PDF](https://dbs.uni-leipzig.de/files/research/publications/2021-11/pdf/EISA2021_Improving%20Host-based%20Intrusion%20Detection%20Using%20Thread%20Information.pdf)
- **Detection rate (code).** `detection_rate = self._alarm_count / self._exploit_count`. `_alarm_count` goes up by one per exploit recording, on the first anomalous syscall with `exploit_time <= syscall_time` (comment: "making sure there is only one true detected alarm in each exploit recording"). The exploit time is `recording.metadata()["time"]["exploit"][0]["absolute"]`, i.e. the first exploit timestamp; the code carries a "TODO: fix the timestamps" — [algorithms/performance_measurement.py](https://github.com/LID-DS/LID-DS/blob/master/algorithms/performance_measurement.py)
- **False positives (code).**
  - Syscall-level `false_positives` counts every anomalous syscall in normal recordings, plus every anomalous syscall in exploit recordings whose timestamp is before the exploit time.
  - Consecutive anomalous syscalls are merged into one CFA. There are two counters: `consecutive_false_positives_normal` and `consecutive_false_positives_exploits` (pre-exploit part of attack recordings).
  - Any open CFA is closed when a new recording starts.
  — [performance_measurement.py](https://github.com/LID-DS/LID-DS/blob/master/algorithms/performance_measurement.py)
- **Precision and F1 (code):**
  - `precision_with_cfa = alarm_count / (alarm_count + cfp_count_normal + cfp_count_exploits)`
  - `precision_with_syscalls = alarm_count / (alarm_count + fp)`
  - `f1_cfa = 2·precision_cfa·DR / (precision_cfa + DR)`
  - `recall` is the same as `detection_rate`.
  — [performance_measurement.py](https://github.com/LID-DS/LID-DS/blob/master/algorithms/performance_measurement.py)
- **Paper definition (2019 data).** EISA 2021 defines four quadrants from the threshold and t′attack = tattack − 2 s ("tattack is somewhat imprecise so that we soften this value"). An FA is a score above the threshold before t′attack. "alarms that directly follow each other should only counted as a single alarm". A TP needs "at least one anomaly score in quadrant 1 … for an attack file". DR = TP/A, where A is the number of attacks in the test data of a scenario. "To compare the results in this work we use DR and FA" — [EISA 2021 PDF](https://dbs.uni-leipzig.de/files/research/publications/2021-11/pdf/EISA2021_Improving%20Host-based%20Intrusion%20Detection%20Using%20Thread%20Information.pdf)
- **Split.**
  - LID-DS 2021 ships fixed `training`, `validation` and `test` folders; test recordings are typed normal or `NORMAL_AND_ATTACK`. The loader exposes `training_data()`, `validation_data()` and `test_data()` — [dataloader/data_loader_2021.py](https://github.com/LID-DS/LID-DS/blob/master/dataloader/data_loader_2021.py); [Dataset Report](https://dbs.uni-leipzig.de/file/978-3-031-35190-7_6.pdf)
  - For 2019, EISA used "The first 200 normal sequences … as training data, the next 50 … as validation data and the remaining normal and attack sequences … as test data". Each scenario has about 1137 files (about 1021 normal, 116 attack) of 30–60 s — [EISA 2021 PDF](https://dbs.uni-leipzig.de/files/research/publications/2021-11/pdf/EISA2021_Improving%20Host-based%20Intrusion%20Detection%20Using%20Thread%20Information.pdf)
- **Reference output (LID-DS 2021, CVE-2017-7529).** The wiki example runs STIDE on 7-grams of syscall names, without thread awareness, with StreamSum window 100, MaxScoreThreshold, and `Direction.CLOSE`. Output:
  - detection_rate 1.0 (119 of 119 exploit recordings)
  - consecutive_false_positives_normal 5, consecutive_false_positives_exploits 0
  - precision_with_cfa 0.9597, f1_cfa 0.9794
  - false_positives 466 syscalls, precision_with_syscalls 0.2034
  - This is per scenario, under the max-validation-score threshold.
  — [wiki: ids_example](https://github.com/LID-DS/LID-DS/wiki/ids_example)
- **Scenario types (wiki).** 15 scenarios. Four are "multi" (CVE-2017-12635_6, CVE-2020-23839, Juiceshop, CVE-2020-13942); the other 11 are "simple" — [wiki: Scenarios](https://github.com/LID-DS/LID-DS/wiki/Scenarios)
- **Library scope.** "62 composable building blocks". The unified loader supports "LID-DS-2019, LID-DS-2021, ADFA-LD, CTF (WRTD), and scap (CB-DS)". The repo ships `tools/defect_recordings/defect_files.json`, with an entry for each of the 15 scenarios. Last commit checked: 2026-08-29 — [LID-DS README](https://github.com/LID-DS/LID-DS)

### Inferences
- "Avg. false alarms 24.47" in the CRITIS figure is most likely the mean, over the 15 scenarios, of CFA-style alarm counts per scenario test set, not a rate. The paper text does not say this explicitly.
- Two protocol details matter when comparing a new detector with the published numbers:
  - Cost unit: the library counts alarms (runs), not syscall-level FPR.
  - Labels: pre-exploit syscalls in attack recordings are scored as normal, so an early alarm in an attack recording is a false alarm, not a detection.
- The current library code compares directly against the exploit timestamp. The −2 s softening described in EISA 2021 does not appear in `performance_measurement.py`. Numbers from the paper and from the library can therefore differ slightly.
- Max-validation-score thresholds give no false alarms on validation by construction. Test FA comes from normal behaviour that validation did not cover, which is why FA grows with scenario size (the 2021 scenarios are about 8.5× larger).

### Gaps
- No published table gives the number of test exploit recordings per scenario for LID-DS 2021. Only the example value for CVE-2017-7529 is known: 119 with `Direction.CLOSE`.
- An unpublished evaluation artifact exists in the repo: `algorithms/evaluation/STIDE_Mode_Flag_eval.ipynb` and `stide_mode_flag.db`. Its best STIDE setting (n = 3, window 800) averages DR 0.881 with CFP_sum 7.6 over 10 scenarios. The dataset version is not stated: exploit_count is 174 for CVE-2017-7529, versus 119 in the 2021 wiki example. Treat it as unverified and unpublished — [repo algorithms/evaluation](https://github.com/LID-DS/LID-DS/tree/master/algorithms/evaluation)

## Q3. Per-scenario numbers and which scenarios are hard

### Takeaway
No source opened here publishes per-scenario **LID-DS 2021** numbers under the library protocol. The only 2021 per-scenario figures are window-level ones for six scenarios (Kozachok et al. 2026), and they are weak (self-detection F1 ≤ 0.31). On **LID-DS 2019**, the hard scenarios that recur are CVE-2014-0160 (Heartbleed), CVE-2012-2122 and, for some models, ZipSlip and Bruteforce. Thread information or argument/frequency context fixes most of them.

### Cited Findings
**LID-DS 2021, window-level (Kozachok et al., arXiv 2606.22581).** Threshold calibrated on normal-only data at target FPR α; values are realised FPR / precision / recall / F1. Source: [arXiv 2606.22581](https://arxiv.org/abs/2606.22581).

Self-detection (Table 3):

| Scenario | α | Realised FPR | Precision | Recall | F1 |
|---|---|---|---|---|---|
| Bruteforce_CWE-307 | 0.01 | 0.0315 | 0.1870 | 0.1652 | 0.1754 |
| Bruteforce_CWE-307 | 0.05 | 0.0834 | 0.1222 | 0.2646 | 0.1671 |
| CVE-2012-2122 | 0.01 | 0.0099 | 0.9301 | 0.0637 | 0.1192 |
| CVE-2012-2122 | 0.05 | 0.0498 | 0.8443 | 0.1304 | 0.2259 |
| CWE-89-SQL-injection | 0.05 | 0.0512 | 0.3546 | 0.2197 | 0.2713 |
| Juice-Shop | 0.05 | 0.0518 | 0.1809 | 0.1059 | 0.1336 |
| EPS_CWE-434 | 0.05 | 0.0899 | 0.0665 | 0.1575 | 0.0935 |
| PHP_CWE-434 | 0.05 | 0.0487 | 0.1202 | 0.1769 | 0.1431 |

Combined CWE-level detectors (Table 5):

| Class | α | Realised FPR | Precision | Recall | F1 | FP | FN |
|---|---|---|---|---|---|---|---|
| CWE-307 | 0.001 | 0.0017 | 0.9902 | 0.1589 | 0.2739 | 376 | 200,142 |
| CWE-307 | 0.01 | 0.0179 | 0.9642 | 0.4368 | 0.6013 | 3,859 | 134,010 |
| CWE-307 | 0.05 | 0.0702 | 0.8994 | 0.5698 | 0.6976 | 15,163 | 102,369 |
| CWE-89 | 0.05 | 0.0381 | 0.2810 | 0.1674 | 0.2098 | — | — |
| CWE-434 | 0.05 | 0.0560 | 0.1168 | 0.1933 | 0.1456 | — | — |

- Test frames per scenario (normal windows / exploit windows): Bruteforce 103,278 / 4,528; CVE-2012-2122 112,723 / 233,425; SQLi 115,279 / 9,599; Juice-Shop 34,936 / 3,777; EPS 37,628 / 1,530; PHP 114,328 / 4,296 (Table 1).
- Cross-CVE transfer Brute→CVE-2012-2122 reaches F1 0.8054, but some rows have realised FPR ≥ 0.6 on target normal data, which the authors mark "operationally unusable".
- The SOTA2 aggregator leaderboard copies the CWE-307 rows but misreads the FP column as 376 / 3 / 15; the paper gives 376 / 3,859 / 15,163 — [SOTA2 CWE-307 leaderboard](https://www.sota2.com/research/sota/intrusion-detection-on-lid-ds-cwe-307-2021) vs [arXiv 2606.22581](https://arxiv.org/abs/2606.22581)

**LID-DS 2019, recording-level DR and FA (EISA 2021).** FA is the number of consecutive alarms per scenario test set; the threshold is the max validation score. Source: [EISA 2021 PDF](https://dbs.uni-leipzig.de/files/research/publications/2021-11/pdf/EISA2021_Improving%20Host-based%20Intrusion%20Detection%20Using%20Thread%20Information.pdf).

STIDE (Table 6). Without TI uses the same n = 5, l = 1000 as conf. 3; with TI is conf. 3. Values are DR / FA.

| Scenario | Without TI | With TI |
|---|---|---|
| BF | 0.94 / 66 | 0.94 / 24 |
| 2012 | 0.03 / 4 | 0.99 / 26 |
| 2014 | 0.00 / 3 | 0.95 / 44 |
| 2017 | 0.97 / 9 | 0.99 / 5 |
| 2018 | 0.99 / 25 | 0.99 / 12 |
| 2019 | 1.00 / 8 | 1.00 / 18 |
| EPS | 1.00 / 4 | 1.00 / 12 |
| PHP | 0.95 / 1 | 1.00 / 93 |
| SQL | 0.15 / 18 | 1.00 / 380 |
| ZIP | 0.34 / 1 | 1.00 / 1 |
| Mean | 0.64 / 13.9 | 0.99 / 61.5 |

BOSC (Table 6). Without TI is conf. 1 (n = 11, l = 10000); with TI is conf. 2 (same n and l). Values are DR / FA.

| Scenario | Without TI | With TI |
|---|---|---|
| BF | 0.94 / 32 | 0.94 / 29 |
| 2012 | 0.95 / 11 | 0.99 / 201 |
| 2014 | 0.00 / 1 | 0.59 / 210 |
| 2017 | 0.97 / 9 | 0.99 / 5 |
| 2018 | 0.99 / 19 | 0.99 / 5 |
| 2019 | 1.00 / 4 | 0.99 / 22 |
| EPS | 1.00 / 20 | 1.00 / 604 |
| PHP | 1.00 / 2 | 1.00 / 119 |
| SQL | 1.00 / 40 | 1.00 / 3183 |
| ZIP | 1.00 / 36 | 1.00 / 817 |
| Mean | 0.89 / 17.4 | 0.95 / 519.5 |

SCG, MLP and AE with TI (Table 7, conf. 3). Values are DR / FA.

| Scenario | SCG | MLP | AE |
|---|---|---|---|
| BF | 0.94 / 1 | 0.94 / 1 | 0.00 / 0 |
| 2012 | 0.10 / 67 | 0.98 / 10 | 0.00 / 0 |
| 2014 | 0.95 / 25 | 0.01 / 7 | 0.00 / 0 |
| 2017 | 0.97 / 9 | 0.97 / 14 | 0.97 / 8 |
| 2018 | 0.99 / 35 | 0.99 / 2 | 0.99 / 11 |
| 2019 | 1.00 / 11 | 1.00 / 0 | 1.00 / 3 |
| EPS | 1.00 / 40 | 1.00 / 0 | 1.00 / 0 |
| PHP | 1.00 / 19 | 1.00 / 6 | 1.00 / 0 |
| SQL | 1.00 / 84 | 1.00 / 2 | 1.00 / 0 |
| ZIP | 1.00 / 0 | 0.00 / 0 | 0.27 / 0 |
| Mean | 0.90 / 29.1 | 0.79 / 4.2 | 0.62 / 2.2 |

Scenario-wise best with TI (Table 8). Values are DR / FA, with the configuration.

| Scenario | Best with TI |
|---|---|
| BF | MLP n = 5, l = 1: 0.94 / 0 |
| 2012 | STIDE n = 5, l = 1000: 0.99 / 26 |
| 2014 | STIDE n = 9, l = 10: 0.95 / 18 |
| 2017 | CNN: 0.99 / 4 |
| 2018 | MLP: 1.00 / 28 |
| 2019, EPS, PHP, SQL | AE W2 n = 3 or 7, l = 1: 1.00 / 0 |
| ZIP | BOSC n = 3, l = 10: 1.00 / 0 |

- Without TI, the best 2014 (Heartbleed) result was only DR 0.06 / FA 22 (MLP). The paper says: "DR is especially increased for scenario 2014 (from 0.06 to 0.95)".

**LID-DS 2019, trace-level, CHIDS (CCSW 2022), Table 4.** Values are precision / recall / F1 for CHIDS at γ = 1.4 with 4-fold cross-validation, followed by the recall of two re-implemented baselines: CDL (frequency-vector autoencoder) and STIDE-BoSC. Source: [CHIDS PDF](https://conand.me/publications/elkhairi-ccsw-2022.pdf).

| Scenario | CHIDS P / R / F1 | CDL recall | STIDE-BoSC recall |
|---|---|---|---|
| CWE-307 | 0.9942 / 0.9183 / 0.9547 | 0.9183 | 0.9795 |
| CVE-2012-2122 | 0.9983 / 0.7935 / 0.8842 | 0.6645 | 0.9935 |
| CVE-2017-7529 | 0.9946 / 0.9885 / 0.9915 | 0.0057 | 0.9885 |
| CVE-2018-3760 | 0.9960 / 0.9998 / 0.9979 | 0.8248 | 0.9999 |
| CVE-2019-5418 | 0.9986 / 0.9989 / 0.9987 | 0.0102 | 0.9999 |
| CWE-89 | 0.9986 / 0.9987 / 0.9987 | 0.9999 | 0.9999 |
| CWE-434-PHP | 0.9933 / 0.9987 / 0.9961 | 0.9902 | 0.9999 |
| CWE-434-EPS | 0.9304 / 0.9988 / 0.9634 | 0.4848 | 0.9999 |
| ZipSlip (CVE-2019-0191) | 0.9881 / 0.9987 / 0.9934 | 0.1224 | 0.9999 |

- STIDE-BoSC precision ranges from 0.5165 to 0.9850.
- Heartbleed is missing from Table 4. The paper lists "Failure to detect Heartbleed (CVE-2014-0050 [sic])" as a limitation.
- AUC averages: 99.97% (container breakout, CB-DS), 99.81% (information disclosure), 99.72% (arbitrary code execution) and 96.40% (authentication bypass).

**Abstract-only per-scenario hints**
- Cross-domain paper (LID-DS, version unstated): in-domain F2 is 13% for CVE-2014-0160 and 80% for CWE-307 — [DOI 10.3390/electronics11213631](https://doi.org/10.3390/electronics11213631)

### Inferences
- **Heartbleed (CVE-2014-0160)** is the most consistently hard scenario in the sources read here:
  - It is at or near 0 DR for every algorithm without TI on 2019 data.
  - CHIDS reports it as a failure.
  - The cross-domain paper reports 13% in-domain F2.
  - It is also the smallest 2021 scenario (1.9 M syscalls).
- **CVE-2012-2122 (MySQL authentication bypass)** and **Bruteforce_CWE-307** are hard for sequence-only models without context. They are the lowest-recall rows for CHIDS, the lowest AUC category, and AE scores 0.00 on both with TI. Frequency features help here (see Q4).
- **ZipSlip** is hard for neural next-call or reconstruction models on 2019 data (MLP 0.00, AE 0.27), while STIDE, BOSC and SCG with TI solve it.
- For LID-DS 2021, the multi-step scenarios (CVE-2017-12635_6, CVE-2020-13942, Juice-Shop, CVE-2020-23839) are the largest by system call count (1311.7 M, 849.1 M and 484.9 M for the first three) and are excluded by at least one paper (TextRank). A lower 2021 average DR is plausible there, but no per-scenario 2021 number confirms it.

### Gaps
- No per-scenario LID-DS 2021 STIDE breakdown exists behind the CRITIS average (DR 0.59, FA 24.47); the figure gives only the average.
- No per-scenario 2021 results were found for CVE-2020-9484, CVE-2020-13942, CVE-2020-23839, CVE-2017-12635_6, CVE-2019-5418, CVE-2018-3760, CVE-2017-7529 (other than the wiki example) or CVE-2014-0160.
- The TextRank paper says "six multi-stage attacks were excluded", while the wiki marks only four scenarios as multi. That discrepancy could not be resolved without the full text.

## Q4. Best reported overall detection rate and its false-alarm cost; frequency-only methods vs sequence or argument-aware ones

### Takeaway
- **LID-DS 2021:** the only verified all-scenario number is STIDE at DR 0.59 with about 24.5 false alarms per scenario. Claims of ≥95% (Guo 2024: 96.8% accuracy and 97.7% F1 on 13 scenarios; ICOECA 2026: DR 94–95% at <2% FPR) are abstract-only and use different protocols.
- **LID-DS 2019:** DR ≈ 0.98–0.99 is reached by thread-aware STIDE or BOSC, at a cost of about 19–110 false alarms per scenario. Low-FA models (MLP with TI: FA 4.2; AE with TI: FA 2.2) only reach DR 0.79 and 0.62.
- **Frequency-only methods** (BOSC, CDL) are competitive on some scenarios but fail on information-disclosure scenarios. Methods that add argument or unseen-call context (CHIDS) or thread context (TI) do best.

### Cited Findings
- **LID-DS 2021, all 15 scenarios.** STIDE (n = 7, w = 100, max-validation threshold): DR 0.59, F-score 0.57, avg. false alarms 24.47 — [CRITIS 2022 extended abstract](https://dbs.uni-leipzig.de/files/research/publications/2023-07/pdf/CRITIS_2022_Extended_Abstract_LID-DS-2021.pdf)
- **LID-DS 2021 subsets (abstract only):**
  - Guo 2024, 13 scenarios: accuracy 96.8%, F1 97.7% — [DOI 10.1145/3677892.3677893](https://doi.org/10.1145/3677892.3677893)
  - TextRank 2026, 3 scenarios: deep learning F1 0.90–0.94 — [DOI 10.3390/electronics15091856](https://doi.org/10.3390/electronics15091856)
  - Inter-PSSG 2026: transfer F1 0.882 at FPR 0.048 — [DOI 10.26583/bit.2026.5.15](https://doi.org/10.26583/bit.2026.5.15)
- **LID-DS 2021 subset, full text.** At window level the best combined result is CWE-307 F1 0.6976 at realised FPR 0.0702; CWE-89 and CWE-434 reach F1 ≤ 0.21 — [arXiv 2606.22581](https://arxiv.org/abs/2606.22581)
- **LID-DS 2019, mean over 10 scenarios (Table 5):**
  - "The overall best detection rates are achieved for the BOSC and the STIDE approaches (98,6%) and the lowest number of false alarms for AE and MLP".
  - BOSC with TI (n = 7, l = 1000): DR 0.986, FA 110.4.
  - STIDE with TI (n = 5, l = 1000): DR 0.986, FA 61.5.
  - MLP with TI (n = 7, l = 1): DR 0.789, FA 4.2.
  - AE with TI (W5, n = 7, l = 1): DR 0.622, FA 2.2.
  — [EISA 2021 PDF](https://dbs.uni-leipzig.de/files/research/publications/2021-11/pdf/EISA2021_Improving%20Host-based%20Intrusion%20Detection%20Using%20Thread%20Information.pdf)
- **LID-DS 2019 at fixed FA budgets (Table 9, with TI):**
  - FA < 40: STIDE n = 5, l = 100 — DR 0.983, FA 23.7.
  - FA < 20: BOSC n = 3, l = 10 — DR 0.982, FA 18.9.
  - FA < 10 and FA < 5: MLP n = 7, l = 1 — DR 0.788, FA 4.2.
  - FA < 2.5: AE n = 7, l = 1 — DR 0.622, FA 2.2.
  - Without TI, the best are BOSC n = 7, l = 100 (DR 0.710, FA 14.9) and MLP (DR 0.526–0.528, FA 2.3–3.1).
  - The authors' view: "a configuration with DR = 0.80 and FA = 10 might be more effective than one with DR = 0.90 and FA = 100 or even DR = 0.99 and FA = 1000".
  — [EISA 2021 PDF](https://dbs.uni-leipzig.de/files/research/publications/2021-11/pdf/EISA2021_Improving%20Host-based%20Intrusion%20Detection%20Using%20Thread%20Information.pdf)
- **Frequency-only method 1: BOSC (EISA 2021, 2019 data).** Definition: it "does not consider the order of system calls in a n-gram but only the frequency of occurrence"; anomaly = ratio of mismatching bags in the streaming window.
  - Without TI: DR 0.885, FA 17.4 (n = 11, l = 10000). This is higher DR than STIDE without TI (0.879, FA 12.5) and much higher than SCG, SVM, MLP, CNN and AE without TI (0.56–0.71).
  - BOSC without TI still gets 0.00 DR on Heartbleed, but 0.95 on CVE-2012-2122, where STIDE without TI gets 0.03.
  — [EISA 2021 PDF](https://dbs.uni-leipzig.de/files/research/publications/2021-11/pdf/EISA2021_Improving%20Host-based%20Intrusion%20Detection%20Using%20Thread%20Information.pdf)
- **Frequency-only method 2: CDL (re-implemented in CHIDS, 2019 data).** 100 ms sequences → frequency vector → autoencoder, threshold at the 99.99th percentile.
  - "works well for attacks exhibiting a high number of syscalls. However, it fails to detect attacks emitting different syscall patterns, such as unseen arguments"; average precision 75.72%.
  - Recall collapses on CVE-2017-7529 (0.0057), CVE-2019-5418 (0.0102), ZipSlip (0.1224) and EPS (0.4848).
  - STIDE-BoSC gets recall of about 0.98–1.0 but "a significant number of false positives", with average precision 61.82%.
  — [CHIDS PDF](https://conand.me/publications/elkhairi-ccsw-2022.pdf)
- **Frequency as one feature (CHIDS ablation and preliminary analysis, 2019 data).**
  - FI alone gives AUC 95.22% on CVE-2012-2122, where USI and UAI are 50% (no unseen calls or arguments there). FI gives 48.88% on M-U_HELPER (a CB-DS scenario) and 81.81% on ZipSlip, where UAI gives 99.96%.
  - A high-frequency observable appears in 86.73% of CWE-307 exploit traces versus 0.21% of normal traces, and in 0% of CVE-2017-7529 exploit traces. Unseen syscalls appear in 97.72% of CVE-2017-7529 exploit traces.
  — [CHIDS PDF](https://conand.me/publications/elkhairi-ccsw-2022.pdf)
- **Frequency-based supervised, LID-DS (version unstated; abstract only).** Ab-HIDS (n-gram frequency + voting/XGBoost) reports "+4%/+6%" accuracy and FPR −0.9/−0.8 points over prior work — [DOI 10.1002/cpe.8249](https://doi.org/10.1002/cpe.8249)
- **Mixed features on LID-DS 2021, window level.** The 66 features (frequency + unseen-argument/syscall + return values + PID/TID + time deltas) give weak one-class self-detection at calibrated FPR (F1 ≤ 0.31) — [arXiv 2606.22581](https://arxiv.org/abs/2606.22581)

### Inferences
- What counts as good depends on the protocol:
  - Under the LID-DS library protocol (recording-level DR, CFA alarms, max-validation threshold), the 2019 numbers show the achievable frontier: DR ≈ 0.98 at about 19–24 alarms per scenario test set, or DR ≈ 0.79 at about 4.
  - The 2021 baseline (DR 0.59, about 24.5 FA) leaves a large gap.
  - No source opened here shows >90–95% DR with low FA on all 15 LID-DS 2021 scenarios under that protocol.
- The 2019 "best" numbers come from choosing configurations after a grid search of more than 30,000 configurations scored on the test data. They are optimistic upper bounds, not held-out results. CHIDS' γ = 1.4 was also "empirically defined" on evaluation outcomes, with trace-level scoring.
- Frequency-only signals are complementary rather than sufficient:
  - They catch volume-type attacks (brute force, MySQL auth bypass, SQLi and PHP upload in CDL).
  - They miss information-disclosure and path or argument attacks (nginx CVE-2017-7529, Rails CVE-2019-5418, ZipSlip, Heartbleed).
  - Argument-aware features (UAI) and unseen-syscall features (USI) or thread context close those gaps.
- Sample-, window- and file-level accuracy or F1 figures (Guo, TextRank, Kozachok) should not be compared with recording-level DR. The CVE-2012-2122 test frame in Kozachok et al. has about 2× more exploit windows than normal ones, so accuracy and F1 there reward recall heavily.

### Gaps
- The full texts of Guo 2024 and ICOECA 2026 could not be read. These are the only sources claiming ≥94% on LID-DS (2021 or unstated), so whether they reach >90–95% DR with low false alarms under a comparable protocol remains unverified.
- No published LID-DS 2021 result was found for a pure bag-of-system-calls or frequency-vector detector under the library protocol. The frequency comparisons above are on LID-DS 2019 (EISA BOSC, CHIDS/CDL) or on 2021 at window level with mixed features.
- No published LID-DS 2021 numbers with thread information (TI) were found, although the library supports thread-aware n-grams.
