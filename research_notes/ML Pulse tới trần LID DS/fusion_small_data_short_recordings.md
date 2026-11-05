# Learned fusion, little normal data and short recordings for container syscall anomaly detection

Research date: 2026-11-05. Builds on `research_notes/Cải thiện ML Pulse LID DS/model_design_and_fusion.md` (2026-11-01) and does not repeat its Vovk-Wang, Bates FPR-spread and Fisher-invalidity details.

Evidence tags: **[Measured]** = number from an experiment in the source. **[Theorem]** = proved in the source. **[Claim]** = author statement; no number was checked here, or only an abstract or search excerpt was read. **[Project]** = development-only number supplied by the coordinator or the repo log, not a published result. Everything under "Inferences" is my reasoning, not a sourced result. Worked figures in Inferences come from a small script (Beta mean and spread, Gaussian quantiles, tangent and chi-square arithmetic); inputs are stated beside each figure.

**Project context used:** [Project] greedy selection with Bonferroni on a recording-level alpha picks language model, I/O tree with fix A, then support: recall 78.3 %, then 80.1 %, then 81.4 %, at about 0.75 % false alarms, p95 latency 2.44 s. Adding the tree over 249 count features does not help. Earlier: Cauchy 61 % against 67 % recall; the two-window rule costs about 25 recall points on development (repo commit fa376b2).

## Fusion from normal data only: normalisation, copulas, meta-models, p-value combiners

### Takeaway
Score normalisation and dependence modelling are well studied, but no benchmark found compares these fusions under normal-only training with sparse (one-branch) alternatives. The closest method to Pulse's floor problem is max-rank, which calibrates the maximum of the branch ranks jointly on normal data instead of dividing alpha by K. It beat Bonferroni in its own benchmark, at alpha = 0.1 and without anomaly data.

### Cited Findings
**Normalisation**
- [Measured] Kriegel et al. Table 5, ROC AUC on KDDCup1999 when combining different methods (LOF, LDOF, kNN, aggregated kNN): mixture-model mean 0.5180, maximum rank 0.9046, unscaled mean 0.9104, sigmoid mean 0.9236, HeDES scaled mean 0.9386, mean of unified scores 0.9413. On ALOI, for the same method combination, the lower rows include mixture-model mean 0.7541, maximum rank 0.7546 and unscaled mean 0.7709 (the upper rows were not read). — [Kriegel et al., SDM 2011](https://web.archive.org/web/2020/https://www.dbs.ifi.lmu.de/~zimek/publications/SDM2011/SDM11-outlier-preprint.pdf)
- [Measured] In the same paper, for the combination of different methods on KDDCup1999, unified-score mean gains 0.0309 AUC over unscaled mean and 0.0367 over maximum rank. This is a ranking metric over datasets with outliers present, not a calibrated decision at about 1 % FPR. — [Kriegel et al.](https://web.archive.org/web/2020/https://www.dbs.ifi.lmu.de/~zimek/publications/SDM2011/SDM11-outlier-preprint.pdf)
- [Claim] None of Kriegel's assumed score distributions (uniform, Gaussian, Gamma) wins every experiment. Sigmoid and mixture calibrations are "rather unstable" and favour the extremes 0 and 1, which degrades combination to counting. — [Kriegel et al.](https://web.archive.org/web/2020/https://www.dbs.ifi.lmu.de/~zimek/publications/SDM2011/SDM11-outlier-preprint.pdf)
- [Claim] Standard statistical scaling yields worse probabilities for outliers than for inliers; robust estimators improve the outlier side. — [Röchner et al., arXiv 2408.15874](https://arxiv.org/abs/2408.15874)

**Copula and tail-sum detectors**
- [Measured] COPOD: average ROC-AUC 82.47 % over 30 datasets, 1.5 points above the second best; first on 12 of 30. — [Li et al., ICDM 2020](https://arxiv.org/abs/2009.09463)
- [Measured] ECOD aggregates per-dimension tail probabilities and reports a statistically significant ROC win over 11 baselines. — [Li et al., ECOD](https://arxiv.org/abs/2201.00382). Contradicted in general by ADBench below: COPOD and ECOD are in its benchmark, yet it finds no statistically superior unsupervised method.
- [Measured] Copula and max-rank corrections on multi-target conformal regression (alpha = 0.1, 100 trials, 20 % calibration). Dataset scpf (m = 3, 1,137 samples, so about 227 calibration points): Bonferroni coverage 0.95, width 46.73; Gumbel copula 0.90, 30.15; empirical copula 0.92, 34.38; max-T 0.91, 53.77; max-rank 0.91, 32.28. Dataset rf1 (m = 8): Bonferroni 0.92, 7.18; max-rank 0.90, 6.08. Dataset scm1d (m = 16): Bonferroni 0.96, 793.70; max-rank 0.90, 564.01. The authors note that max-T and max-rank suffer from the small sample on scpf, where the parametric Gumbel copula benefits from low dimension. — [Timans et al., AISTATS 2025](https://arxiv.org/abs/2311.10900); copula methods from [Messoudi et al., arXiv 2101.12002](https://arxiv.org/abs/2101.12002)
- [Measured] Max-rank needs enough calibration data for family-wise error control: roughly n >= 100 m at rho = 0 in its simulation (FWER level 0.05). Higher correlation lowers the need. — [Timans et al.](https://arxiv.org/abs/2311.10900)

**P-value combiners under dependence**
- [Theorem] Heavy-tailed combiners are equivalent to Bonferroni as alpha tends to 0, and in that regime there is "no power gain over the Bonferroni test". [Measured] At finite alpha the gains appear "particularly in situations where signals are dense". — [Aggregating Dependent Signals, arXiv 2310.20460](https://arxiv.org/abs/2310.20460)
- [Claim] The Cauchy combination may be less powerful when signals are mixed, meaning some p-values are small and others large. [Theorem] Its power is no less than minP as the number of p-values grows, under regularity conditions. — [Long et al., American Statistician 2023](https://arxiv.org/abs/2107.06040)
- [Claim] Only the Cauchy and harmonic-mean class has practical robustness to dependence, and Cauchy has a large negative penalty for p-values near 1, addressed by a truncated Cauchy. — [Fang et al., Statistica Sinica 2023](https://arxiv.org/abs/2103.12967)
- [Claim] Wilson's harmonic mean loses error guarantees under general dependence; Simes/BH is robust to positively dependent p-values. — [Goeman, Rosenblatt, Nichols, PNAS 2019](https://pmc.ncbi.nlm.nih.gov/articles/PMC6876242)
- [Claim] Conformal p-values sharing a calibration set are positively dependent (PRDS across test points), which makes independence-based corrections conservative a priori. — [Bates et al., Ann. Statist. 2023](https://arxiv.org/abs/2104.08279); [Timans et al.](https://arxiv.org/abs/2311.10900)

**Meta-models and selection from normal data**
- [Measured] Over 39 tasks and 297 candidate models, the three existing internal selection strategies were not significantly different from random selection. Consensus-based ones beat random but were no better than iForest alone. — [Ma et al., arXiv 2104.01422](https://arxiv.org/abs/2104.01422)
- [Measured] None of ADBench's unsupervised methods is statistically better than the others (57 datasets). [Claim] Performance depends on whether a detector's assumptions match the anomaly type. — [Han et al., NeurIPS 2022](https://arxiv.org/abs/2206.09426)
- [Claim] LSCP's average-of-maximum variant outperforms baselines on most of 20 real datasets, using a local pseudo ground truth rather than labels. — [Zhao et al., SDM 2019](https://arxiv.org/abs/1812.01528)
- [Claim] Tax's one-class combining rules: product suits independent inputs, mean suits correlated or noisy inputs. This comes from a secondary summary only. — [Tax & Duin via citing paper](https://arxiv.org/pdf/1112.5246v2)
- [Claim] The modular one-class ensemble of Giacinto et al. maps outputs to density functions before combining, evaluated on KDD-Cup 1999. No max-rule number was retrieved. — [Information Fusion 2008 record](https://dblp.uni-trier.de/rec/journals/inffus/GiacintoPRR08.html)

### Inferences
- **Why max-rank is the first thing to test.** For each normal recording, rank each branch's score, take the maximum rank across branches, and set one threshold on that maximum. Under exchangeable recordings this targets recording-level alpha with no division by K. It is simple, needs no distribution and costs about the same as Bonferroni at runtime. The scpf row is the nearest published analogue: 3 tests and about 227 calibration points, 31 % narrower than Bonferroni. That was at alpha = 0.1, not 1 %.
- **COPOD and ECOD have the wrong shape for a sparse pattern.** Both sum per-dimension log tail probabilities, which is the shape of Fisher. A worked case is under the next question.
- **A one-class meta-model on the score vector is low priority.** Ma et al. suggest that normal-only evaluation cannot pick it, and with 3 branches there is little joint structure to learn. Mahalanobis gives an elliptical region, while the wanted region is a box (any one branch exceeds).
- **Normalisation is largely settled by conformal ranks at this scale.** Kriegel's gains are AUC on datasets containing outliers. Pulse needs the decision at about 1 %, where only the far tail matters, and a Gaussian fit to the bulk says little about that.

### Gaps
- No source found applies Kost or Brown's method, or vine copulas, to detector score vectors. A Poole et al. empirical-Brown paper was searched for but not retrieved. Hommel was not researched.
- No benchmark found compares these fusions at FPR about 1 % with normal-only calibration. ADBench, Zimek and Kriegel use AUC-type metrics.
- Aggarwal & Sathe's outlier-ensemble theory was not retrieved, as the PDF download failed. AOM evidence here comes from LSCP only.
- The full text of Tax & Duin 2001 and of Giacinto et al. 2008 was not read.

## Fusion for this sparse pattern with very few branches; sparse versus dense; when combining loses

### Takeaway
With three branches the sparse pattern favours a union-of-tests decision: Bonferroni, max-rank, or Simes as an extension. The total possible gain from any better correction is bounded by a small gap between alpha/3 and alpha, and it can be measured offline before building anything. The binding constraint is calibration resolution, not the combiner.

### Cited Findings
- [Project] Recall rises 78.3 %, 80.1 %, 81.4 % with diminishing gains. The tree over 249 count features adds nothing, and Cauchy did worse than Bonferroni.
- [Theorem] Any reasonable combiner is optimal against some alternative. Fisher suits positive data larger under H1, George/Stouffer suits approximately Gaussian data. Fisher is sensitive to the smallest p-value and Pearson to the largest. The likelihood-ratio alternative behind Tippett (min-p) is "uncomfortable" under independence, so the authors find it "very difficult to justify in practice". — [Heard & Rubin-Delanchy, Biometrika 2018](https://arxiv.org/abs/1707.06897). This conflicts in tone with the sparse-optimality result for Cauchy and minP-like tests in [Liu & Xie, JASA 2020](https://arxiv.org/abs/1808.09011v1), which rests on a sparse-signal alternative and a different framing.
- [Measured] On ADFA-LD, tail p-values fused by sum or max of -log p did not beat the best single detector at the declared operating point: 3-gram DR at 1 % FPR 0.165, Max(3-gram, LSTM) 0.123, LSTM 0.106. Not peer-reviewed. — [syscall-ids-benchmark](https://github.com/saishyamdontha/syscall-ids-benchmark)
- [Claim] Ensembles need both accuracy and diversity, and diversity cannot be easily assessed without labels. — [Zimek, Campello, Sander, SIGKDD Explorations 2013](https://kdd.org/exploration_files/V15-01-02-Zimek.pdf)
- [Claim] Selecting among detectors by per-dataset meta-learning significantly outperformed always using one popular model or the ensemble of many, in the authors' benchmark. — [Zhao, Rossi, Akoglu, MetaOD, NeurIPS 2021](https://papers.nips.cc/paper_files/paper/2021/file/23c894276a2c5a16470e6a31f4618d73-Paper.pdf)

### Inferences
- **Why the sparse pattern suits very few branches.** Each branch catches a different scenario, so a recording usually needs one branch only. That is a union rule, and a sum-type statistic pays for quiet branches.
- **Worked case at the floor** (n = 260 calibration recordings, floor 1/261, K = 3, one branch at floor):
  - Bonferroni needs 3/261 = 1.15 %, so it misses at alpha = 1 %. It needs n >= 299 at 1 % or n >= 399 at 0.75 % (K/alpha - 1).
  - Cauchy, other two p = 0.5: T = 27.7 against thresholds 31.8 (1 %) and 42.4 (0.75 %), a miss. Others at p = 0.99: T = 6.5, so the quiet branches cancel most of the signal.
  - Fisher, other two p = 0.5: statistic 13.9 against chi-square(6) 16.81 at 1 %, a miss.
  - This is a plausible explanation for Pulse's Cauchy result (61 % against 67 %), and agrees with the mixed-signal and negative-penalty findings above. It is not yet verified on Pulse data. A truncated Cauchy would remove the penalty but not the floor.
- **Upper bound test, offline, no new model.** Run each selected branch at the undivided alpha and record the union false-alarm rate. The ratio of union rate to per-branch rate is the effective number of tests. If it is close to 3, the branches are nearly disjoint on normal data and max-rank will buy little. If it is close to 1, max-rank can recover most of the Bonferroni price. In a Gaussian tail, alpha/3 against alpha at 0.75 % is a shift of 0.375 standard deviations (z 2.807 against 2.432), so the gain is bounded by the recordings inside that gap.
- **Observed 0.75 % against target.** The coordinator gave no alpha target. If the target was 1 %, then a quarter of the budget is unused, and that slack is the immediate room for any correction.
- **Simes** rejects if p(1) <= alpha/3, p(2) <= 2 alpha/3 or p(3) <= alpha, by its definition. It equals Bonferroni for one firing branch and adds only recordings where two or three branches are moderate, so it is a low-cost extension. Its validity across branches of one recording is assumed rather than proved, so check it on normal data.
- **When combining will lose.** Adding a branch whose unique catches are fewer than those lost to the tighter threshold reduces recall. The count tree appears to be in that state. With 3 branches at +1.8 and +1.3 points, a fourth branch needs a measurable unique catch. Keep the branch list frozen after development to avoid selection bias.

### Gaps
- No published comparison of max-rank, Simes and Bonferroni on detector scores with one firing branch at alpha about 1 % was found.
- Whether Pulse's recording-level calibration uses 60, 200 or 260 recordings, or out-of-fold scores, was not stated. The floor arithmetic above needs the true n.

## Data-driven alpha budgets per branch and per scenario from normal data

### Takeaway
Normal data can legitimately inform a budget through dependence between branches, discreteness of scores and tail shape, but it holds no direct information on power. Weights for power must come from frozen development scenarios or a covariate that is independent under the null. Per-scenario budgets are poorly determined at this sample size, whereas a budget averaged across scenarios is much better determined.

### Cited Findings
- [Theorem, excerpt only] Weighted Bonferroni is valid for any nonnegative weights meeting a budget, chosen without reference to the p-values being tested. [Claim] An earlier report by the same authors says power is "remarkably robust" to misspecified weights; exact conditions were not checked. — [Roeder & Wasserman, Statistical Science 2009](https://arxiv.org/abs/1010.4637); [earlier report](https://arxiv.org/abs/math/0701104)
- [Claim] Independent hypothesis weighting learns weights from a covariate independent of the p-value under the null but informative on power. Cross-fitting makes a hypothesis's weight independent of its own p-value. A Bonferroni variant exists. — [Ignatiadis et al., Nature Methods 2016](https://pmc.ncbi.nlm.nih.gov/articles/PMC4930141); [IHW manual](https://bioc.r-universe.dev/IHW/doc/manual.html)
- [Theorem, excerpt only] Tarone's procedure drops tests whose minimal attainable p-value is too large to be rejected, giving a larger critical value. Zhu & Guo's modified Bonferroni uses a single threshold such that the summed null CDFs stay within alpha. It is universally more powerful than Tarone and reduces to ordinary Bonferroni for uniform nulls. — [Zhu & Guo, arXiv 1711.08147](https://arxiv.org/abs/1711.08147)
- [Theorem] Under group-balanced conformal, calibration is run per group, with a per-group guarantee. — [Angelopoulos & Bates, gentle introduction](https://arxiv.org/abs/2107.07511)
- [Theorem] Realised FPR for marginal conformal follows Beta(l, n+1-l), l = floor((n+1) alpha). — [Bates et al.](https://arxiv.org/abs/2104.08279)
- [Measured] On LID-DS 2021, normal-only calibrated thresholds realised FPR above target: Bruteforce 0.0315 at target 0.01, EPS_CWE-434 0.0899 at target 0.05. — [Kozachok et al., arXiv 2606.22581](https://arxiv.org/abs/2606.22581)
- [Claim] Tail models give p-values below the empirical floor: a GPD tail fit needs far fewer resamples for small p-values ([Knijnenburg et al., Bioinformatics 2009](https://pmc.ncbi.nlm.nih.gov/articles/PMC2687965)); extreme conformal prediction targets confidence too high for the calibration size ([Pasche, Lam, Engelke, arXiv 2505.08578](https://arxiv.org/abs/2505.08578)). GPD fits with a negative shape can yield zero p-values ([permApprox, arXiv 2602.22975](https://arxiv.org/abs/2602.22975)). A kernel-density variant avoids the floor but is "strictly not conformal", without finite-sample validity ([Hennhöfer, nonconform, PMLR 2026](https://arxiv.org/abs/2605.13642)).

### Inferences
- **Spread of the realised rate per scenario** (Beta formula, exchangeability assumed):

| Calibration n | Floor | Alpha 1 %: mean FPR ± sd | Across 15 scenarios: sd of mean |
|---|---|---|---|
| 60 | 1.64 % | no finite threshold | n/a |
| 200 | 0.50 % | 1.00 % ± 0.70 % | 0.18 % |
| 260 | 0.38 % | 0.77 % ± 0.54 % | 0.14 % |

- **Consequence.** A per-scenario alpha between 0.5 % and 1 % cannot be resolved at this n, since the threshold moves by one order statistic. A fleet-level average budget is about four times tighter (sqrt(15), assuming scenarios are independent). The defensible claim for a paper is therefore average false alarms across scenarios, with per-scenario spread reported, not per-scenario control.
- **Budget sources ranked by defensibility:**
  1. Equal rank per branch through max-rank (no weights needed).
  2. Zhu-Guo style threshold: a common p threshold such that the sum of each branch's realised normal exceedance stays within alpha. This reallocates automatically if a branch has many ties at zero (likely for the language model on low-surprise scenarios) and needs only normal data.
  3. Fixed weights learned on development scenarios and frozen, for example more on the language model. The weights encode how often each branch has unique catches. That uses development attack labels, not target-scenario ones, so it stays within a leave-one-scenario-out protocol.
  4. Per-scenario normal-only covariates, such as recording length, tail shape or number of ties, used to shift budget between branches. No evidence exists, so treat as exploratory and cross-fit it across scenarios.
- **What normal data cannot do.** A branch with quiet normal behaviour is not necessarily powerful on an unseen attack. Weights fitted from normal only may simply favour the branch with the fewest ties. Compare any such weights with equal weights on development before using them.
- **Tail extrapolation is the only way to split below the floor per scenario.** It loses exact conformal validity, so report realised normal rates on held-out recordings.

### Gaps
- No HIDS or anomaly-detection paper found that sets per-detector alpha budgets from normal data; the methods above come from genomics and discrete multiple testing.
- Measured power loss from misweighting in the Roeder & Wasserman or IHW papers was not extracted, as only abstracts and excerpts were read.

## Few normal data per workload: hybrid models, shrinkage, cross-workload calibration, transfer

### Takeaway
Pooling across scenarios helps only when one normal profile contains the other, which is rare when the stack differs; otherwise it collapses. Reusing data within a scenario through resampling is the best-measured gain. Sharing only tail shape, not behaviour models, is the promising but unmeasured way to borrow strength across scenarios.

### Cited Findings
**Cross-workload transfer measured on LID-DS 2021 (window level)**
- [Measured] Self-detection at target FPR 0.05 gives F1 <= 0.31 in all six scenarios. Bruteforce_CWE-307 to CVE-2012-2122 transfer F1 0.8054; reverse 0.0782. Combined CWE-307 profile: F1 0.6013 at alpha 0.01 (precision 0.9642, recall 0.4368, realised FPR 0.0179) and F1 0.6976 at alpha 0.05 (realised FPR 0.0702). CWE-89 and CWE-434 collapse to F1 <= 0.21. Transfer is "dominated by the breadth of the source normal profile rather than by the CWE label". Caveat: the best candidate per row is chosen on the test frame, while the threshold is set on normal only. — [Kozachok et al.](https://arxiv.org/abs/2606.22581)

**Within-scenario data reuse**
- [Measured] Resampling conformal against split conformal with kNN at FDR 0.1 (mean power). Small datasets: WBC split 0.072 against Jackknife-after-Bootstrap+ 0.638; Ionosphere 0.006 against 0.248 (best variant Jackknife+ 0.275); WDBC 0.382 against 0.782; Breast 0.347 against 0.770. Large datasets gain little: Satellite 0.354 against 0.367; Mammography 0.041 against 0.049; Musk 1.000 in both. The authors report no marginal FDR exceedance, but they state that these variants have no exact finite-sample validity in this setting. — [Hennhöfer & Preisach, arXiv 2402.16388](https://arxiv.org/abs/2402.16388)

**Hierarchical conformal**
- [Measured] CDF pooling across groups undercovers at small to moderate group counts (k <= 35) in simulation and reaches about 1 - alpha for larger k, with the smallest sets. Single and repeated subsampling overcover at small k. Recommendation: CDF pooling if asymptotic coverage is acceptable, repeated subsampling for a guarantee. — [Dunn, Wasserman, Ramdas, JASA 2023](https://arxiv.org/abs/1809.07441)
- [Claim] Meta-learned nonconformity from auxiliary tasks yields "substantially tighter" sets with marginal guarantees, assuming exchangeable tasks; it is slightly conservative with little auxiliary data. Numbers are in figures and were not extracted. — [Fisch et al., ICML 2021](https://arxiv.org/abs/2102.08898)
- [Claim] Regional extreme-value practice assumes a common shape across homogeneous sites with site-specific location and scale; regional GPD estimates beat at-site estimates for small to moderate samples. These are secondary descriptions; the standard reference is Hosking & Wallis. — [Ribatet et al.](https://ar5iv.arxiv.org/html/0802.0433); [EarthRef record](https://earthref.org/ERR/68988); [Automated EVA, arXiv 1611.08261](https://arxiv.org/abs/1611.08261)

**Meta-learning and container-specific approaches**
- [Claim] OFA-TAD trains once on multiple source datasets and generalises to unseen ones (34 datasets, 14 domains), while noting that anomaly patterns are "often domain-specific" and that winners are distributed across datasets. — [OFA-TAD, ICML 2026](https://arxiv.org/abs/2603.14407)
- [Claim] OC-MAML adapts few-shot meta-learning to one-class data. — [Frikha dissertation](https://edoc.ub.uni-muenchen.de/30833/7/Frikha_Ahmed.pdf). MLTDD is a few-shot tabular framework. — [Zhai et al., 2026](https://link.springer.com/article/10.1007/s40747-026-02265-9)
- [Measured] ReplicaWatcher, with no training phase but relying on replicas, reports average precision 91.08 % and recall 98.35 %. — [Replicawatcher, NDSS 2024](https://ndss-symposium.org/ndss-paper/replicawatcher-training-less-anomaly-detection-in-containerized-microservices)
- [Claim] CHIDS builds a per-container behavioural baseline on 30-second traces with no shared model. — [El Khairi et al., CCSW 2022](https://conand.me/publications/elkhairi-ccsw-2022.pdf); [code](https://github.com/Asbatel/ContainerHIDS)
- [Claim] Domain filters on normal stability can destroy the strongest transfer. — [Kozachok et al.](https://arxiv.org/abs/2606.22581)

### Inferences
- **Do not pool behaviour models across LID-DS scenarios by default.** Kozachok's success depends on a superset normal profile, and the coordinator says the stack rarely repeats. Merged normals would also absorb attack behaviour seen as normal in another scenario. It could help only as a tested gated branch for scenarios sharing a stack, such as a clear CWE-307 pair.
- **Out-of-fold scores are the first low-risk gain.** Hennhöfer's biggest gains occur on datasets of a few hundred points, which matches 200 + 60 recordings. Five-fold across recordings gives n about 260 scores instead of 60. This removes the "no finite threshold" row above. Folds must split by recording. It costs training time, not latency, but exact validity is lost, so check the realised rate on held-out normal.
- **Dunn's k <= 35 undercoverage warns against pooling scores across about 15 scenarios for thresholds.** Treat the pooled calibration as approximate.
- **Borrow tail shape only.** A per-scenario threshold with a shared GPD shape per branch type is a hydrology-style shrinkage. It keeps behaviour models per scenario and needs only normal data. It is unmeasured here, so verify by leave-one-scenario-out realised false alarms.
- **ReplicaWatcher does not fit LID-DS directly,** since recordings are not live replicas. Its idea could apply live, where deployed replicas exist, as a separate track.

### Gaps
- No HIDS paper found that uses hierarchical Bayesian shrinkage of per-workload parameters across workloads, or that measures global-plus-local syscall models with a fixed FPR.
- No study measures negative transfer directly on LID-DS beyond Kozachok's six scenarios and its window-level unit.

## Short and sparse recordings; what could replace the 4-contiguous-window requirement

### Takeaway
No HIDS paper found measures zero-filling against gaps directly, so this choice needs a Pulse experiment. Sequence-based and event-based models already cope with idle time and short traces. Ranked options: first check whether the selected branches still need contiguity at all, then history over the last non-empty windows plus a gap feature, then zero-fill, then event-count windows.

### Cited Findings
- [Project] About 24 attack recordings of CVE-2017-7529 (median 25 windows, idle gaps) never have 4 contiguous scored windows. The chosen fusion drops the count tree that needs 3 contiguous history windows. Empty .sc recordings exist in that scenario's training set (commit 127ab37), and a recording without a scored window stays in the denominators as a row with no alarm (commit ecbdb10).
- [Measured] Thread-aware sequence models on LID-DS 2019 reach detection rates near 0.99: STIDE configuration n = 5, stream window 1,000, mean DR 0.986 with 61.5 false alarms; on Heartbleed STIDE+TI 0.95 / 44 and SCG+TI 0.95 / 25; on ZipSlip BOSC+TI n = 3, l = 10 gave 1.00 / 0. These figures operate in syscall-count space, with no time window. Figures are as extracted in the project note `published_ml_results.md`. — [Grimmer, Kaelble, Rahm, EISA 2021](https://dbs.uni-leipzig.de/files/research/publications/2021-11/pdf/EISA2021_Improving%20Host-based%20Intrusion%20Detection%20Using%20Thread%20Information.pdf)
- [Measured] In one WordPress container with RCE exploits, one-class models reach F1 above 97 % with a window of about 1.5 % of the smallest trace of 1,628 calls (24 syscalls, on filtered data with Isolation Forest), and One-Class SVM reaches 98 % below 0.5 %. It is a single attack family in a self-made dataset, so these numbers should not transfer. — [Castanhel et al., ERRC 2020](https://sol.sbc.org.br/index.php/errc/article/view/15203)
- [Claim] CHIDS tried durations from 100 ms to 2 s and picked 1 s: shorter periods "may contain no syscalls" and lead to poor characterisation, longer ones may delay processing. — [El Khairi et al.](https://conand.me/publications/elkhairi-ccsw-2022.pdf)
- [Claim] Kozachok uses 1 s windows at 300 ms step, including inter-event time-delta histograms in 66 features. The paper does not isolate their value and defers window sensitivity. — [Kozachok et al.](https://arxiv.org/abs/2606.22581)
- [Claim] Missingness can be informative: a mask plus the interval since last observation can be fed to a model. Clinical data, not syscalls. — [Che et al., Scientific Reports 2018](https://www.ncbi.nlm.nih.gov/pmc/articles/PMC5904216/)
- [Claim] Anomalous event sequences can be detected with goodness-of-fit tests on temporal point processes, using event times. Not tested on syscalls here. — [Shchur et al., NeurIPS 2021](https://arxiv.org/abs/2106.04465)
- [Claim] Bag-of-system-calls discards call order and keeps frequencies in a window. — [Abed et al., arXiv 1611.03056](https://arxiv.org/abs/1611.03056)

### Inferences
Options to replace the requirement, in the order to try:

| Option | Mechanism | Risk | Latency effect |
|---|---|---|---|
| 0. Check need | Language model counts n-grams and support may need no history. If the alarm path no longer needs the count tree, the 4-window rule may already be removable | Fix A's I/O tree may still have its own history need; verify in code | None |
| 1. Last non-empty history | History = last 3 non-empty windows, with gap length and mask as features; same transform on normal training | Normal idle-to-burst transitions must exist in training | None added; scoring starts at the 4th non-empty window, which may come later after a gap |
| 2. Zero-fill | Treat a missing window as all zeros, use in training and test | Long zero runs dominate, degenerate zero predictions, any burst after idle looks anomalous unless seen in normal | None added; earlier first score |
| 3. Event-count windows | Window closes every N syscalls, with a timeout flush | Features change meaning, count tree needs retraining | Bad on quiet recordings without a timeout; timeout bounds latency |
| 4. History-free branch | Fit a tree with no history inputs, or per-recording summary | Loses the temporal signal | None |
| 5. Availability strata | Calibrate separately per availability pattern (Mondrian) | Few normal recordings per stratum | None |

- **Option 1 is my first model change** because it keeps the 249 features, adds an explicit gap channel in line with Che et al., and needs only a change to how history is built. The gap value itself may separate these attacks, but that is untested.
- **Compare against a floor.** A recording with no scored window must stay a miss, per the existing rule, so report recall over all 24 recordings.
- **Beware of leakage through recording length.** If attack recordings have longer idle gaps than normal ones in LID-DS, the gap feature detects a recording artefact, not exploit behaviour. Check the normal distribution of gap lengths per scenario first, and report the result as a limitation if the gap channel supplies the catches.
- **Empty training recordings** in CVE-2017-7529 argue against discarding idle behaviour: they are part of normal for that scenario.

### Gaps
- No HIDS paper found with a head-to-head of zero-filled windows against gaps, time-based against event-based windows at fixed FPR, or the latency effects of either. Searches returned sliding-window and bag-of-calls work without this comparison.
- No isolated measurement of time-delta features on LID-DS was found.
- The EISA figures were not re-read in this pass; they come from the project's earlier full-text extraction.

## Training-set augmentation for normal data (bootstrap, mixup-like window mixing) and calibration

### Takeaway
No source measures mixup-like augmentation of normal syscall windows or its effect on conformal validity in one-class detection. Augmenting the calibration set is invalid by the exchangeability argument, while out-of-fold resampling provides the same data gain and has measurements behind it. Augmentation should be limited to model fitting and treated as an experiment.

### Cited Findings
- [Claim] Exchangeability fails if data are altered by augmentation, so the coverage guarantee no longer holds; the study compares regimes including Mixup and CutMix on a multi-class grading task. — [Effect of Data Augmentation on Conformal Prediction, arXiv 2508.14266](https://arxiv.org/abs/2508.14266)
- [Claim] Mixup-trained models are less over-confident on out-of-distribution data ([Thulasidasan et al., NeurIPS 2019](https://papers.nips.cc/paper_files/paper/2019/file/36ad8b5f42db492827016448975cc22d-Reviews.html)). Contradicted by: stronger mixup can substantially raise expected calibration error ([NeurIPS 2026 listing](https://neurips.cc/virtual/2026/171818)).
- [Measured] Bootstrap-based calibration raises power on small datasets without synthetic samples (see Hennhöfer numbers above). — [Hennhöfer & Preisach](https://arxiv.org/abs/2402.16388)
- [Claim] Existing few-shot tabular anomaly methods rely on generative models to increase sample size. — [Zhai et al., 2026](https://link.springer.com/article/10.1007/s40747-026-02265-9)

### Inferences
- **Keep calibration real.** Synthetic windows may enter the fit only; thresholds use untouched, out-of-fold normal recordings. Conformal validity then rests on the calibration and test exchangeability, not on how the model was fitted.
- **Mixing windows has a specific risk here.** Averaged or summed count windows widen a support interval model and could admit attack behaviour, so support may lose its catches (CVE-2017-12635_6, PHP_CWE-434). Recording-level bootstrap resampling changes weights rather than widening the support, so it seems safer. This is untested.
- **Priority is low** compared with fusion and contiguity, since there is no evidence of a benefit at a fixed FPR.

### Gaps
- No measurement of augmentation effects on one-class calibration, in HIDS or in tabular anomaly detection, was found.

## Latency: decision rules that keep p95 <= 3 s, and the trade-off with confirmation

### Takeaway
A recording-level threshold on the running maximum gives a decision with no confirmation wait, which is consistent with the measured 2.44 s (the Pulse decision code was not read here). Confirmation rules cost recall and time. If evidence accumulation is wanted, a CUSUM-type statistic calibrated on normal recordings is the option worth testing, because classical sequential guarantees assume independence that windows do not have.

### Cited Findings
- [Project] Recording-level Bonferroni selection: p95 2.44 s. Earlier window-level rule: p95 4.04 s to 5.29 s, and the two-window rule costs about 25 recall points on development.
- [Theorem] Standard conformal martingale methods can have delay Omega(T) or Omega(sqrt(ARL)). New conformal e-processes and e-detectors have delay Theta(log T) and Theta(log ARL), and shorter delays in simulation. Assumes independent observations with an unknown change. — [Bhattacharyya & Ramdas, arXiv 2609.27179](https://arxiv.org/abs/2609.27179)
- [Claim] Growing the reference set with post-change samples dilutes evidence; a fixed reference reduces delay. Validated on ImageNet-C, not on security data. — [Shaer et al., arXiv 2602.13848](https://arxiv.org/abs/2602.13848)
- [Claim] E-detectors give nonasymptotic bounds on the average run length through sums of e-processes (Shiryaev-Roberts, CUSUM styles). — [Shin, Ramdas, Rinaldo](https://physics.paperswithcode.com/paper/e-detectors-a-nonparametric-framework-for)
- [Claim] Smaller windows flag anomalies sooner in theory. — [Castanhel et al.](https://sol.sbc.org.br/index.php/errc/article/view/15203)

### Inferences
- **Why the recording-level maximum needs no confirmation.** The running maximum at any time is at most the final maximum, so a threshold calibrated on the final maximum of normal recordings keeps the same false-alarm rate at any stopping point. Latency is then simply the first crossing.
- **Length effect.** Longer recordings have higher maxima. With recordings of 10 to 60 s, a test recording longer than calibration recordings would exceed the rate. In live use, recordings do not end, so an hourly false-alarm rate is needed instead, and this recording-level rate does not translate directly. This matters for the Pulse live deployment and should be stated as a limitation.
- **Accumulation.** S_t = max(0, S_(t-1) + log(1/p_t) - c), with the threshold set as the recording-level quantile of max S_t on normal recordings. It has finer resolution than a floor-limited rank because the sum across windows produces more distinct values, and it has no contiguity requirement. Validity rests on exchangeable recordings, not on independent windows. The hyperparameter c needs a fixed value from development. It is untested and the recording-level quantile still needs n, so it does not remove the n >= K/alpha constraint at the recording level.
- **Pure e-value route is unlikely to fit.** With a p-to-e calibrator (kappa = 0.5) and n = 260, a window at the floor gives e about 8.1, while alpha = 1 % needs 100. That is at least 3 such windows, and the independence assumption fails for autocorrelated windows. Confirmation by accumulation therefore costs at least several window steps.
- **Budget left.** 3 s - 2.44 s = 0.56 s at p95. Any added confirmation must fit within this. One extra step fits if the step is below 0.56 s; the current step should be checked in the Pulse configuration, as it was not checked here.

### Gaps
- No HIDS paper found that reports p95 detection latency against a confirmation rule at fixed FPR. Sequential results are theoretical or on non-security data.
- Numeric delay figures from the Bhattacharyya & Ramdas and Shaer simulations were not extracted.
