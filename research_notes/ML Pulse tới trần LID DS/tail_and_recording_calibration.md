# Tail and recording-level calibration for Sentinel Pulse on LID-DS 2021

As of 2026-11-05. Evidence labels: **[Measured]** a result reported from an experiment, **[Proof]** a theorem or exact result stated by the source, **[Method]** a definition or procedure, **[Claim]** the authors' statement or a secondary summary without a checked number, **[Pulse]** a Pulse number supplied by the coordinator or found in this repo, not re-measured here. Everything under "Inferences" is my own derivation, simulation or judgement and has no external source.

How the sources were read: I read the passages cited from Knijnenburg, SPOT, Fischer et al., Roeder and Wasserman and Holscher in the extracted text. The other arXiv and journal pages went through a summarising fetch tool, so I saw extracts, not every line. Sources known only from search snippets are marked "(snippet)". Full texts not obtained are listed under Gaps.

Pulse context used throughout:
- **[Pulse]** Moment Gumbel on about 60 per-recording validation maxima, per scenario and per branch, one-window decision, three learned branches: 81.4 % recall, 0.76 % false-alarm recordings on development. This is development only.
- **[Pulse]** CVE-2019-5418 detects 5/36, although the language model reaches its conformal floor on 30/36. False alarms concentrate in CVE-2014-0160 (9/227) and CVE-2017-7529 (8/219).
- **[Pulse]** The normal test data splits into 3,403 development and 7,938 official recordings ([report](../../reports/Cải%20thiện%20ML%20Pulse%20LID%20DS.md)), which is about 227 and 529 per scenario if spread evenly over 15 scenarios.

## 1. Can extreme value theory give p-values below the empirical floor, and what breaks it?

### Takeaway
Yes: a generalized Pareto (GPD) tail keeps magnitude beyond the calibration maximum, but no source gives a finite-sample guarantee, and the methods assume independent or near-independent data. Use it to rank magnitude, not as proof of a false-alarm rate. At window level, about 4,500 autocorrelated windows per scenario sit at or below the published tail-sample rules of thumb.

### Cited Findings
- **[Method]** Knijnenburg et al. model the tail of the permutation distribution with a GPD, scaled to the interval [1−Nexc/N, 1]. They start from the 250 largest values and, if an Anderson-Darling test rejects (P ≤ 0.05), reduce the count by ten at a time. They use the empirical estimate when at least M = 10 values exceed the statistic — [Knijnenburg et al. 2009](https://pmc.ncbi.nlm.nih.gov/articles/PMC2687965/).
- **[Measured]** Below N = 250 permutations the GPD estimate is worse than the empirical one. For P between 10⁻³ and 10⁻⁵ it needs about 5 to 10 times fewer permutations, and it usually needs fewer than 1/P while the empirical estimate always needs more. Heavy tails converge with fewer samples than light tails — [Knijnenburg et al. 2009](https://pmc.ncbi.nlm.nih.gov/articles/PMC2687965/).
- **[Measured]** A power transform (statistic cubed) moves a light tail towards a heavier one and reduced the permutations needed. The gain stops at larger powers — [Knijnenburg et al. 2009](https://pmc.ncbi.nlm.nih.gov/articles/PMC2687965/). A later paper calls this ad hoc and notes it changes the scale of the statistic — [permApprox 2026](https://arxiv.org/html/2602.22975v1).
- **[Measured]** A negative fitted shape gives a finite upper endpoint, so p-values can be exactly zero. With B = 1000, nearly half of Knijnenburg-style p-values were zero already at n = 50 in a Gaussian t-test simulation. permApprox forces the fitted endpoint above the observed statistic plus a margin, and removes zeros by construction — [permApprox 2026](https://arxiv.org/html/2602.22975v1).
- **[Method]** permApprox defaults: p_GPD = p_exc × F̄_GPD(Y_obs), start from the top 25 % with at least 250 exceedances, and accept a threshold only if Anderson-Darling does not reject at three successive candidates. Otherwise it keeps the empirical p-value — [permApprox 2026](https://arxiv.org/html/2602.22975v1).
- **[Proof] [Claim]** Extreme Conformal Prediction (conformal plus peaks over threshold) extrapolates with Q̂_τ̃ = Q̂_τ₀ + (σ̂/ξ̂)[((1−τ₀)/(1−τ̃))^ξ̂ − 1] and uses the upper confidence limit of that quantile. It splits the level so that 1−α ≤ (1−α₁)(1−α₂). Its guarantee is conditional on the confidence interval being correct, which is asymptotic (k→∞, k/n→0). The authors state it "lacks the finite-sample guarantees of classical conformal prediction" — [Pasche, Lam and Engelke](https://arxiv.org/html/2505.08578v2).
- **[Measured]** In that paper's simulations (n_c from 10³ to 10⁴, α from 10⁻³ to 10⁻⁵, threshold at the 0.95 quantile), the simple GPD quantile undercovered at small n and extreme levels, while the profile-likelihood version met the target on Student-t data. Numerical failure reached 85 % at n_c = 1000 and the smallest α, and 0 % at n_c = 10⁴. Gaussian noise made all GPD methods conservative. Serial dependence is handled by arguing that it is weak, not by proof — [Pasche, Lam and Engelke](https://arxiv.org/html/2505.08578v2).
- **[Method]** SPOT computes z_q ≃ t + (σ̂/γ̂)[(qn/N_t)^(−γ̂) − 1], with t at the empirical 98 % quantile and n about 1000, on iid observations. DSPOT handles drift by modelling the difference from a local mean — [Siffer et al. 2017](https://www.eecs.yorku.ca/course_archive/2018-19/F/6412/reading/kdd17p1067.pdf).
- **[Measured]** SPOT's reliability test used q = 10⁻³ on independent Gaussian white noise, with initial batches of 300 to 5000. Error was low and converged whatever the batch size, so n "is not a paramount parameter" unless too few peaks exist — [Siffer et al. 2017](https://www.eecs.yorku.ca/course_archive/2018-19/F/6412/reading/kdd17p1067.pdf). This test used no autocorrelation and q is 5 times the Pulse floor of 2×10⁻⁴ per window, so it says nothing about the Pulse regime.
- **[Method]** Ferro-Segers intervals estimator with interexceedance times T_i: θ̂ = 2(ΣT_i)² / [(N−1)ΣT_i²] if max T_i ≤ 2, otherwise θ̂* = 2(Σ(T_i−1))² / [(N−1)Σ(T_i−1)(T_i−2)], capped at 1. For automatic declustering, the ⌊θ̂N⌋ largest gaps are taken as inter-cluster times. Clusters are kept whole when bootstrapping — formula as reproduced in [Holscher thesis](https://thesis.eur.nl/pub/50094/Holscher_449506.pdf), from [Ferro and Segers 2003](https://ideas.repec.org/a/bla/jorssb/v65y2003i2p545-556.html). The mean cluster size is about 1/θ̂ — [texmex docs](https://rdrr.io/cran/texmex/man/extremalIndex.html).
- **[Measured]** In a student thesis's simulation, a test on extremal indices had little power at 50 exceedances and appropriate size only at 300 with the intervals estimator — [Holscher thesis](https://thesis.eur.nl/pub/50094/Holscher_449506.pdf). This is weak evidence (master's thesis, a two-sample test rather than estimation).
- **[Claim]** A continuous weighted-KDE conformal p-value trades exact finite-sample validity for asymptotic validity to escape "resolution collapse". The authors report discoveries where discrete baselines find none, but I saw no numbers — [Hennhöfer and Preisach 2026](https://arxiv.org/abs/2603.23205).
- **[Method]** PALM's tail approximation fits a GPD only to p-values under 0.10, shows `-n 500` as its example, and lists corrected (FWER, FDR) as well as uncorrected p-values — [PALM docs](https://web.mit.edu/fsl_v5.0.10/fsl/doc/wiki/PALM(2f)FasterInference.html). The docs do not say whether the GPD is fitted to the maximum statistic.

### Inferences
- Window-level tail sample, per scenario and branch: 4,500 × 2 % = 90 exceedances at SPOT's threshold, and 225 at the 95 % threshold. Both are below Knijnenburg's start of 250, and these windows are not independent. After declustering at θ = 0.5, the 225 become about 112 clusters.
- A window p-value only maps to a recording if clustering is known: P(recording alarm) ≈ 1 − exp(−θ·m·p). With θ estimated from about 100 clusters per scenario, this adds a second unstable estimate. Recording-level fitting (question 2) avoids θ altogether, because within-recording dependence disappears when each recording gives one number.
- Window-level GPD is still useful as a score transform: −log p_GPD keeps magnitude for the sequential statistic in question 3, and the threshold on that statistic can be set at recording level. Under this design, errors in the GPD change power, not the false-alarm rate.
- If a branch's tail has a fitted upper endpoint (negative shape), an attack above that endpoint gets p = 0. This is safe for detection but needs a numeric cap, as in permApprox.

### Gaps
- I found no paper that builds valid conformal p-values below 1/(n+1) with a finite-sample guarantee. The only finite-sample statement I found points the other way: Pasche et al. argue this is impossible without extra distributional assumptions.
- I found no published study of GPD tail p-values on syscall scores or LID-DS.
- I read the Ferro and Segers formula through a thesis, not the 2003 paper.

## 2. How should false alarms be calibrated at recording level, with only about 60 recordings?

### Takeaway
Treating each recording's maximum as one exchangeable sample gives an exact guarantee that autocorrelation inside a recording cannot break, and it stays causal online. With 60 recordings the empirical floor is 1/61 = 1.64 %, so ≤ 0.8 % needs either a tail fit or at least 124 recordings (287 for 90 % confidence).

### Cited Findings
- **[Proof]** Conformal p-value: u(x) = (1 + #{i: s(X_i) ≤ s(x)})/(n+1), with lower score as more anomalous in that paper's notation. Conditional on the calibration set, the false-positive rate at level α is Beta(ℓ, n+1−ℓ) with ℓ = ⌊(n+1)α⌋, and its relative spread scales as (nα)^(−1/2) — [Bates et al. 2023](https://ar5iv.labs.arxiv.org/html/2104.08279).
- **[Proof]** Calibration-conditional p-values have a floor about 2 log(1/δ)/n (Simes), about 0.0046 at n = 1000, δ = 0.1 — [Bates et al. 2023](https://ar5iv.labs.arxiv.org/html/2104.08279).
- **[Proof]** Hierarchical exchangeability requires groups to be exchangeable, and observations exchangeable within groups. Its split procedure gives each point weight 1/((K₁+1)N_k) and puts 1/(K₁+1) at +∞, with coverage ≥ 1−α, and the upper bound involves 2/(K₁+1) — [Lee et al.](https://arxiv.org/html/2306.06342v4). This guarantee is per test point, not per group, so it does not bound the chance that any window in a recording fires.
- **[Measured]** With α = 0.2, pooled CDFs undercover at small K, double conformal is over-conservative, and hierarchical conformal performs well on coverage and stability (K = 20 to 100) — [Lee et al.](https://arxiv.org/html/2306.06342v4). The paper's HCP2 uses within-group pairwise minimum scores for a second-moment guarantee, the nearest idea to a within-group extreme.
- **[Claim]** Dunn, Wasserman and Ramdas favour CDF pooling for asymptotic coverage and repeated subsampling for finite-sample coverage — [JASA 2023 record](https://arxiv.org/abs/1809.07441v4) (snippet).
- **[Method]** Conformal time-series forecasting calibrates across multiple exchangeable series rather than within one, with a Bonferroni correction across horizons — [Stankeviciute et al. 2021](https://proceedings.neurips.cc/paper/2021/hash/312f1ba2a72318edaaa995a67835fad5-Abstract.html) (snippet; the Bonferroni detail is from a [secondary source](https://arxiv.org/html/2601.18509v1)). This is the closest conformal precedent I found for sequence-level exchangeability.
- **[Method]** Laxhammar and Falkman's inductive conformal anomaly detection scores sequences through sliding sub-trajectories — [Annals of Mathematics and AI 2015](https://dblp.uni-trier.de/pid/118/9880.html), [thesis record](https://www.avhandlingar.se/avhandling/a5565e371d/) (snippets; full text not read). This is the nearest published anomaly-detection work.
- **[Method]** The maxT approach samples the distribution of the maximum statistic to set a critical value, so it needs no independence between tests; it controls the family-wise error under exchangeability — [Efficient FWER control in GLMs](https://arxiv.org/pdf/1603.05938), [multtest docs](https://rdrr.io/bioc/multtest/man/mt.maxT.html) (snippets).
- **[Proof] [Measured]** Leave-one-out and cross-conformal anomaly detection use out-of-fold scores, so no recordings are lost to a split, and p-values remain marginally super-uniform. On Isolation Forest with WBC data, power rose from 0.174 (split) to 0.586–0.645 at α = 0.2. Marginal FDR exceeded nominal (about 0.24) at n_calib = 500 in one experiment, and on Musk split beat CV+ (0.406 vs 0.062) — [Hennhöfer and Preisach](https://arxiv.org/html/2402.16388v3).
- **[Pulse]** The LID-DS evaluation library sets its threshold at the maximum anomaly score on validation data, normal only — [repo notes](../Cải%20thiện%20Pulse%20trên%20LID%20DS/published_results.md). So max-of-validation is the published convention, and its known weakness is the Beta(1, K) spread below.

### Inferences
- **Exact results (own derivation; exchangeable maxima).** If threshold T is the largest of K recording maxima, then the true false-alarm rate is Beta(1, K), with mean 1/(K+1). So P(true FA > x) = (1−x)^K:

| K recordings | floor 1/(K+1) | P(FA > 0.8 %) | P(FA > 2 %) | P(FA > 4 %) |
|---|---|---|---|---|
| 60 | 1.64 % | 61.8 % | 29.8 % | 8.6 % |
| 124 | 0.80 % | 36.9 % | 8.2 % | 0.6 % |
| 200 | 0.50 % | 20.1 % | 1.8 % | 0.0 % |
| 287 | 0.35 % | 10.0 % | 0.3 % | 0.0 % |

- Reaching a mean FA ≤ 0.8 % without a fit needs K ≥ 124. Reaching it with 90 % confidence needs K ≥ ln 0.1/ln 0.992 = 287. That is about validation (60) plus development normals (227) per scenario. This is a one-statistic bound; three branches need one joint statistic per recording (question 8).
- **Why floor hits reach 8.8 %.** For exchangeable windows, P(some of m test windows above the maximum of n calibration windows) = m/(n+m) exactly. With m = 60, n = 4,500 this is 1.32 % per branch and at most about 5.3 % over four branches. The measured 8.8 % is higher, which points to calibration variance or a shift between validation and test, not only scanning. The branch count behind 8.8 % is not stated, so this is indicative. Getting m/(n+m) to 0.2 % would take about 30,000 calibration windows, if they were independent.
- **Raising K (most useful lever).** Three normal-only sources: development normals (with a split kept aside for checking), cross-fitted training recordings (retraining cost), and pooling across scenarios (question 7). Using development normals keeps "no attack data" intact and leaves the official set untouched. On the live cluster, the equivalent is a longer normal bake-in, which also protects against shift.
- **Length normalisation (own derivation from max-stability).** If one window's tail is GEV(μ, σ, ξ), the maximum over m windows has σ_m = σ·m^ξ and μ_m = μ + σ(m^ξ−1)/ξ, which for Gumbel is μ_m = μ + σ ln m. Recordings of 10–60 s have m of 20–120, so the Gumbel location varies by σ·ln 6 ≈ 1.8σ. Practical form: fit recording maxima with location as a function of ln m, or fit T for a fixed reference horizon and apply it to the running maximum. Online, the elapsed window count is known, so T(m_elapsed) can rise with time, which is a form of alpha spending. Autocorrelation makes the effective m smaller, so estimate the slope on ln m rather than fixing it.
- A running maximum exceeds T exactly when the final maximum would, so the recording-level threshold does not add delay beyond the first window above T. Short recordings get less scan exposure than long ones, so report FA by length.
- A hybrid p-value following Knijnenburg's M ≥ 10 rule would use the empirical rank when at least 10 of K exceed the score, and the fit otherwise. With K = 60, every useful decision comes from the fit, so the empirical part is only a sanity check.

### Gaps
- I found no paper that calibrates anomaly false alarms at recording level with the per-sequence maximum and reports results on system-call data. The search phrase "recording-level exchangeable" found nothing.
- I did not read Laxhammar's full text, so its sequence-level error statement is unconfirmed.
- Exchangeability between LID-DS validation and test normal recordings has not been tested. The false-alarm concentration suggests checking it (question 5).

## 3. Which sequential rules keep one-window events and still accumulate weak evidence?

### Takeaway
A combined Shewhart-CUSUM in log-evidence units fits best: a very extreme window can cross alone, while weaker windows add up. The theoretical 1/b bound does not hold for Pulse's dependent windows, so set the threshold on the per-recording maximum of the statistic, not from Ville's inequality. Whether this beats one-window on LID-DS is unmeasured.

### Cited Findings
- **[Method]** Combined Shewhart-CUSUM schemes supplement a CUSUM with a Shewhart limit, and average run lengths for such schemes have been tabulated — [SAS docs citing Lucas and Crosier](https://support.sas.com/documentation/cdl/en/qcug/68161/HTML/default/qcug_cusum_sect059.htm), [Lucas and Saccucci 1990](https://www.stat.cmu.edu/technometrics/90-00/vol-32-01/v3201001.pdf) (snippets). I did not read Lucas 1982. An example scheme in the SAS docs has ARL 111.1 at δ = 0 and 6.322 at δ = 1, and its origin is unclear.
- **[Proof]** Ville's inequality: for a nonnegative (super)martingale started at 1, P(∃n: S_n ≥ c) ≤ 1/c. Conformal test martingales alarm at S_n ≥ 1/α — [Bhattacharyya and Ramdas 2026](https://arxiv.org/html/2609.27179v1), [nonconform](https://arxiv.org/pdf/2605.13642) (snippet).
- **[Proof]** With restart weights w_k and statistic S_t = Σ_k w_k M_{k,t}: P(τ < ∞) ≤ ‖w‖₁/b, and E τ ≥ b/‖w‖_∞ — [Bhattacharyya and Ramdas 2026](https://arxiv.org/html/2609.27179v1). Their mixture martingale CUSUM and Shiryaev-Roberts forms are max_i M_n/M_i ≥ γ and Σ_i M_n/M_i ≥ γ.
- **[Proof]** Standard conformal martingale baselines can have delay Ω(T) under false-alarm-probability control, and Ω(√γ) under ARL control. The proposed restart-based detectors have O_P(log T/D_KL(H‖U)) and O_P(log γ/D_KL(H‖U)) — [same paper](https://arxiv.org/html/2609.27179v1). It assumes independent observations and a change that persists, which does not cover a one-window exploit. It does not address single extreme p-values.
- **[Method]** Betting functions: f(p) = κp^(κ−1) with κ = 0.15 appears as 0.15·p^(−0.85) in [Bhattacharyya and Ramdas](https://arxiv.org/html/2609.27179v1), and the mixture ∫₀¹ εp^(ε−1)dε in [Volkhonskiy et al. 2017](https://arxiv.org/html/1706.03415).
- **[Claim] [Measured]** Volkhonskiy's cut-off C_n = max{0, C_{n−1} + log g_n(p_n)} loses theoretical validity, and the paper checks it by simulation. A kernel betting function fitted on an example with a change performed best (m = 200 training points) — [Volkhonskiy et al. 2017](https://arxiv.org/html/1706.03415). That precomputed betting function would need attack-like data, which the Pulse constraint forbids.
- **[Proof] [Measured]** Conformal p-values sharing one calibration set are positively dependent, with correlation 1/(n+2). Fisher's combination at α = 5 % with m = 3n test points has a real type-I error of 20.5 %, and 50 % as m/n grows — [Bates et al. 2023](https://ar5iv.labs.arxiv.org/html/2104.08279). So a product of such p-values is not a true martingale.
- **[Proof] [Claim]** Scan statistics: the maximum over windows of length w grows with the log of n/w, so plain variable-window scans favour short signals. Size-dependent critical values remove most of the cost of not knowing the window size, and one option is a weighted Bonferroni across scales — [Walther 2021](https://arxiv.org/pdf/2107.08296) (snippets).
- **[Claim] [Measured]** Higher Criticism has the same detection boundary as the likelihood ratio test in sparse mixtures — [Donoho and Jin 2004](https://projecteuclid.org/euclid.aos/1085408492). Berk-Jones has better power than Higher Criticism across a broad range of sample sizes — [Li and Siegmund 2015](https://arxiv.org/pdf/1411.1437), and exact p-values are available in O(n²) — [Moscovich et al.](https://arxiv.org/pdf/1311.3190) (snippets). These results assume iid p-values.
- **[Claim]** The Cauchy combination is a weighted sum of tan((0.5−p_i)π), with a null tail approximately Cauchy regardless of dependence, and most accurate for very small p — [Liu and Xie 2020](https://ar5iv.arxiv.org/html/1808.09011). Heavy-tailed combinations emphasise very small p-values and down-weight marginal ones — [Fang and Tseng](https://arxiv.org/pdf/2103.12967v1) (snippets). I did not verify the theorem's conditions.

### Inferences
- **Proposed statistic.** S_t = max(0, S_{t−1} + log f(p_t)), with f(p) = κp^(κ−1), and p_t from a GPD tail so that it has no floor. One window adds log κ + (1−κ)(−log p_t), so magnitude directly controls how much confirmation is needed. This is the score-dependent confirmation requested: a single window passes if p is small enough, weak windows must persist, and values above p = κ^(1/(1−κ)) drain S. Choose κ a priori (for example 0.15), not on attacks.
- **What a single window can reach (arithmetic).**

| κ | e at p = 1/4501 | e at 10⁻⁶ | e at 10⁻⁸ | p needed for e ≥ 125 (0.8 % by Ville) |
|---|---|---|---|---|
| 0.05 | 148 | 25,059 | 1,990,536 | 2.7×10⁻⁴ |
| 0.15 | 191 | 18,884 | 946,436 | 3.7×10⁻⁴ |
| 0.30 | 108 | 4,755 | 119,432 | 1.8×10⁻⁴ |
| 0.50 | 34 | 500 | 5,000 | 1.6×10⁻⁵ |

- So with κ = 0.15, one floor-level window would already cross 1/0.008 = 125. This shows why Ville's bound cannot be used directly: the floor is reached in 8.8 % of normal recordings, which is 11 times the 0.8 % bound. The assumptions fail because windows are autocorrelated, p-values share a calibration set, branches multiply exposure, and test data may be shifted.
- **Threshold.** Replay normal recordings, take R_i = max_t S_t for each, and fit or rank R_i at recording level, as in question 2. Autocorrelation is then absorbed by construction, as long as recordings are exchangeable. This turns any sequential rule into a candidate with the same calibration.
- **Compared with k-of-n.** Two-window rules lost 25 recall points because many exploits are one-window events and the rule ignores magnitude. Compared with one-window, S_t can only improve recall at fixed FA if attacks produce nearby elevated windows more often than normals do, which has to be measured. One-window maximum is the limiting case (S with no carry-over) and should be the baseline.
- **Higher Criticism and Berk-Jones are poor fits.** With m ≈ 60 autocorrelated windows and one-window exploits, these reduce to something close to the minimum p, and their null calibration relies on independence. A multi-scale scan (windows of 1, 2, 4, 8) with recording-level calibration is a simpler way to get the same sensitivity.
- A branch-level Cauchy combination is a candidate for merging branches because of its dependence claim, but it depends on very small p being available, so it needs tail p-values first.

### Gaps
- I found no empirical comparison of e-processes and k-of-n on syscall windows or any comparable short-burst security data.
- I could not read Lucas 1982 for run-length tables on large single shifts, and the [autocorrelated combined-scheme paper](https://ph02.tci-thaijo.org/index.php/thaistat/article/view/256085) was seen only as a search result.
- I found nothing on the behaviour of Higher Criticism or Berk-Jones under serial dependence in this search.

## 4. How does autocorrelation affect calibration, and how should uncertainty be resampled?

### Takeaway
Marginal coverage at moderate levels is surprisingly robust, but the published evidence stops at about α = 0.1 and does not cover the extreme tail or the union over a recording. Resample whole recordings for uncertainty.

### Cited Findings
- **[Proof]** For stationary β-mixing data, split conformal coverage is ≥ 1 − α − η, with η = ε_cal + ε_train + δ_cal, and ε_cal carries σ̃(a)·√(4/(n_cal−r+1)·log(...)) + (1/3m)·log(...) + (r−1)/n_cal, where σ̃(a) = √(1/4 + (2/a)Σ_{j<a}(a−j)β(j)) — [Oliveira et al. 2024](https://arxiv.org/html/2203.15885v2).
- **[Measured]** At nominal 90 %, AR(1) coverage stays above 89 % up to coefficient 0.99, with significant losses only at 0.999 — [Oliveira et al. 2024](https://arxiv.org/html/2203.15885v2).
- **[Proof]** Under non-exchangeable scores, P(alarm) ≤ α + Σ_i [w_i/(‖w‖₁+1)]·d_TV(s, s^i), from Barber et al. as used in — [arXiv 2604.20122](https://arxiv.org/html/2604.20122v1). See also [Barber et al. 2023](https://arxiv.org/abs/2202.13415). I saw the bound through the citing paper, not the original.
- **[Claim]** That time-series paper gives a per-observation guarantee only, with no whole-series false-alarm bound, and its p-value floor is 1/(|w|+1), with α_c = 0.01 — [arXiv 2604.20122](https://arxiv.org/html/2604.20122v1). Its reported FPR of 0.077–0.084 is at oracle-selected thresholds, not a fixed target.
- **[Pulse]** Calibration variance already appeared on Heartbleed, with 15.57 % false alarms under the earlier ML, against 0.79–3.82 % in other scenarios — [repo report](../../reports/Cải%20thiện%20ML%20Pulse%20LID%20DS.md). That is the same scenario as today's CVE-2014-0160 false-alarm group, so the cause may be scenario-specific rather than a fit problem.
- **[Method]** Effective sample size is N/(1 + 2Σρ_k), with truncation needed, and it is unstable for small samples — [TensorFlow Probability](https://www.tensorflow.org/probability/api_docs/python/tfp/mcmc/effective_sample_size) (snippet).
- **[Claim]** Blocks should cover the autocorrelation time, and fewer effective samples increase bootstrap bias — [Lattice QCD bootstrap paper](https://arxiv.org/pdf/2409.11379) (snippet). A student study found moving-block intervals still failed for lag-1 autocorrelation at n = 1024 — [AJUR 2024](https://ajuronline.org/uploads/Volume_20_4/AJUR_Vol_20_Issue_4_March_2024_p3.pdf) (snippet, weak source).
- **[Method]** Ferro and Segers resample inter-cluster gaps and keep clusters whole — [Holscher thesis](https://thesis.eur.nl/pub/50094/Holscher_449506.pdf).

### Inferences
- Oliveira's reassuring result is for α = 0.1. It should not be carried over to α ≈ 2×10⁻⁴, where a window's p-value depends on the few largest calibration points, and those come from only a few recordings.
- For AR(1) with ρ = 0.8, N_eff = N(1−ρ)/(1+ρ) = N/9, so 4,500 windows behave like about 500 for mean-type quantities. Tail quantities depend on θ rather than ρ, so measure them separately: run the Ferro-Segers estimator per branch at a high threshold, and count how many distinct recordings hold the top 50 windows. That count is an honest effective tail sample, cheap to compute from the stored scores.
- A recording is a natural block. Recording-level bootstrap (and scenario-level bootstrap for pooled claims) avoids choosing a block length, and it matches what we want to predict. With K = 60 it cannot produce anything beyond the sample's largest recording, so use it for the spread of a fitted threshold, not for extreme levels on its own.
- The two-window rule's real false-alarm cut was measured, and it should stay measured. It cannot be derived from window FPR without knowing the dependence.

### Gaps
- I found no source on block-bootstrap failure at extreme quantiles specifically, nor Politis's stationary-bootstrap results in this search.
- I have not measured θ or the effective tail sample on Pulse scores; the repo's raw branch scores make this possible.

## 5. What can a small validation set verify about ≤ 0.8 % false-alarm recordings?

### Takeaway
No single scenario in development can verify 0.8 %, and official can do so only with zero false alarms. A pooled claim is verifiable only if the observed rate is well below 0.8 %. The current 0.76 % on development is not yet verified at 95 %.

### Cited Findings
- **[Method]** For zero failures in n trials, the 95 % upper bound is about 3/n — [Hanley and Lippman-Hand, cited by NIST](https://www.nist.gov/document/iyer-presentationpdf) (snippet; the citation is confirmed, the formula itself I computed below).
- **[Claim]** The false alarm rate is the limiting factor for an intrusion detector, because low base rates make P(intrusion | alarm) small — [Axelsson 2000](https://www.profsandhu.com/cs6393_s20/p186-axelsson.pdf), revisited in [Erbacher 2022](https://arxiv.org/pdf/2203.08801) (snippets).
- **[Pulse]** 3,403 normal development and 7,938 normal official recordings; 1,271 attack recordings in the official evaluation — [repo report](../../reports/Cải%20thiện%20ML%20Pulse%20LID%20DS.md).

### Inferences
All below computed with exact one-sided 95 % Clopper-Pearson bounds, assuming independent recordings.

| False alarms seen | Recordings needed for upper bound ≤ 0.8 % |
|---|---|
| 0 | 373 |
| 1 | 592 |
| 2 | 785 |
| 3 | 967 |
| 5 | 1,312 |
| 10 | 2,117 |

- **Per scenario.** Zero false alarms gives an upper bound of 1.31 % on about 227 development normals, and 0.56 % on about 529 official normals. So on official, a scenario verifies 0.8 % only with zero false alarms, and on development never.
- **Pooled.** The bound ≤ 0.8 % allows at most 18 false alarms in 3,403 (0.53 %), or at most 50 in 7,938 (0.63 %). Today's 0.76 % is about 26/3,403 if that is the denominator, with a one-sided upper bound of 1.06 %, so it is **not verified**.
- **Verifying requires a lower target.** To verify ≤ 0.8 % on official, the procedure should aim for about 0.5–0.6 % pooled. This matters when setting the budget (question 8).
- **Clustered false alarms make these bounds too narrow.** About 17 of 26 are in two scenarios. CVE-2014-0160 (9/227) has a 95 % interval of 1.8–7.4 %, and CVE-2017-7529 (8/219) has 1.6–7.1 %. If 0.76 % held everywhere, P(≥ 9) would be 7×10⁻⁵ and P(≥ 8) 3×10⁻⁴ per scenario, and the chance that some scenario of 15 reaches ≥ 8 is about 0.6 %. So rates differ by scenario. Report scenario-level bootstrap for pooled claims, plus the worst scenario.
- **Threshold variance alone could explain these scenarios.** Moment Gumbel's p90 true FA is about 1.9 % per branch at ξ = 0.2 in my simulation (question 6), which over three branches is up to about 5.6 %. A shift is the other explanation. Normal-only test: compare validation with development maxima for those two scenarios (rank test, or count how many development maxima exceed the validation maximum, expected K_dev/(K_val+1) ≈ 3.7 of 227 under exchangeability).
- **Precision at recall 95 %, FA 0.8 %.** It is 95.0 % at the official base rate (13.8 % attacks, 1,271/(1,271+7,938)), 54.5 % at 1 %, and 10.6 % at 0.1 %. The official precision is not a deployment precision, so it should be reported with the base rate.
- **Selection.** Thresholds and budgets chosen on development make development FA optimistic, so a final claim needs official normals, once. If development normals enter calibration, split them and keep one part for checking, or use cross-validation at recording level.

### Gaps
- I could not confirm the rule of three inside the Hanley paper itself; I computed the bounds directly.
- I do not have the exact development denominator behind 0.76 %; 26/3,403 is my reconstruction.

## 6. Moment Gumbel versus GEV or GPD by ML or L-moments with about 60 maxima

### Takeaway
At about 60 maxima a free-shape GEV is too noisy, and a fixed Gumbel is biased when the tail is heavy. Moment fitting is also destroyed by a single outlier, which matches CVE-2019-5418. Fit GEV with a pooled or shrunken shape; the shape cannot be estimated from 60 maxima alone (sd about 0.11 in my simulation).

### Cited Findings
- **[Measured]** In a study comparing estimators up to n = 200: on Gumbel data, Gumbel ML has the lowest RMSE, and adding a third parameter roughly doubles RMSE. At ξ = 0.1, a Gumbel fit has a substantial negative quantile bias, yet its RMSE is still much smaller than GEV's at small n. At ξ = 0.2, Gumbel bias and RMSE nearly double (2.5 times at the 99.9 % quantile). L-moment GEV has a large positive bias at small n. "In case of at most 50 observations, fitting a Gumbel distribution with TL(1,1)-Moments seems best, closely followed by ML, MD and TL(0,1)." From at least 100 observations, "GEV fitting becomes worthwhile" — [Fischer, Fried and Schumann 2015](https://hess.copernicus.org/preprints/12/8553/2015/hessd-12-8553-2015.pdf) (discussion paper).
- **[Measured]** PWM estimators have low variance and no severe bias, and at n < 100 have much smaller standard deviation than MLE for quantiles. All methods are "very inaccurate for estimating large quantiles in small samples, especially when κ < 0" (heavy tail, in Hosking's sign). PWM efficiency is poor outside κ in [−0.2, 0.2] — [Hosking, Wallis and Wood 1985, summary in EnvStats](https://rdrr.io/cran/EnvStats/man/HoskingEtAl1985.html).
- **[Measured]** Small-sample MLE can produce absurd shape values. A Bayesian prior restricting the shape (generalized ML) did substantially better than moments and L-moments for −0.4 ≤ κ ≤ 0. Earlier work found moment quantile estimators had smaller RMSE than L-moments and MLE for −0.25 < κ < 0.30 — [Martins and Stedinger 2000](https://earthref.org/ERR/70267) (abstract snippet).
- **[Measured]** A Monte Carlo study (n = 10 to 1000) found Gumbel MLE lowest RMSE, PWM least biased, and PWM best for GEV on both RMSE and bias — [Comparison of parameter estimation methods](https://cir.nii.ac.jp/crid/1050282677086895744?lang=en) (snippet).
- **[Claim] [Measured]** Gumbel can significantly underestimate the largest rainfall extremes — [Koutsoyiannis, snippet via HEAL](https://dspace.lib.ntua.gr/xmlui/handle/123456789/36720?show=full). Across about 3,800 Brazilian gauges, Gumbel quantiles tended to be lower than GEV fits, with most gauges heavy tailed — [ABRHidro](https://anais.abrhidro.org.br/job.php?Job=16417) (snippet). Note that these are rainfall series, not software scores, and the snippet-to-URL match for these two is my best reading of the search results.

### Inferences
**Own simulation** (not Pulse data; true GEV, K = 60, target per-branch FA 0.25 %, which assumes 0.76 %/3; 2,000 repetitions; true FA of each fitted threshold computed exactly; lower is more conservative). Outlier cases replace the smallest value with the true quantile at tail probability 10⁻⁵ (ξ = 0) or 10⁻⁶ (ξ = 0.2).

| True tail | Measure | moment Gumbel | ML Gumbel | Gumbel, quantiles (IQR) | Gumbel, top 2 censored | GEV L-moments | GEV ML | GEV, shape pooled over 15 scenarios sharing the true ξ |
|---|---|---|---|---|---|---|---|---|
| ξ = 0 | mean FA % | 0.35 | 0.33 | 0.41 | 0.33 | 0.59 | 0.66 | 0.38 |
| ξ = 0 | p90 FA % | 0.72 | 0.62 | 0.89 | 0.63 | 1.54 | 1.76 | 0.75 |
| ξ = 0.1 | mean FA % | 0.68 | 0.88 | 1.02 | 0.92 | 0.56 | 0.58 | 0.35 |
| ξ = 0.2 | mean FA % | 1.02 | 1.56 | 1.83 | 1.68 | 0.54 | 0.51 | 0.35 |
| ξ = 0.2 | p90 FA % | 1.87 | 2.38 | 3.03 | 2.52 | 1.28 | 1.25 | 0.60 |
| ξ = 0.3 | mean FA % | 1.29 | 2.22 | 2.70 | 2.47 | 0.58 | 0.49 | 0.37 |
| ξ = 0.5 | mean FA % | 1.67 | 3.27 | 4.61 | 3.93 | 0.61 | 0.42 | 0.43 |
| ξ = 0 + one outlier | mean FA % | **0.018** | 0.19 | 0.38 | 0.31 | **0.003** | **0.006** | 0.13 |
| ξ = 0.2 + one outlier | mean FA % | **0.001** | 0.21 | 1.65 | 1.45 | **0.000** | **0.008** | 0.16 |

- The maximum of the sample as threshold gave mean FA 1.6 % across clean cases, matching 1/61, which checks the simulation. The ML shape had sd 0.107–0.136, so 60 maxima cannot tell ξ = 0 from ξ = 0.2 with confidence. GEV ML exceeded 1 % true FA in 14–20 % of fits at ξ = 0 to 0.2.
- **Reading.** No method with shape fixed at 0 is safe under real heavy tails. Moment Gumbel's sensitivity to large values partly offsets this, which may be part of why it gave a usable 0.76 %, but it also explains the loss when a single value is large. Free-shape GEV is unbiased on average only because a few fits are very permissive.
- **CVE-2019-5418 mechanism (arithmetic).** Moment Gumbel's threshold is mean + c·sd, with c = (−ln(−ln(1−α)) − 0.5772)·√6/π. c = 3.35 at α = 0.76 %, and 4.22 at α = 0.25 %. One value z sd above the mean raises the threshold (in original sd units, K = 60) to z/K + c·√(1+z²/K): z = 5 gives 5.11, z = 10 gives 7.06, z = 20 gives 12.02, at α = 0.25 %. So one outlier can lift the threshold by nearly 3 sd or more. This matches the reported pattern, but I have not inspected this scenario's maxima, so it is a hypothesis.
- **Attacks in the gap.** 30/36 reach the window floor, 5/36 pass the fitted threshold. So 25 attacks lie between the validation maxima and T. Before tuning, count on development normals how many fall in that same band. If normals are also there, a better fit cannot separate them and the branch's score is the limit. This is the cheapest decisive check for this scenario.
- **Conflict across sources.** Fischer finds Gumbel underestimates at positive ξ, while Pulse sees a threshold too high. These fit together: bias is low on average, and a large value still inflates sd in moment fitting. A diagnostic: the ratio of moment scale to top-censored scale flags the inflation.
- Log transform: if maxima are Fréchet, the log is exactly Gumbel, so a Gumbel fit to log maxima is a two-parameter heavy-tail model, and it compresses outliers. It needs positive scores with a meaningful zero. Not simulated; worth one cheap trial, since it needs no pooling.

### Gaps
- Fischer et al. is a discussion paper, and I did not locate the final version. Sample sizes there are small hydrology records at ξ up to 0.2, not ξ = 0.5.
- I did not read Hosking 1985 or Martins and Stedinger 2000 directly, and the exact Beta prior of the latter is not confirmed. My simulation's prior is my own choice.
- Whether Pulse's maxima have ξ near 0.2 or an outlier is unmeasured here. The simulation assumes exact GEV, so it ignores mixtures and shifts.

## 7. Robust or shrunken tail fits pooled across scenarios, and stopping one outlier from inflating a threshold

### Takeaway
Pool the shape parameter only and keep location and scale per scenario, as regional extreme-value work does; add censoring of the top one to three maxima. In my simulation this was the only option close to target with and without an outlier. Robust fits alone are unsafe, because an "outlier" may be a true normal tail.

### Cited Findings
- **[Method]** Regional analysis screens with a discordancy measure and a heterogeneity measure H, comparing observed between-site spread of L-moment ratios with a simulated homogeneous region. H < 1 is acceptably homogeneous, 1–2 possibly heterogeneous, ≥ 2 definitely heterogeneous — [lmomRFA docs](https://rdrr.io/cran/lmomRFA/man/regtst.html), [nsRFA docs](https://search.r-project.org/CRAN/refmans/nsRFA/html/HOMTESTS.html) (snippets).
- **[Claim]** Regional analysis gives more accurate flood quantiles than at-site in moderately heterogeneous regions (Lettenmaier 1987, secondhand) — [Sri Lankan document](https://dl-iesl.nsf.gov.lk/bitstreams/f611df7d-1243-478b-a613-156a2a92e1d2/download) (snippet). Uncertainty rises and reliability falls at rarer return periods — [Nepal study](https://nepjol.info/index.php/east/article/download/98614/74673/284707) (snippet).
- **[Claim]** A regional Bayesian POT model beat the index-flood model and local estimators on French stations, and relatively large, reasonably homogeneous regions may be more accurate than small, very homogeneous ones — [Ribatet et al.](https://arxiv.org/abs/0802.0433).
- **[Measured]** With 12 tide gauges and 87–124 year records, drawing site shapes from a shared Gaussian lowered the 50-year return level's predictive sd compared with separate fits at all sites, and the spatial GP model reached below 50 % of separate. Separate fits were more sensitive to one anomalous January 1984 value, and removing it changed the hierarchical models only slightly — [Räty et al. 2023](https://nhess.copernicus.org/articles/23/2403/2023/). The paper gives no direct pooling-bias comparison.
- **[Claim]** A referee of another hierarchical study warned that with short records the shape can be driven by the prior — [HESS review comment](https://hess.copernicus.org/preprints/hess-2018-22/hess-2018-22-RC2.pdf) (snippet).
- **[Measured]** Trimmed moments in hydrology: with extraordinary events in the sample, robust Minimum Distance and TL-moments have lower bias and RMSE at the higher quantile, at a cost when no such events occur. TL(1,1) is preferred overall and tends not to overestimate, even when the event's return period is much longer than the record. Without obvious events, L-moments are recommended. When the top 20 % of values were corrupted, all estimators failed. The authors suggest the sensitivity curve to identify an influential event — [Fischer, Fried and Schumann 2015](https://hess.copernicus.org/preprints/12/8553/2015/hessd-12-8553-2015.pdf).
- **[Claim]** Fischer also found robust GEV fits with a free shape worse than the same estimators with a Gumbel fit — same source.
- **[Method]** Optimal B-robust GEV estimation gives each data point a weight in [0, 1], and points near 0 are poorly fitted, which also gives a model check — [Dupuis and Field 1998](https://zendy.io/title/10.2307/3315505) (snippet). Trimmed L-moments with separate trimming per moment — [Poudyal et al. 2025](https://arxiv.org/pdf/2505.09860) (snippet).

### Inferences
**Own simulation 2** (not Pulse data; 15 scenarios with K = 60 each, target 0.25 %, 300 repetitions, so these numbers are rougher). Pooled shape = median of the 15 per-scenario L-moment shapes, which one outlier cannot shift. It is used as a Gaussian prior on the target scenario's shape with sd 0.10, and combined with type II censoring of the top r maxima. Outlier q = 10⁻⁵ is placed in the target scenario only.

| Scenario shapes | Case | moment Gumbel | Gumbel top-2 censored | GEV ML | Pooled prior | Pooled + censor 2 |
|---|---|---|---|---|---|---|
| all ξ = 0 | clean, mean FA % | 0.35 | 0.33 | 0.66 | 0.46 | 0.45 |
| all ξ = 0 | outlier, mean FA % | 0.017 | 0.30 | 0.005 | 0.030 | 0.21 |
| ξ ~ N(0.15, 0.10) | clean, mean FA % | 0.85 | 1.34 | 0.54 | 0.43 | 0.43 |
| ξ ~ N(0.15, 0.10) | outlier, mean FA % | 0.012 | 1.14 | 0.013 | 0.078 | 0.25 |
| ξ ~ N(0.3, 0.15) | clean, mean FA % | 1.18 | 2.34 | 0.41 | 0.42 | 0.42 |
| ξ ~ N(0.3, 0.15) | outlier, mean FA % | 0.008 | 2.05 | 0.023 | 0.135 | 0.31 |

- Pooled-plus-censored is the only column within a factor of two of the target in all six rows. Its mean FA is about 0.2–0.45 % against 0.25 %, and it exceeds 1 % true FA in about 2–12 % of fits (P(FA > 1 %) was 0.067–0.087 clean with heterogeneous shapes, and 0.120 clean at ξ = 0). The clean cases cost little, so censoring two maxima is cheap insurance in this simulated setting.
- Pooling reduces variance less when shapes really differ: with all scenarios sharing the true ξ and a tight prior (sd 0.03, first simulation), p90 was 0.60–0.75 %, while the wider prior of sd 0.10 here gave about 0.9–1.1 %.
- **Procedure for one branch.** (1) Fit each scenario's maxima, after any length adjustment. (2) ξ̄ = median of per-scenario shapes, τ² = max(0, var(ξ̂_s) − mean(SE²)), with SE about 0.11 at K = 60. (3) Refit each scenario with prior N(ξ̄, τ²) on the shape and the top r = 2 censored. Fit shape per branch, since branches have different score scales and tails. This uses 15 × 60 = 900 recordings for shape, and it needs no attack data.
- **Do not pool location or scale.** The score scales differ by application, and Pulse's false alarms differ by scenario.
- **Outlier or real tail?** A value that looks like an outlier is labelled normal, so censoring may hide a true rare normal event, and FA then rises (Gumbel top-2 censored reaches 1.45–1.68 % at ξ = 0.2 with target 0.25 %). Check by replicate: development normals of the same scenario (and normal cross-validation). If they reach the same range, it is tail, not outlier, and the threshold should stay high. A leave-one-recording-out threshold is also a simple check: flag the scenario when dropping one recording moves T by more than one fitted scale.
- Fix the censoring count r before looking at attacks. r = 1, 2 and 3 gave similar results in the simulation.
- Heterogeneity H should be computed on maxima per branch across scenarios. If H ≥ 2, widen τ rather than dropping pooling, because the prior sd then reflects the evidence.

### Gaps
- I found no use of regional or hierarchical extreme-value pooling in intrusion detection or software anomaly scores. The transfer from hydrology is my analogy, and 15 applications are more heterogeneous than gauges on one coast.
- I found no direct empirical-Bayes treatment of GEV shape; the τ² step is mine. A search returned fully Bayesian partial pooling only.
- The simulation has one outlier in one scenario and no shift between validation and test. It should be repeated by replaying Pulse's stored maxima.

## 8. How to choose the per-branch alpha budget from normal data only

### Takeaway
Attack-free data cannot show which branch has power, so the budget cannot be optimised for recall from normal data. The defensible options are equal weights as the baseline, plus one joint statistic calibrated on normal recordings so that the dependence between branches is used automatically.

### Cited Findings
- **[Method]** Weighted Bonferroni tests P_i/W_i with weights averaging 1 — [Roeder and Wasserman 2009](https://arxiv.org/pdf/1010.4637.pdf).
- **[Proof] [Claim]** Optimal weights have a simple parametric form but depend on unknown means. Power is "very robust" to misspecification: "sparse weights (few large weights and minimum weight close to 1) lead to huge power gains for well specified weights, but minute power loss for poorly specified weights" — [Roeder and Wasserman 2009](https://arxiv.org/pdf/1010.4637.pdf). Weights can be external or estimated by data splitting — [Gui et al. review](https://pmc.ncbi.nlm.nih.gov/articles/PMC2703613/) (snippet; the matching of this claim to this URL is my best reading of the results).
- **[Claim]** Under moderately informative guesses, weighting improves power for FDR too — [Genovese, Roeder and Wasserman 2006](https://www.stat.cmu.edu/tr/tr811/tr811.pdf) (snippet; I did not confirm that this URL is the same paper).
- **[Method]** maxT or minP uses the empirical null of the most extreme statistic across tests, so positive dependence needs no explicit correction — [multtest docs](https://rdrr.io/bioc/multtest/man/mt.maxT.html) (snippet).
- **[Method]** Extreme Conformal Prediction splits a level between the estimate and its uncertainty with 1−α ≤ (1−α₁)(1−α₂) — [Pasche, Lam and Engelke](https://arxiv.org/html/2505.08578v2). Scan calibration uses scale-weighted Bonferroni — [Walther 2021](https://arxiv.org/pdf/2107.08296) (snippet).

### Inferences
- **Normal-only limit.** Power depends on attacks, and optimal weights need attack effect sizes. Normal data tells only how expensive or unreliable each branch's threshold is, not how useful the branch is.
- **Candidates, in the order I would test them.**
  1. **Equal budget (baseline).** α_b = target/3, or Šidák. Roeder and Wasserman's robustness result means the loss from not optimising may be small, though that result is for many Gaussian tests rather than three branches.
  2. **Joint minP.** For each normal recording, U_i = min_b p_b(R_ib), with p_b from each branch's fit. Then fit or rank U_i at recording level for the single cut-off. If branches fire together on normals, this gives each branch more budget than Bonferroni. Measure the correlation of branch maxima first; if it is low, the gain will be small.
  3. **Reserve for uncertainty.** Spend less where the threshold is less certain: pick α_b so that the sum of the bootstrap upper bounds (for example p90 of true FA per branch) is within the target. This uses only normal data, and it directs budget away from heavy-tailed or thin branches. It can take budget from the branch that detects most, which is a real risk for CVE-2019-5418's language model. Measure it.
  4. **Surrogate anomalies.** Use normal recordings from other scenarios as stand-ins for out-of-distribution behaviour, to compare branches' separation without attack data. This satisfies the constraint in letter, but such "anomalies" may be far easier than exploits, so treat it as a tie-breaker only. Weights must come from data that are not used for the threshold.
- **Set the pooled target lower than 0.8 %.** Question 5 shows that about 0.5–0.6 % is needed to verify 0.8 % on official. For three branches with equal weights, that is about 0.17–0.2 % per branch before any dependence gain.
- **Per-scenario or global budget.** A global target allows scenario-specific rates. Heartbleed-like scenarios will dominate, unless each scenario gets the same α, which is what per-scenario fitting already does. Keep per-scenario α equal, since no normal-only basis exists to favour a scenario.
- **Boundary with attack data.** Choosing among budget schemes by development recall is model selection on attacks, which the calibration constraint excludes but the project's earlier development selection has done. Report which it is. Pre-register the scheme from normal-only measures if the paper will call the threshold "learned from normal data only".

### Gaps
- I found no paper on allocating false-alarm budget across detector branches with only normal data; this is a real literature gap.
- I did not verify optimal weight formulas in detail, nor whether robustness holds for three correlated branches. Roeder and Wasserman's results are for independent-style Gaussian tests.
- I have not measured branch-maxima correlation on Pulse.

## 9. What to try first (synthesis of questions 1–8)

### Takeaway
All steps below use the stored raw branch scores and are offline replays. Most target the current 81.4 %/0.76 % directly. The recall ≥ 95 % target has no evidence yet in any option here: threshold fitting can only recover attacks whose scores exceed normal behaviour.

### Cited Findings
- **[Pulse]** Baseline: 81.4 % recall, 0.76 % false-alarm recordings on development with moment Gumbel, one-window, three branches (coordinator's measurement).
- **[Measured]** No extreme-value or recording-level calibration paper found here reports results on LID-DS, so every LID-DS effect below must be measured by Pulse. The nearest LID-DS threshold paper reports results at target FPR = 0.05 only — [Kozachok et al. 2026](https://arxiv.org/abs/2606.22581).

### Inferences
Ordered by cost and expected information. Every estimate is unmeasured on Pulse.

1. **Band check for CVE-2019-5418.** Count development normals in the same score band as the 25 missed attacks. This decides whether the threshold or the score is the limit. Do the same for all scenarios: the recall available at ≤ 0.8 % when T is chosen per scenario with knowledge of development normals is an upper bound on what any calibration can do.
2. **Shift check.** Compare validation and development maxima by scenario, and count development maxima above the validation maximum (expected about 3.7 of 227 under exchangeability). High counts in CVE-2014-0160 and CVE-2017-7529 mean shift rather than threshold variance.
3. **Replace moment Gumbel with pooled-shape GEV with top-2 censoring,** keeping one-window. Compare on the same recordings with moment Gumbel, TL(1,1) Gumbel and log-maxima Gumbel.
4. **Increase K** by moving part of the development normals into calibration (K ≈ 170 with half of them), checking on the other half. In my simulation at K = 287 and ξ = 0.2 clean, GEV ML reached mean FA 0.31 % with p90 0.51 %, and moment Gumbel's bias remained (0.81 %). Larger K favours the GEV. For the clean ξ = 0 case at K = 287 (200 repetitions), all fitted methods were within 0.27–0.33 %, and with one outlier the moment Gumbel and GEV were 0.08–0.14 %.
5. **Joint minP over branches** against equal budget.
6. **Length term** on ln m in the location, then report FA by recording length.
7. **Sequential S_t** with GPD p-values and recording-level threshold, against one-window, and a multi-scale scan.
8. **Target** about 0.5–0.6 % pooled on development, and only then run official once.

### Gaps
- Whether recall 95 % is reachable under these constraints is unknown from this literature.
- Simulation scripts are in the session scratchpad: `/tmp/claude-1000/-home-tndat-Downloads-eBPF-project/d1d13a88-05e8-4b39-9713-6ed9238ff484/scratchpad/sim_maxima.py` and `/tmp/claude-1000/-home-tndat-Downloads-eBPF-project/d1d13a88-05e8-4b39-9713-6ed9238ff484/scratchpad/sim2.py`. They are not in the repo and were run on synthetic data only.
- Full texts not obtained: Winkler et al. 2016 (host blocked), Lucas 1982, Hosking 1985, Martins and Stedinger 2000, Laxhammar and Falkman 2015, Ferro and Segers 2003, Coles 2001. Dunn et al. 2023 was seen only through snippets and through Lee et al.'s comparison.
