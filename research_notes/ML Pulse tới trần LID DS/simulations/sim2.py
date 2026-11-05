"""Partial pooling of the GEV shape plus top-censoring, with heterogeneous shapes across 15 scenarios
and an outlier in the target scenario. Own simulation; not Pulse data."""
import importlib.util, sys
import numpy as np
from scipy import optimize
sp = importlib.util.spec_from_file_location("sim_maxima", sys.argv[1]); m = importlib.util.module_from_spec(sp); sp.loader.exec_module(m)
rng = np.random.default_rng(7); m.rng = rng
K, alpha, reps = 60, 0.0025, int(sys.argv[2])

def cens_gev(x, r, center, sd):
    xs = np.sort(x); n = len(xs); obs = xs[:n-r]; c = obs[-1]
    def f(p):
        mu, ls, xi = p; s = np.exp(ls)
        z = (obs-mu)/s; t = 1+xi*z; tc = 1+xi*(c-mu)/s
        if abs(xi) < 1e-6:
            ll = np.sum(-ls - z - np.exp(-z)); Fc = np.exp(-np.exp(-(c-mu)/s))
        else:
            if np.any(t <= 0) or tc <= 0: return 1e10
            ll = np.sum(-ls - (1+1/xi)*np.log(t) - t**(-1/xi)); Fc = np.exp(-tc**(-1/xi))
        return -(ll + r*np.log(max(1-Fc, 1e-300)) - 0.5*((xi-center)/sd)**2)
    g = m.gumbel_mom(obs)
    res = optimize.minimize(f, [g[1], np.log(g[2]), center], method="Nelder-Mead", options=dict(maxiter=500, xatol=1e-3, fatol=1e-3))
    return res.x[2], res.x[0], np.exp(res.x[1])

methods = ["gumbel_mom","gumbel_cens2","gev_lmom","gev_ml","pool_prior_sd.05","pool_prior_sd.10","pool_prior_sd.10_cens1","pool_prior_sd.10_cens2","pool_prior_sd.10_cens3"]
for name, mean_xi, sd_xi, out in [("het xi~N(0.15,0.10) clean",.15,.10,None),("het xi~N(0.15,0.10) +1 outlier q=1e-5",.15,.10,1e-5),("het xi~N(0.3,0.15) clean",.3,.15,None),("het xi~N(0.3,0.15) +1 outlier q=1e-5",.3,.15,1e-5),("common xi=0 clean",0,0,None),("common xi=0 +1 outlier q=1e-5",0,0,1e-5)]:
    res = {k: [] for k in methods}; est = []
    for _ in range(reps):
        xis = rng.normal(mean_xi, sd_xi, 15) if sd_xi else np.full(15, float(mean_xi))
        xis = np.clip(xis, -0.3, 0.8)
        xs = [m.gev_rvs(K, x) for x in xis]
        if out is not None: xs[0][np.argmin(xs[0])] = m.gev_q(out, xis[0])
        # robust pooled shape: median of the per-scenario L-moment shapes, so one outlier cannot move it
        center = float(np.median([m.fit_lmom(x)[0] for x in xs])); est.append(center)
        x = xs[0]
        fits = dict(gumbel_mom=m.gumbel_mom(x), gumbel_cens2=m.gumbel_censored(x), gev_lmom=m.fit_lmom(x), gev_ml=m.fit_ml(x))
        fits["pool_prior_sd.05"] = m.fit_ml(x, m.shape_prior(center,.05)); fits["pool_prior_sd.10"] = m.fit_ml(x, m.shape_prior(center,.10))
        for r in (1,2,3): fits[f"pool_prior_sd.10_cens{r}"] = cens_gev(x, r, center, .10)
        for k,(a,b,c) in fits.items():
            res[k].append(float(m.gev_sf(np.array([m.gev_q(alpha,a,b,c)]), xis[0])[0]))
    print(f"\n{name}: pooled shape estimate mean {np.mean(est):+.3f} sd {np.std(est):.3f}")
    print(f"{'method':24s} {'mean FA %':>9s} {'median %':>9s} {'p10 %':>8s} {'p90 %':>8s} {'P(FA>1%)':>9s}")
    for k in methods:
        r=np.array(res[k])*100; print(f"{k:24s} {r.mean():9.3f} {np.median(r):9.3f} {np.quantile(r,.1):8.3f} {np.quantile(r,.9):8.3f} {np.mean(r>1):9.3f}")
