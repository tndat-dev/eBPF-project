"""Monte Carlo: how accurately can about 60 per-recording maxima set a threshold at a low
false-alarm target? True exceedance of each fitted threshold is computed exactly from the true GEV.
Own simulation; not Pulse data. xi > 0 is heavy tailed."""
import numpy as np
from scipy import optimize, special

G = 0.5772156649
rng = np.random.default_rng(20261105)


def gev_sf(x, xi, mu=0.0, s=1.0):
    z = (x - mu) / s
    if abs(xi) < 1e-9:
        return -np.expm1(-np.exp(-z))
    t = 1 + xi * z
    out = np.where(t <= 0, (0.0 if xi > 0 else 1.0) if False else 0.0, 0.0)
    pos = t > 0
    out = np.zeros_like(z, dtype=float)
    out[pos] = -np.expm1(-t[pos] ** (-1 / xi))
    out[~pos] = 1.0 if xi > 0 else 0.0
    return out


def gev_rvs(size, xi):
    u = rng.uniform(size=size)
    e = -np.log(u)
    return -np.log(e) if abs(xi) < 1e-9 else (e ** (-xi) - 1) / xi


def gev_q(a, xi, mu=0.0, s=1.0):
    y = -np.log1p(-a)
    return mu - s * np.log(y) if abs(xi) < 1e-9 else mu + s * (y ** (-xi) - 1) / xi


def lmom(x):
    x = np.sort(x)
    n = len(x)
    i = np.arange(1, n + 1)
    b0 = x.mean()
    b1 = np.sum((i - 1) / (n - 1) * x) / n
    b2 = np.sum((i - 1) * (i - 2) / ((n - 1) * (n - 2)) * x) / n
    return b0, 2 * b1 - b0, 6 * b2 - 6 * b1 + b0


def gev_from_l(l1, l2, t3):
    c = 2 / (3 + t3) - np.log(2) / np.log(3)
    k = 7.8590 * c + 2.9554 * c * c  # Hosking k = -xi
    k = np.clip(k, -0.95, 0.95)
    if abs(k) < 1e-6:
        s = l2 / np.log(2)
        return 0.0, l1 - G * s, s
    g = special.gamma(1 + k)
    s = l2 * k / ((1 - 2.0 ** (-k)) * g)
    return -k, l1 - s * (1 - g) / k, s


def fit_lmom(x):
    l1, l2, l3 = lmom(x)
    return gev_from_l(l1, l2, l3 / l2)


def nll(p, x, prior=None):
    mu, ls, xi = p
    s = np.exp(ls)
    z = (x - mu) / s
    if abs(xi) < 1e-6:
        v = len(x) * ls + np.sum(z) + np.sum(np.exp(-z))
    else:
        t = 1 + xi * z
        if np.any(t <= 0):
            return 1e10
        v = len(x) * ls + (1 + 1 / xi) * np.sum(np.log(t)) + np.sum(t ** (-1 / xi))
    if prior is not None:
        v -= prior(xi)
        if not np.isfinite(v):
            return 1e10
    return v


def fit_ml(x, prior=None):
    start = fit_lmom(x)
    x0 = [start[1], np.log(start[2]), np.clip(start[0], -0.3, 0.45)]
    r = optimize.minimize(nll, x0, args=(x, prior), method="Nelder-Mead",
                          options=dict(maxiter=600, xatol=1e-3, fatol=1e-3))
    return r.x[2], r.x[0], np.exp(r.x[1])


def shape_prior(center, sd):
    return lambda xi: -0.5 * ((xi - center) / sd) ** 2


def gumbel_mom(x):
    s = x.std(ddof=1) * np.sqrt(6) / np.pi
    return 0.0, x.mean() - G * s, s


def gumbel_ml(x):
    s = x.std(ddof=1) * np.sqrt(6) / np.pi
    f = lambda sg: x.mean() - np.sum(x * np.exp(-x / sg)) / np.sum(np.exp(-x / sg)) - sg
    try:
        s = optimize.brentq(f, s * 0.05, s * 5)
    except ValueError:
        pass
    return 0.0, -s * np.log(np.mean(np.exp(-x / s))), s


def gumbel_robust(x):
    """quantile fit: median and IQR only (breakdown 25 %)"""
    q25, q50, q75 = np.quantile(x, [0.25, 0.5, 0.75])
    a, b, c = -np.log(-np.log(0.25)), -np.log(-np.log(0.5)), -np.log(-np.log(0.75))
    s = (q75 - q25) / (c - a)
    return 0.0, q50 - b * s, s


def gumbel_censored(x, r=2):
    """Gumbel ML with the r largest values right censored at the next one (type II censoring)"""
    xs = np.sort(x)
    n = len(xs)
    obs = xs[: n - r]
    c = obs[-1]

    def f(p):
        mu, ls = p
        s = np.exp(ls)
        z = (obs - mu) / s
        ll = np.sum(-ls - z - np.exp(-z))
        ll += r * np.log(max(-np.expm1(-np.exp(-(c - mu) / s)), 1e-300))
        return -ll

    g = gumbel_mom(obs)
    res = optimize.minimize(f, [g[1], np.log(g[2])], method="Nelder-Mead",
                            options=dict(maxiter=300, xatol=1e-3, fatol=1e-3))
    return 0.0, res.x[0], np.exp(res.x[1])


def run(K=60, alpha=0.0025, reps=2000, n_regional=15):
    print(f"K={K} target per-branch alpha={alpha} reps={reps}")
    rows = []
    scen = [("xi=-0.1", -0.1, None), ("xi=0", 0.0, None), ("xi=0.1", 0.1, None), ("xi=0.2", 0.2, None),
            ("xi=0.3", 0.3, None), ("xi=0.5", 0.5, None), ("xi=0+1 outlier", 0.0, 1e-5), ("xi=0.2+1 outlier", 0.2, 1e-6)]
    methods = ["gumbel_mom", "gumbel_ml", "gumbel_iqr", "gumbel_cens2", "gev_lmom", "gev_ml", "gev_gml_prior",
               "gev_regional_shape", "empirical_max"]
    for name, xi, out in scen:
        res = {m: [] for m in methods}
        shapes = []
        for _ in range(reps):
            x = gev_rvs(K, xi)
            if out is not None:
                x[np.argmin(x)] = gev_q(out, xi)
            # regional shape: same xi at n_regional scenarios, L-moment ratios averaged (index-flood idea)
            ts = [lmom(gev_rvs(K, xi)) for _ in range(n_regional - 1)]
            t3 = np.mean([l3 / l2 for _, l2, l3 in ts] + [lmom(x)[2] / lmom(x)[1]])
            xi_reg = gev_from_l(1.0, 1.0, t3)[0]
            fits = dict(gumbel_mom=gumbel_mom(x), gumbel_ml=gumbel_ml(x), gumbel_iqr=gumbel_robust(x),
                        gumbel_cens2=gumbel_censored(x), gev_lmom=fit_lmom(x), gev_ml=fit_ml(x),
                        gev_gml_prior=fit_ml(x, shape_prior(0.1, 0.15)),
                        gev_regional_shape=fit_ml(x, shape_prior(xi_reg, 0.03)))
            shapes.append(fits["gev_ml"][0])
            for m, (a, b, c) in fits.items():
                T = gev_q(alpha, a, b, c)
                res[m].append(float(gev_sf(np.array([T]), xi)[0]))
            res["empirical_max"].append(float(gev_sf(np.array([x.max()]), xi)[0]))
        print(f"\n{name}: shape MLE mean {np.mean(shapes):+.3f} sd {np.std(shapes):.3f}")
        print(f"{'method':22s} {'mean FA %':>9s} {'median %':>9s} {'p10 %':>8s} {'p90 %':>8s} {'P(FA>1%)':>9s}")
        for m in methods:
            r = np.array(res[m]) * 100
            print(f"{m:22s} {r.mean():9.3f} {np.median(r):9.3f} {np.quantile(r,.1):8.3f} {np.quantile(r,.9):8.3f} {np.mean(r>1):9.3f}")


if __name__ == "__main__":
    import sys
    run(K=int(sys.argv[1]), alpha=float(sys.argv[2]), reps=int(sys.argv[3]))
