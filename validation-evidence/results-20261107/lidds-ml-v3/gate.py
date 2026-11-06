import glob, json, os, numpy as np
A="/var/tmp/lid-ds-2021/ml-v3-tokens"; T="/var/tmp/lid-ds-2021/ml-tokens"
tot = worst = 0
for f in sorted(glob.glob(A + "/*.json")):
    s = os.path.basename(f)[:-5]; meta = json.load(open(f)); j = meta["columns"].index("full")
    tm = json.load(open(f"{T}/{s}.json")); it, et = tm["columns"].index("top10"), tm["columns"].index("window_end")
    z, zt = np.load(f"{A}/{s}.npz"), np.load(f"{T}/{s}.npz"); n = w = 0
    for k in z.files:
        if k not in zt.files or not len(zt[k]): continue
        ref = {float(a): float(b) for a, b in zip(zt[k][:, et], zt[k][:, it])}
        for a, b in zip(z[k][:, 0], z[k][:, j]):
            if float(a) in ref: w = max(w, abs(ref[float(a)] - float(b))); n += 1
    tot += n; worst = max(worst, w); print(s, len(z.files), "recordings", n, "windows, largest difference", w)
print("ALL", tot, "windows, largest difference", worst)
