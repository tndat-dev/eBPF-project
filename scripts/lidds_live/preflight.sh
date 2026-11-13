#!/usr/bin/env bash
# protocol pulse-live-lidds-v1: report which scenarios have every image present on .234 (victim, exploit, generator).
# Run on .234 before import_images.sh / the driver.
#   bash preflight.sh scenarios.json
set -euo pipefail
SCENARIOS=${1:?scenarios.json}
python3 - "$SCENARIOS" <<'PY'
import json, subprocess, sys
cfg = json.load(open(sys.argv[1]))
gen = cfg.get("_generator_image", "lidds-gen:latest")
def have(img):
    return subprocess.run(["docker", "image", "inspect", img], capture_output=True).returncode == 0
print(f"generator {gen}: {'ok' if have(gen) else 'MISSING'}")
ready = []
for name, s in cfg.items():
    if name.startswith("_"):
        continue
    v, e = s["victim"]["image"], s["exploit"]["image"]
    hv, he = have(v), have(e)
    status = "READY" if (hv and he and have(gen)) else "incomplete"
    if status == "READY":
        ready.append(name)
    print(f"{name:22s} victim={'ok' if hv else 'MISSING':7s} exploit={'ok' if he else 'MISSING':7s} -> {status}")
print("\nrunnable scenarios:", ",".join(ready) if ready else "(none)")
PY
