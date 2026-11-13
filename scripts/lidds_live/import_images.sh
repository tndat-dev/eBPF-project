#!/usr/bin/env bash
# protocol pulse-live-lidds-v1: import the LID-DS victim/exploit images and the generator image from the .234 Docker
# daemon into containerd (k8s.io namespace) on every worker, so the pods run them with imagePullPolicy Never.
#
#   bash import_images.sh scenarios.json [worker-ip ...]
#
# Default workers are the three Pulse worker nodes. Run on .234, where the images were built.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
SCENARIOS=${1:?scenarios.json path}
shift || true
WORKERS=("$@"); [ ${#WORKERS[@]} -gt 0 ] || WORKERS=(10.1.16.237 10.1.16.238 10.1.16.239)

mapfile -t IMAGES < <(python3 - "$SCENARIOS" <<'PY'
import json, sys
cfg = json.load(open(sys.argv[1]))
imgs = {cfg.get("_generator_image", "lidds-gen:latest")}
for name, s in cfg.items():
    if name.startswith("_"):
        continue
    imgs.add(s["victim"]["image"])
    imgs.add(s["exploit"]["image"])
print("\n".join(sorted(imgs)))
PY
)

echo "images: ${IMAGES[*]}"
present=()
for img in "${IMAGES[@]}"; do
  if docker image inspect "$img" >/dev/null 2>&1; then present+=("$img"); else echo "MISSING on .234, skipped: $img"; fi
done
[ ${#present[@]} -gt 0 ] || { echo "no images to import"; exit 1; }

TAR=/var/tmp/lidds-images.tar
echo "saving ${#present[@]} images to $TAR"
docker save "${present[@]}" -o "$TAR"
for w in "${WORKERS[@]}"; do
  echo "== import to $w"
  scp -q "$TAR" "$w:/var/tmp/lidds-images.tar"
  ssh "$w" 'echo 1 | sudo -S -p "" ctr -n k8s.io images import /var/tmp/lidds-images.tar && rm -f /var/tmp/lidds-images.tar'
done
rm -f "$TAR"
echo "done"
