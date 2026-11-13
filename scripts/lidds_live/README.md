# pulse-live-lidds: LID-DS 2021 scenarios on the cluster under the Pulse token probe

Protocol: `sentinel_pulse/protocol/pulse-live-lidds-v1.json` (+ amendment 1). Closes weakness W2
(`notes/PAPER_PLAN.md`): real vulnerable services, their exploits acting **inside the victim's own process tree**,
on Kubernetes, scored by the same token model as a production workload.

## What runs where

- **Victim** of each scenario: a Deployment `victim-<slug>` in namespace `lidds-live`. The Pulse resolver watches
  this namespace (code: `WATCHED_NAMESPACES`), so the victim's syscalls go through the token pipeline unchanged.
- **Normal traffic** and the **exploit**: throwaway pods labelled `lidds-gen` / `lidds-atk`, which the resolver
  **excludes** (`EXCLUDED_MARKERS`). They reach the victim over the network, so only the victim is probed and the
  exploit shows up in the victim's own process tree, as in the dataset.
- **Normal traffic is a generic generator** (image `lidds-gen:latest`): the dataset's selenium/chrome normal clients
  no longer build, so `normal.request` in `scenarios.json` is a plain HTTP/DB command run once per sampled wait time
  (amendment 1). The victim and exploit images are the dataset's own.

## Build the images (on .234, where Docker lives)

The LID-DS repo is cloned at `/var/tmp/lidds-live/LID-DS` (commit 5b8e414). Rot already fixed:

- `ubuntu:13.04` / `ubuntu:16.04` victims use schema-1 manifests that containerd rejects. Converted to local
  schema-2 images with `skopeo copy --format v2s2 docker://ubuntu:13.04 docker-daemon:localrot/ubuntu:13.04` and the
  victim Dockerfiles repointed to `localrot/...`.
- `debian:9` (stretch) apt sources repointed to `archive.debian.org`.
- The generator image: `docker build -f scripts/lidds_live/gen.Dockerfile -t lidds-gen:latest .`

Build victim + exploit images (each independently, one log per image):

    # on .234, as dat (docker group)
    bash /var/tmp/lidds-live/build_ve.sh        # writes /var/tmp/lidds-live/VE.txt
    cat /var/tmp/lidds-live/VE.txt              # per-image ok / FAIL

Known remaining rot: the **metasploit-based exploits** (`exploit_bruteforce`, `exploit_heartbleed`) clone
metasploit 6.1.5 and `bundle install`, which fails on the old ruby base. Those two scenarios' exploits may not build;
the other scenarios do not need metasploit. A scenario is usable when its victim and exploit both build.

Check readiness and import to the workers:

    bash scripts/lidds_live/preflight.sh scripts/lidds_live/scenarios.json
    bash scripts/lidds_live/import_images.sh scripts/lidds_live/scenarios.json   # docker save -> ctr import on the 3 workers

## Run (on .234, with kubectl)

    kubectl apply -f scripts/lidds_live/namespace.yaml
    RUN=/mnt/sentinel-pulse-archive/pulse-live-lidds-<date>
    # 1) capture: normal cycles only, to fit the models
    python3 scripts/lidds_live/driver.py capture --scenarios-file scripts/lidds_live/scenarios.json \
        --run-dir $RUN --duration 43200 --only ZipSlip,CVE-2019-5418,CVE-2017-7529
    # 2) fit one model per victim workload from the capture (token_branch_fit.py, lidds-ml-v5 cluster settings)
    # 3) live: each cycle is an exploit cycle with probability 0.5
    python3 scripts/lidds_live/driver.py live --scenarios-file scripts/lidds_live/scenarios.json \
        --run-dir $RUN --duration 43200 --only ZipSlip,CVE-2019-5418,CVE-2017-7529

The worker/probe must run the lineage-tag build (`ml-final-study-v1` amendment 2) and the resolver must be started
with `--namespace production,lidds-live`. The driver writes `schedule-{capture,live}.jsonl` into `$RUN`.

## Analyse

    python3 scripts/analysis/pulse_live_lidds.py --run-root $RUN --output $RUN/lidds-live.json

Per scenario: recall over exploit cycles, false-alarm cycles over normal cycles, latency, and the session-event share
of alarm windows (near 0 confirms the exploit is detected on the victim's native stream).

## Teardown

    kubectl delete namespace lidds-live
    # on each worker: ctr -n k8s.io images rm <victim/exploit/generator images>
