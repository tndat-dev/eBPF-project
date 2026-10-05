# Sentinel Pulse R10-C2 formal normal soak — start receipt

- Run ID: `sentinel-pulse-r10-c2-formal-20261001`.
- Start: `2026-10-01T13:08:37.023605Z` (20:08:37 ICT), after 321 s healthy preflight.
- Registered capture: 86,400 s at 500 ms; 24-hour minimum per workload.
- Source snapshot commit: `05c09a79ea608486374e3b694e3d0d070ab51ec0` in an isolated VM worktree.
- Model manifest SHA-256: `6ddf7cf9b03cb783b82c23272f7046bafa7ab1412b0545b60a2821d1f441cc21`.
- Decision policy SHA-256: `602165bd48d81f549d3bfb65e5bdb319a11252678cbf484d739afcf2e5bc8143`.
- Traffic gate passed: 20/20 per each of 10 east-west services and 20/20 per ingress route.
- Initial monitor (13:11 UTC): all 3 workers active, old collectors inactive, no restarts/errors/alerts, telemetry availability 1.0. This is startup evidence only, not a soak result.
- No training, attack injection, blind evaluation, or model promotion. Lifecycle is configured to stop after normal phase.
- Earliest finalize eligibility: `2026-10-02T13:08:37Z`; default 300 s finalization margin means approximately 20:13:37 ICT if all gates remain valid.

The JSON start marker, workload fingerprint, source checksums, worker map, lifecycle
phases and traffic gate receipt are included here. Raw captures and live monitor
remain on the master under `/home/dat/eBPF-project-formal-r10-c2-20261001/validation-evidence/sentinel-pulse-campaign/sentinel-pulse-r10-c2-formal-20261001/`.
