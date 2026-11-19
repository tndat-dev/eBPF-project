# Rehearsal of the final live run (`pulse-final-rehearsal-1119`, 19/11, 30 min)

Six trials, one of each kind on the workloads with unusual images and paths (planner `--rehearsal`): aims-frontend (musl,
6/s), aims-redis (musl, 0.5/s), aims-waypoint (distroless, PAD 300), aims-postgres-cnpg (staging in /run, on-off 10 s),
aims-rabbitmq-server (/operator, 24/s), api-gateway (12/s). Snapshot runtime-0c385d9-20261119, probe
pulse-tokens-final-f8ccbb2, models pulse-live-v7-fit-1118 (t3).

- Every step ran: control, admin, harmless binary, attack, living off the land, event-generator. Event-generator outcomes
  (`EVENTGEN.jsonl`): 4 executed, 1 error (permission, counted as an attempt), 1 skipped on the distroless waypoint (no `ln`),
  left out by the analysis as registered.
- `scripts/analysis/pulse_live_v4.py` runs on the new sets (`rehearsal-v4.json`): rates 0.5 … 24, `pad300`, `onoff10`,
  event-generator per action. Workers: 0 issues.
- Bridge: 37/37 episodes pushed; every alert row carries `session_events` (stream label 30 session, 7 native); no push
  failed, so the durable queue file was never needed.
- Kubernetes events recorded (303 events in 30 min).
- Mean time per trial 138 s (137–139), which sets the final run to 162,000 s for 945 trials.
