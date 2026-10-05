# R10-C1 follow-up production traffic-gate receipt

- Run on cluster control plane: `2026-10-01T12:02:19.817668Z`
- Gate source commit: `6eb1cd34b36f8c52d75e679e2e931e6ae7d35080`
- Result: **failed; no canary was started**.
- All 10 AIMS Argo Rollouts reported Healthy 4/4 in the captured snapshot.
- East-west: 9 targets returned 20/20 HTTP 200. `security-telemetry-service`
  returned 19 HTTP 200 and one timeout (observed maximum latency about 38.6 s).
- North-south: `/` and `/api/health/` returned 20/20; `/api/products/` returned
  0/20 because the gate used an obsolete non-paginated route. The continuous
  loadgen already used `/api/products/?page=1`. The local gate implementation
  and focused test now use that same route; end-to-end rerun is still required.
- At approximately the same time, worker1 had `NodeNotReady`/probe timeouts and
  PostgreSQL primary pod liveness restarts. Kernel logs showed Longhorn iSCSI
  timeouts and SCSI resets on worker1 and worker4; subsequent Longhorn logs
  included refused replica connections to worker4 endpoint `10.0.4.244`.
- Current read-only cluster snapshot later showed 6/6 Kubernetes nodes Ready,
  CNPG 3/3 instances Ready, and 29/29 Longhorn volumes `healthy`. This does not
  establish sustained stability or root cause. No causal claim is made between
  this transient disruption and the earlier C1 telemetry gaps.

Do not count this as an ML detection result or relax the gate. Repeat only after
the infrastructure remains stable and with the corrected gate source.

## Corrected-gate rerun

At `2026-10-01T12:13:34Z`, the corrected gate passed with 20 samples per target:
all 10 east-west services returned 20/20 HTTP 200, and `/`, `/api/health/`, and
`/api/products/?page=1` each returned 20/20. This is a short functional traffic
gate only; it does not establish a sustained infrastructure-stability window
and is not an ML detection or latency benchmark. Raw receipt:
`traffic-gate-v2.json`.
