# Model aging: v5 token models on the v6 normal capture (17/11/2026)

Protocol `sentinel_pulse/protocol/pulse-live-v6-v1-amendment-1.json` (added analysis `model_aging`, registered before any
capture window was scored). Descriptive, no decision: the live run uses the fresh fit either way.

- Models and thresholds: `pulse-live-v5-fit-1110/token/MODELS.json`, unchanged (learnt on `pulse-token-capture-1107` and
  the normal of `pulse-live-v4-1109`, before the 12/11 VM resize and recovery).
- Data: the whole capture `pulse-token-capture-v6-1116` (16/11 14:14 to 17/11 02:14, 43,200 s on each of the three workers,
  token drain `insert_fail_cumulative` 0). Worker issues: only `cadence_gap` (12, 25, 11), on all three workers within
  34 s at 16/11 17:10, plus some on k8s-worker3 from 14:55.
- Code: `scripts/analysis/model_aging.py --heldout validation-evidence/results-20261113/ml-final-study/cluster-threshold.json`
  (unit `pulse-v6-model-aging` on `.234`, 4 jobs, 42 min CPU).

| | 60 s container blocks above the v5 threshold | Wilson 95 % |
|---|---|---|
| v5 models on the new capture | 278/47082 = 0.59% | 0.53–0.66% |
| v5's own held-out blocks (cross-fit, part C) | 350/134905 = 0.26% | 0.23–0.29% |
| design level alpha' | 0.018% | |

Burden over the whole capture: 291 episodes in 769.1 replica-hours = 0.378 per
replica-hour; v5's burden in the part C receipt is 0.105 on declared segments of its live run
(different spans, side by side only).

| Workload | New capture | v5 held-out | Episodes per replica-hour |
|---|---|---|---|
| `aims-redis:aims-redis` | 83/2178 (3.81%) | 16/6219 (0.26%) | 2.415 |
| `api-gateway:app` | 45/2904 (1.55%) | 32/8298 (0.39%) | 1.103 |
| `aims-kafka-dual-role:kafka` | 34/2178 (1.56%) | 33/6220 (0.53%) | 0.944 |
| `aims-rabbitmq-server:rabbitmq` | 25/2178 (1.15%) | 66/6218 (1.06%) | 0.694 |
| `aims-waypoint:istio-proxy` | 25/1608 (1.55%) | 63/6954 (0.91%) | 0.945 |
| `aims-postgres-cnpg:postgres` | 14/2178 (0.64%) | 21/6218 (0.34%) | 0.389 |
| `inventory-service:app` | 14/2904 (0.48%) | 5/8299 (0.06%) | 0.291 |
| `catalog-service:app` | 10/2904 (0.34%) | 7/8299 (0.08%) | 0.208 |
| `aims-minio-pool-0:minio` | 8/1452 (0.55%) | 52/4143 (1.26%) | 0.366 |
| `notification-service:app` | 7/2904 (0.24%) | 2/8298 (0.02%) | 0.146 |
| `payment-service:app` | 5/2904 (0.17%) | 11/8299 (0.13%) | 0.104 |
| `aims-redis-sentinel-sentinel:aims-redis-sentinel-sentinel` | 4/2178 (0.18%) | 6/6222 (0.10%) | 0.111 |
| `auth-service:app` | 2/2820 (0.07%) | 1/8301 (0.01%) | 0.064 |
| `order-service:app` | 1/2904 (0.03%) | 13/8300 (0.16%) | 0.021 |
| `search-recommendation-service:app` | 1/2904 (0.03%) | 1/6946 (0.01%) | 0.021 |
| `aims-frontend:web` | 0/1452 (0.00%) | 4/4146 (0.10%) | 0.000 |
| `aims-kafka-entity-operator:topic-operator` | 0/726 (0.00%) | 0/2070 (0.00%) | 0.000 |
| `aims-kafka-entity-operator:user-operator` | 0/726 (0.00%) | 0/2070 (0.00%) | 0.000 |
| `aims-minio-pool-0:sidecar` | 0/1452 (0.00%) | 1/4140 (0.02%) | 0.000 |
| `cart-service:app` | 0/2904 (0.00%) | 5/8294 (0.06%) | 0.000 |
| `security-telemetry-service:app` | 0/2724 (0.00%) | 11/6951 (0.16%) | 0.000 |

Reading: the exceedance rate of the unchanged v5 models is about 2.3 times their own held-out rate, and the excess sits in
a few workloads (Redis 3.81 % against 0.26 %, then api-gateway, Kafka, inventory); others are lower than before (MinIO,
order, security-telemetry). Redis, its sentinels and several services were recreated in the 12/11 recovery. So a count
model learnt before a cluster change raises the false-alarm rate of some workloads after it, and a refit after such a
change is needed; which change caused it per workload is not identified here.
