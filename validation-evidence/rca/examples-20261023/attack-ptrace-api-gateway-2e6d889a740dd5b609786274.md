# Cây bằng chứng sau tín hiệu Pulse

Case: `2e6d889a740dd5b609786274`. Nguồn: `candidate_alert_preview`.

Workload: `production/api-gateway:app`; node: `k8s-worker1.local`; pod UID: `9fa980bd-f485-4b2d-892f-d1e3018931d9`.

Đây là bằng chứng tương quan, chưa xác nhận process nào gây anomaly hoặc root cause.

Connect khớp: 36; giữ trong cây: 36.

| Loại | Bằng chứng |
|---|---|
| process | binary=/usr/local/bin/uvicorn; pid=3804938; exec_id=azhzLXdvcmtlcjEubG9jYWw6MjM4MDY3MTExMDg2NTg4MzozODA0OTM4 |
| process_parent | binary=/usr/bin/containerd-shim-runc-v2; pid=3803310; exec_id=azhzLXdvcmtlcjEubG9jYWw6MjM4MDY2MTk0NzgzOTU2MjozODAzMzEw |
| Đích connect (kết quả theo từng event) | 10.96.0.10:53; K8s={'kind': 'Service', 'namespace': 'kube-system', 'name': 'kube-dns', 'uid': 'f57e394f-78cc-4b99-b1dd-2476dc2504a3'} |
| Đích connect (kết quả theo từng event) | 10.105.36.105:8000; K8s={'kind': 'Service', 'namespace': 'production', 'name': 'catalog-service', 'uid': '539fa59e-4c87-4745-9e8a-0a8944229d30'} |
| Đích connect (kết quả theo từng event) | 10.102.22.84:8000; K8s={'kind': 'Service', 'namespace': 'production', 'name': 'auth-service', 'uid': 'c7c9cf16-74cc-421a-a68b-037012071e20'} |
| process | binary=/usr/local/bin/python; pid=2278399; exec_id=azhzLXdvcmtlcjEubG9jYWw6NDUwOTIxNzY0MTI0MzM5NDoyMjc4Mzk5 |
| Đích connect (kết quả theo từng event) | 127.0.0.1:8000; K8s=None |
| process | binary=/usr/local/bin/python; pid=2278959; exec_id=azhzLXdvcmtlcjEubG9jYWw6NDUwOTIyMTM4ODMzOTY1NjoyMjc4OTU5 |
| process | binary=/usr/local/bin/python; pid=2279303; exec_id=azhzLXdvcmtlcjEubG9jYWw6NDUwOTIyMjYzNjE2Nzc5MDoyMjc5MzAz |
| process_parent | binary=/usr/bin/runc; pid=2279290; exec_id=azhzLXdvcmtlcjEubG9jYWw6NDUwOTIyMjU1NTI0NzI4ODoyMjc5Mjkw |
| Đích connect (kết quả theo từng event) | 10.109.229.136:8000; K8s={'kind': 'Service', 'namespace': 'production', 'name': 'cart-service', 'uid': '72ba8842-b294-4e96-9486-27b93805e6f1'} |
| process | binary=/usr/local/bin/python; pid=2280111; exec_id=azhzLXdvcmtlcjEubG9jYWw6NDUwOTIyNzYzMDg0Mzk1ODoyMjgwMTEx |
| process | binary=/usr/local/bin/python; pid=2280853; exec_id=azhzLXdvcmtlcjEubG9jYWw6NDUwOTIzMjYyOTUwNzA3MDoyMjgwODUz |
| process_parent | binary=/usr/bin/runc; pid=2280841; exec_id=azhzLXdvcmtlcjEubG9jYWw6NDUwOTIzMjU1NDk5NDM4MjoyMjgwODQx |
| process | binary=/usr/local/bin/python; pid=2281449; exec_id=azhzLXdvcmtlcjEubG9jYWw6NDUwOTIzNjM5NDcyNTAzOToyMjgxNDQ5 |
| process | binary=/usr/local/bin/python; pid=2281694; exec_id=azhzLXdvcmtlcjEubG9jYWw6NDUwOTIzNzYyNTQzMDIxNjoyMjgxNjk0 |
| process | binary=/usr/local/bin/python; pid=2282396; exec_id=azhzLXdvcmtlcjEubG9jYWw6NDUwOTI0MjYxODY0MTcxMzoyMjgyMzk2 |
| process | binary=None; pid=None; exec_id=azhzLXdvcmtlcjEubG9jYWw6MjM4MDY2MTkzNTU3NzYwMDozODAzMzAy |
| Đích connect (kết quả theo từng event) | 10.0.2.158:43365; K8s={'kind': 'Pod', 'namespace': 'production', 'name': 'aims-waypoint-6d558c5d7c-n879w', 'uid': '62b19ea1-27ac-4bbf-880d-f9a357b5f005', 'service': 'aims-waypoint'} |
| Đích connect (kết quả theo từng event) | 10.1.16.239:50471; K8s={'kind': 'Pod', 'namespace': 'monitoring', 'name': 'monitoring-prometheus-node-exporter-2pfq6', 'uid': '17c00cf6-cfab-4039-9a46-ed31ba9d91bc', 'service': 'monitoring-prometheus-node-exporter'} |
| Đích connect (kết quả theo từng event) | 10.1.16.238:46527; K8s={'kind': 'Pod', 'namespace': 'monitoring', 'name': 'monitoring-prometheus-node-exporter-5t4tl', 'uid': 'ebca49f1-acab-4346-9bfb-fbe3bafb4b5b', 'service': 'monitoring-prometheus-node-exporter'} |
| Đích connect (kết quả theo từng event) | 127.0.0.1:49300; K8s=None |
| Đích connect (kết quả theo từng event) | 10.1.16.238:46287; K8s={'kind': 'Pod', 'namespace': 'monitoring', 'name': 'monitoring-prometheus-node-exporter-5t4tl', 'uid': 'ebca49f1-acab-4346-9bfb-fbe3bafb4b5b', 'service': 'monitoring-prometheus-node-exporter'} |
| Đích connect (kết quả theo từng event) | 10.109.180.244:4317; K8s={'kind': 'Service', 'namespace': 'observability', 'name': 'otel-collector-collector', 'uid': 'a62b5cc8-87f0-41d7-8a09-48f263848993'} |
| Đích connect (kết quả theo từng event) | 10.1.16.239:54809; K8s={'kind': 'Pod', 'namespace': 'monitoring', 'name': 'monitoring-prometheus-node-exporter-2pfq6', 'uid': '17c00cf6-cfab-4039-9a46-ed31ba9d91bc', 'service': 'monitoring-prometheus-node-exporter'} |
| Đích connect (kết quả theo từng event) | 127.0.0.1:49430; K8s=None |
| Đích connect (kết quả theo từng event) | 10.0.2.119:6379; K8s={'kind': 'Pod', 'namespace': 'production', 'name': 'aims-redis-0', 'uid': '5af687a6-4011-4738-be63-c2014aaa983f', 'service': 'aims-redis-master'} |
| Đích connect (kết quả theo từng event) | 127.0.0.1:49528; K8s=None |
| Đích connect (kết quả theo từng event) | 10.1.16.238:59461; K8s={'kind': 'Pod', 'namespace': 'monitoring', 'name': 'monitoring-prometheus-node-exporter-5t4tl', 'uid': 'ebca49f1-acab-4346-9bfb-fbe3bafb4b5b', 'service': 'monitoring-prometheus-node-exporter'} |
| process | binary=/tmp/sentinel-runtime-attack-blind; pid=2279470; exec_id=azhzLXdvcmtlcjEubG9jYWw6NDUwOTIyMzcyODY1NDI0MzoyMjc5NDcw |
| Đích connect (kết quả theo từng event) | 10.0.2.165:55287; K8s={'kind': 'Pod', 'namespace': 'istio-ingress', 'name': 'aims-ingress-istio-5d4db857f-vhdmt', 'uid': 'a303be1b-aed7-4dfd-8eb9-a1303a97f758', 'service': 'aims-ingress-istio'} |
| Đích connect (kết quả theo từng event) | 10.0.2.165:56405; K8s={'kind': 'Pod', 'namespace': 'istio-ingress', 'name': 'aims-ingress-istio-5d4db857f-vhdmt', 'uid': 'a303be1b-aed7-4dfd-8eb9-a1303a97f758', 'service': 'aims-ingress-istio'} |
| Đích connect (kết quả theo từng event) | 10.1.16.238:48021; K8s={'kind': 'Pod', 'namespace': 'monitoring', 'name': 'monitoring-prometheus-node-exporter-5t4tl', 'uid': 'ebca49f1-acab-4346-9bfb-fbe3bafb4b5b', 'service': 'monitoring-prometheus-node-exporter'} |
| Đích connect (kết quả theo từng event) | 127.0.0.1:46362; K8s=None |
| Đích connect (kết quả theo từng event) | 10.1.16.239:57887; K8s={'kind': 'Pod', 'namespace': 'monitoring', 'name': 'monitoring-prometheus-node-exporter-2pfq6', 'uid': '17c00cf6-cfab-4039-9a46-ed31ba9d91bc', 'service': 'monitoring-prometheus-node-exporter'} |
| Đích connect (kết quả theo từng event) | 10.1.16.238:33371; K8s={'kind': 'Pod', 'namespace': 'monitoring', 'name': 'monitoring-prometheus-node-exporter-5t4tl', 'uid': 'ebca49f1-acab-4346-9bfb-fbe3bafb4b5b', 'service': 'monitoring-prometheus-node-exporter'} |
| Đích connect (kết quả theo từng event) | 10.1.16.239:50543; K8s={'kind': 'Pod', 'namespace': 'monitoring', 'name': 'monitoring-prometheus-node-exporter-2pfq6', 'uid': '17c00cf6-cfab-4039-9a46-ed31ba9d91bc', 'service': 'monitoring-prometheus-node-exporter'} |
| Đích connect (kết quả theo từng event) | 127.0.0.1:46598; K8s=None |
| Đích connect (kết quả theo từng event) | 10.0.2.158:53631; K8s={'kind': 'Pod', 'namespace': 'production', 'name': 'aims-waypoint-6d558c5d7c-n879w', 'uid': '62b19ea1-27ac-4bbf-880d-f9a357b5f005', 'service': 'aims-waypoint'} |
| Đích connect (kết quả theo từng event) | 127.0.0.1:48484; K8s=None |
| Đích connect (kết quả theo từng event) | 127.0.0.1:48594; K8s=None |
| Đích connect (kết quả theo từng event) | 10.0.2.165:60635; K8s={'kind': 'Pod', 'namespace': 'istio-ingress', 'name': 'aims-ingress-istio-5d4db857f-vhdmt', 'uid': 'a303be1b-aed7-4dfd-8eb9-a1303a97f758', 'service': 'aims-ingress-istio'} |
| Đích connect (kết quả theo từng event) | 10.1.16.239:39081; K8s={'kind': 'Pod', 'namespace': 'monitoring', 'name': 'monitoring-prometheus-node-exporter-2pfq6', 'uid': '17c00cf6-cfab-4039-9a46-ed31ba9d91bc', 'service': 'monitoring-prometheus-node-exporter'} |
| Đích connect (kết quả theo từng event) | 10.1.16.239:47003; K8s={'kind': 'Pod', 'namespace': 'monitoring', 'name': 'monitoring-prometheus-node-exporter-2pfq6', 'uid': '17c00cf6-cfab-4039-9a46-ed31ba9d91bc', 'service': 'monitoring-prometheus-node-exporter'} |
| Đích connect (kết quả theo từng event) | 127.0.0.1:48794; K8s=None |
| Đích connect (kết quả theo từng event) | 10.0.2.158:40469; K8s={'kind': 'Pod', 'namespace': 'production', 'name': 'aims-waypoint-6d558c5d7c-n879w', 'uid': '62b19ea1-27ac-4bbf-880d-f9a357b5f005', 'service': 'aims-waypoint'} |
| process | binary=/tmp/sentinel-runtime-attack-blind; pid=2282532; exec_id=azhzLXdvcmtlcjEubG9jYWw6NDUwOTI0Mzg1NjYxNjYwMzoyMjgyNTMy |
| process | binary=/tmp/sentinel-runtime-attack-blind; pid=2282550; exec_id=azhzLXdvcmtlcjEubG9jYWw6NDUwOTI0Mzg1Nzc2NzA0NDoyMjgyNTUw |
| process | binary=/tmp/sentinel-runtime-attack-blind; pid=2282590; exec_id=azhzLXdvcmtlcjEubG9jYWw6NDUwOTI0MzkwMDA1MzU4NToyMjgyNTkw |
| process | binary=/tmp/sentinel-runtime-attack-blind; pid=2282631; exec_id=azhzLXdvcmtlcjEubG9jYWw6NDUwOTI0Mzk0MjM5NjQzNDoyMjgyNjMx |
| process | binary=/tmp/sentinel-runtime-attack-blind; pid=2282651; exec_id=azhzLXdvcmtlcjEubG9jYWw6NDUwOTI0Mzk4NDY2MzkxNDoyMjgyNjUx |
| process | binary=/tmp/sentinel-runtime-attack-blind; pid=2282661; exec_id=azhzLXdvcmtlcjEubG9jYWw6NDUwOTI0NDAyNzIxMjkxMDoyMjgyNjYx |
| process | binary=/tmp/sentinel-runtime-attack-blind; pid=2282670; exec_id=azhzLXdvcmtlcjEubG9jYWw6NDUwOTI0NDA2OTc1OTc5MjoyMjgyNjcw |
| process | binary=/tmp/sentinel-runtime-attack-blind; pid=2282685; exec_id=azhzLXdvcmtlcjEubG9jYWw6NDUwOTI0NDExMjExNjQ1MjoyMjgyNjg1 |
| process | binary=/tmp/sentinel-runtime-attack-blind; pid=2282686; exec_id=azhzLXdvcmtlcjEubG9jYWw6NDUwOTI0NDE1NDYzOTI4NjoyMjgyNjg2 |
| process | binary=/tmp/sentinel-runtime-attack-blind; pid=2282707; exec_id=azhzLXdvcmtlcjEubG9jYWw6NDUwOTI0NDE5NzAzMzgzOToyMjgyNzA3 |
| process | binary=/tmp/sentinel-runtime-attack-blind; pid=2282725; exec_id=azhzLXdvcmtlcjEubG9jYWw6NDUwOTI0NDIzOTgyMzM4ODoyMjgyNzI1 |
| process | binary=/tmp/sentinel-runtime-attack-blind; pid=2282732; exec_id=azhzLXdvcmtlcjEubG9jYWw6NDUwOTI0NDI4MjE3NjUzMToyMjgyNzMy |
| process | binary=/tmp/sentinel-runtime-attack-blind; pid=2282733; exec_id=azhzLXdvcmtlcjEubG9jYWw6NDUwOTI0NDMyNDU4Njk2MjoyMjgyNzMz |
| process | binary=/tmp/sentinel-runtime-attack-blind; pid=2282734; exec_id=azhzLXdvcmtlcjEubG9jYWw6NDUwOTI0NDM2NzE1MzY2MToyMjgyNzM0 |
| process | binary=/tmp/sentinel-runtime-attack-blind; pid=2282735; exec_id=azhzLXdvcmtlcjEubG9jYWw6NDUwOTI0NDQxMjc0NjM5NjoyMjgyNzM1 |
| process | binary=/tmp/sentinel-runtime-attack-blind; pid=2282754; exec_id=azhzLXdvcmtlcjEubG9jYWw6NDUwOTI0NDQ1NTg0MzMyNzoyMjgyNzU0 |
| process | binary=/tmp/sentinel-runtime-attack-blind; pid=2282761; exec_id=azhzLXdvcmtlcjEubG9jYWw6NDUwOTI0NDQ5ODQ2OTY3NjoyMjgyNzYx |

## Phạm vi quan sát

```json
{
  "inventory_at": 1792567117.0625117,
  "inventory_age_seconds": 50.31568789482117,
  "pod_name": "api-gateway-5b79675d85-4q84j",
  "connect_policy_selected": true,
  "connect_policy": "sentinel-rca-runtime-v1",
  "subscription_started_at": 1792566577.0704787,
  "subscription_started_before_pre_window": true,
  "transport_loss": "not_measured_no_exact_event_completeness_guarantee",
  "subscriber_lag_seconds": 0.19560790061950684,
  "query_event_cap": 10001,
  "query_event_cap_reached": false,
  "ring_retention_seconds": 180,
  "initial_history_backfill": false,
  "runtime_policy": "sentinel-rca-runtime-v1",
  "runtime_policy_scope": "production namespace, all pods",
  "file_detail_sampling": "1s per process per open/write hook",
  "post_context_seconds": 0,
  "case_ready_grace_seconds": 2,
  "target_preview_to_case_seconds": 2,
  "lifecycle_subscription_started_at": 1792566478.8935504,
  "last_runtime_event_received_at": 1792567167.378136
}
```

Không thu nội dung ứng dụng, mật khẩu, argv hoặc TLS plaintext. JSON kèm theo chứa đầy đủ node/edge và hash bằng chứng.

## Sự kiện runtime trong cửa sổ điều tra

| Nhóm | Thao tác | Kết quả kernel | Đối tượng / chi tiết |
|---|---|---|---|
| process | exec | {"status": "executed", "return_observed": false, "return_value": null} | {} |
| process | exit | {"status": "exited", "exit_status": 0, "signal": null, "return_observed": false, "return_value": null} | {} |
| process | exec | {"status": "executed", "return_observed": false, "return_value": null} | {} |
| process | exit | {"status": "exited", "exit_status": 0, "signal": null, "return_observed": false, "return_value": null} | {} |
| process | exec | {"status": "executed", "return_observed": false, "return_value": null} | {} |
| process | exit | {"status": "exited", "exit_status": 0, "signal": null, "return_observed": false, "return_value": null} | {} |
| process | exec | {"status": "executed", "return_observed": false, "return_value": null} | {} |
| process | exec | {"status": "executed", "return_observed": false, "return_value": null} | {} |
| process | exit | {"status": "exited", "exit_status": 0, "signal": null, "return_observed": false, "return_value": null} | {} |
| process | exec | {"status": "executed", "return_observed": false, "return_value": null} | {} |
| process | exit | {"status": "exited", "exit_status": 0, "signal": null, "return_observed": false, "return_value": null} | {} |
| process | exec | {"status": "executed", "return_observed": false, "return_value": null} | {} |
| process | exit | {"status": "exited", "exit_status": 0, "signal": null, "return_observed": false, "return_value": null} | {} |
| process | exec | {"status": "executed", "return_observed": false, "return_value": null} | {} |
| process | exit | {"status": "exited", "exit_status": 0, "signal": null, "return_observed": false, "return_value": null} | {} |
| process | exit | {"status": "exited", "exit_status": 0, "signal": null, "return_observed": false, "return_value": null} | {} |
| process | exec | {"status": "executed", "return_observed": false, "return_value": null} | {} |
| process | exit | {"status": "exited", "exit_status": 0, "signal": null, "return_observed": false, "return_value": null} | {} |
| process | exec | {"status": "executed", "return_observed": false, "return_value": null} | {} |
| process | fork | {"status": "child_created", "return_observed": false, "return_value": null} | {"parent_pid": 2282532, "child_pid": 2282550} |
| ptrace | ptrace | {"status": "success", "return_observed": true, "return_value": 0, "errno": null} | {"ptrace_request": 0, "target_pid": 0, "target_address": 0} |
| process | exit | {"status": "exited", "exit_status": 0, "signal": null, "return_observed": false, "return_value": null} | {} |
| process | fork | {"status": "child_created", "return_observed": false, "return_value": null} | {"parent_pid": 2282532, "child_pid": 2282590} |
| ptrace | ptrace | {"status": "success", "return_observed": true, "return_value": 0, "errno": null} | {"ptrace_request": 0, "target_pid": 0, "target_address": 0} |
| process | exit | {"status": "exited", "exit_status": 0, "signal": null, "return_observed": false, "return_value": null} | {} |
| process | fork | {"status": "child_created", "return_observed": false, "return_value": null} | {"parent_pid": 2282532, "child_pid": 2282631} |
| ptrace | ptrace | {"status": "success", "return_observed": true, "return_value": 0, "errno": null} | {"ptrace_request": 0, "target_pid": 0, "target_address": 0} |
| process | exit | {"status": "exited", "exit_status": 0, "signal": null, "return_observed": false, "return_value": null} | {} |
| process | fork | {"status": "child_created", "return_observed": false, "return_value": null} | {"parent_pid": 2282532, "child_pid": 2282651} |
| ptrace | ptrace | {"status": "success", "return_observed": true, "return_value": 0, "errno": null} | {"ptrace_request": 0, "target_pid": 0, "target_address": 0} |
| process | exit | {"status": "exited", "exit_status": 0, "signal": null, "return_observed": false, "return_value": null} | {} |
| process | fork | {"status": "child_created", "return_observed": false, "return_value": null} | {"parent_pid": 2282532, "child_pid": 2282661} |
| ptrace | ptrace | {"status": "success", "return_observed": true, "return_value": 0, "errno": null} | {"ptrace_request": 0, "target_pid": 0, "target_address": 0} |
| process | exit | {"status": "exited", "exit_status": 0, "signal": null, "return_observed": false, "return_value": null} | {} |
| process | fork | {"status": "child_created", "return_observed": false, "return_value": null} | {"parent_pid": 2282532, "child_pid": 2282670} |
| ptrace | ptrace | {"status": "success", "return_observed": true, "return_value": 0, "errno": null} | {"ptrace_request": 0, "target_pid": 0, "target_address": 0} |
| process | exit | {"status": "exited", "exit_status": 0, "signal": null, "return_observed": false, "return_value": null} | {} |
| process | fork | {"status": "child_created", "return_observed": false, "return_value": null} | {"parent_pid": 2282532, "child_pid": 2282685} |
| ptrace | ptrace | {"status": "success", "return_observed": true, "return_value": 0, "errno": null} | {"ptrace_request": 0, "target_pid": 0, "target_address": 0} |
| process | exit | {"status": "exited", "exit_status": 0, "signal": null, "return_observed": false, "return_value": null} | {} |
| process | fork | {"status": "child_created", "return_observed": false, "return_value": null} | {"parent_pid": 2282532, "child_pid": 2282686} |
| ptrace | ptrace | {"status": "success", "return_observed": true, "return_value": 0, "errno": null} | {"ptrace_request": 0, "target_pid": 0, "target_address": 0} |
| process | exit | {"status": "exited", "exit_status": 0, "signal": null, "return_observed": false, "return_value": null} | {} |
| process | fork | {"status": "child_created", "return_observed": false, "return_value": null} | {"parent_pid": 2282532, "child_pid": 2282707} |
| ptrace | ptrace | {"status": "success", "return_observed": true, "return_value": 0, "errno": null} | {"ptrace_request": 0, "target_pid": 0, "target_address": 0} |
| process | exit | {"status": "exited", "exit_status": 0, "signal": null, "return_observed": false, "return_value": null} | {} |
| process | fork | {"status": "child_created", "return_observed": false, "return_value": null} | {"parent_pid": 2282532, "child_pid": 2282725} |
| ptrace | ptrace | {"status": "success", "return_observed": true, "return_value": 0, "errno": null} | {"ptrace_request": 0, "target_pid": 0, "target_address": 0} |
| process | exit | {"status": "exited", "exit_status": 0, "signal": null, "return_observed": false, "return_value": null} | {} |
| process | fork | {"status": "child_created", "return_observed": false, "return_value": null} | {"parent_pid": 2282532, "child_pid": 2282732} |
| ptrace | ptrace | {"status": "success", "return_observed": true, "return_value": 0, "errno": null} | {"ptrace_request": 0, "target_pid": 0, "target_address": 0} |
| process | exit | {"status": "exited", "exit_status": 0, "signal": null, "return_observed": false, "return_value": null} | {} |
| process | fork | {"status": "child_created", "return_observed": false, "return_value": null} | {"parent_pid": 2282532, "child_pid": 2282733} |
| ptrace | ptrace | {"status": "success", "return_observed": true, "return_value": 0, "errno": null} | {"ptrace_request": 0, "target_pid": 0, "target_address": 0} |
| process | exit | {"status": "exited", "exit_status": 0, "signal": null, "return_observed": false, "return_value": null} | {} |
| process | fork | {"status": "child_created", "return_observed": false, "return_value": null} | {"parent_pid": 2282532, "child_pid": 2282734} |
| ptrace | ptrace | {"status": "success", "return_observed": true, "return_value": 0, "errno": null} | {"ptrace_request": 0, "target_pid": 0, "target_address": 0} |
| process | exit | {"status": "exited", "exit_status": 0, "signal": null, "return_observed": false, "return_value": null} | {} |
| process | fork | {"status": "child_created", "return_observed": false, "return_value": null} | {"parent_pid": 2282532, "child_pid": 2282735} |
| ptrace | ptrace | {"status": "success", "return_observed": true, "return_value": 0, "errno": null} | {"ptrace_request": 0, "target_pid": 0, "target_address": 0} |
| process | exit | {"status": "exited", "exit_status": 0, "signal": null, "return_observed": false, "return_value": null} | {} |
| process | fork | {"status": "child_created", "return_observed": false, "return_value": null} | {"parent_pid": 2282532, "child_pid": 2282754} |
| ptrace | ptrace | {"status": "success", "return_observed": true, "return_value": 0, "errno": null} | {"ptrace_request": 0, "target_pid": 0, "target_address": 0} |
| process | exit | {"status": "exited", "exit_status": 0, "signal": null, "return_observed": false, "return_value": null} | {} |
| process | fork | {"status": "child_created", "return_observed": false, "return_value": null} | {"parent_pid": 2282532, "child_pid": 2282761} |
| ptrace | ptrace | {"status": "success", "return_observed": true, "return_value": 0, "errno": null} | {"ptrace_request": 0, "target_pid": 0, "target_address": 0} |
| process | exit | {"status": "exited", "exit_status": 0, "signal": null, "return_observed": false, "return_value": null} | {} |

## Process nghi vấn (thứ tự ưu tiên điều tra, không phải kết luận)

| Hạng | Binary | Điểm | Lý do |
|---|---|---|---|
| 1 | "/tmp/sentinel-runtime-attack-blind" | 7 | novel_binary, spawned_children, started_in_window |
| 2 | "/tmp/sentinel-runtime-attack-blind" | 7 | novel_binary, security_operation |
| 3 | "/tmp/sentinel-runtime-attack-blind" | 7 | novel_binary, security_operation |
| 4 | "/tmp/sentinel-runtime-attack-blind" | 7 | novel_binary, security_operation |
| 5 | "/tmp/sentinel-runtime-attack-blind" | 7 | novel_binary, security_operation |

## Đích mạng đang hoạt động (66 lần gửi, lấy mẫu 10 s/socket)

- "[\"10.0.2.119\", 6379]"
- "[\"10.0.2.158\", 40469]"
- "[\"10.0.2.158\", 43365]"
- "[\"10.0.2.158\", 53631]"
- "[\"10.0.2.165\", 55287]"
- "[\"10.0.2.165\", 56405]"
- "[\"10.0.2.165\", 60635]"
- "[\"10.1.16.238\", 33371]"
- "[\"10.1.16.238\", 46287]"
- "[\"10.1.16.238\", 46527]"
- "[\"10.1.16.238\", 48021]"
- "[\"10.1.16.238\", 59461]"
- "[\"10.1.16.239\", 39081]"
- "[\"10.1.16.239\", 47003]"
- "[\"10.1.16.239\", 50471]"
- "[\"10.1.16.239\", 50543]"
- "[\"10.1.16.239\", 54809]"
- "[\"10.1.16.239\", 57887]"
- "[\"10.102.22.84\", 8000]"
- "[\"10.105.36.105\", 8000]"
- "[\"10.109.180.244\", 4317]"
- "[\"10.109.229.136\", 8000]"
- "[\"10.96.0.10\", 53]"
- "[\"127.0.0.1\", 46362]"
- "[\"127.0.0.1\", 46598]"
- "[\"127.0.0.1\", 48484]"
- "[\"127.0.0.1\", 48594]"
- "[\"127.0.0.1\", 48794]"
- "[\"127.0.0.1\", 49300]"
- "[\"127.0.0.1\", 49430]"
- "[\"127.0.0.1\", 49528]"
- "[\"127.0.0.1\", 8000]"

Cây chứa bằng chứng quan sát; chưa phải kết luận nguyên nhân gốc.
