# Cây bằng chứng sau tín hiệu Pulse

Case: `00a0b1e0f074049e0b62676c`. Nguồn: `candidate_alert_preview`.

Workload: `production/inventory-service:app`; node: `k8s-worker3.local`; pod UID: `a786afb7-f9c9-4568-b2ab-1f47f4a968af`.

Đây là bằng chứng tương quan, chưa xác nhận process nào gây anomaly hoặc root cause.

Connect khớp: 119; giữ trong cây: 119.

| Loại | Bằng chứng |
|---|---|
| process | binary=/usr/local/bin/uvicorn; pid=1273229; exec_id=azhzLXdvcmtlcjMubG9jYWw6NDA1Mjg5MTEzMDU5MTkxODoxMjczMjI5 |
| process_parent | binary=/usr/bin/containerd-shim-runc-v2; pid=1268830; exec_id=azhzLXdvcmtlcjMubG9jYWw6NDA1Mjg1NTQyNzkyMDU0NzoxMjY4ODMw |
| Đích connect (kết quả theo từng event) | 10.96.0.10:53; K8s={'kind': 'Service', 'namespace': 'kube-system', 'name': 'kube-dns', 'uid': 'f57e394f-78cc-4b99-b1dd-2476dc2504a3'} |
| Đích connect (kết quả theo từng event) | 10.109.129.182:5432; K8s={'kind': 'Service', 'namespace': 'production', 'name': 'aims-postgres-cnpg-rw', 'uid': '5f09aa86-f08a-4cc3-a8aa-6a85a9a7e6d8'} |
| process | binary=/usr/local/bin/python; pid=2350899; exec_id=azhzLXdvcmtlcjMubG9jYWw6NDY0Mzg0NTYzMTc5NjkwOToyMzUwODk5 |
| Đích connect (kết quả theo từng event) | 127.0.0.1:8000; K8s=None |
| process | binary=/usr/local/bin/python; pid=2351622; exec_id=azhzLXdvcmtlcjMubG9jYWw6NDY0Mzg1MDY0NDc2OTk2NToyMzUxNjIy |
| process_parent | binary=/usr/bin/runc; pid=2351591; exec_id=azhzLXdvcmtlcjMubG9jYWw6NDY0Mzg1MDU3NTgyMzY0MjoyMzUxNTkx |
| process | binary=/usr/local/bin/python; pid=2352319; exec_id=azhzLXdvcmtlcjMubG9jYWw6NDY0Mzg1NDk0ODY3NDM0OToyMzUyMzE5 |
| process | binary=/usr/local/bin/python; pid=2352384; exec_id=azhzLXdvcmtlcjMubG9jYWw6NDY0Mzg1NTY0NTYyMDk2MjoyMzUyMzg0 |
| process | binary=/usr/local/bin/python; pid=2353164; exec_id=azhzLXdvcmtlcjMubG9jYWw6NDY0Mzg2MDYzMzA2NjIyODoyMzUzMTY0 |
| process | binary=/usr/local/bin/python; pid=2353868; exec_id=azhzLXdvcmtlcjMubG9jYWw6NDY0Mzg2NTYzODk3NTc1NToyMzUzODY4 |
| Đích connect (kết quả theo từng event) | 10.0.2.48:9093; K8s={'kind': 'Pod', 'namespace': 'production', 'name': 'aims-kafka-dual-role-2', 'uid': '69c4a376-76f4-41a1-9898-ee1f3417e754', 'service': 'aims-kafka-kafka-brokers'} |
| Đích connect (kết quả theo từng event) | <nil>:None; K8s=None |
| process | binary=/usr/local/bin/python; pid=2354567; exec_id=azhzLXdvcmtlcjMubG9jYWw6NDY0Mzg2OTk0ODQ4NjYyMzoyMzU0NTY3 |
| process_parent | binary=/usr/bin/runc; pid=2354555; exec_id=azhzLXdvcmtlcjMubG9jYWw6NDY0Mzg2OTg3Njk4NDg3OToyMzU0NTU1 |
| process | binary=/usr/local/bin/python; pid=2354660; exec_id=azhzLXdvcmtlcjMubG9jYWw6NDY0Mzg3MDY0MTExNzMxODoyMzU0NjYw |
| process | binary=None; pid=None; exec_id=azhzLXdvcmtlcjMubG9jYWw6NDA1Mjg1NTQxNjI4NDIwMjoxMjY4ODIy |
| Đích connect (kết quả theo từng event) | 10.0.4.17:9093; K8s={'kind': 'Pod', 'namespace': 'production', 'name': 'aims-kafka-dual-role-1', 'uid': 'a0bafbf3-4b01-457c-9c9e-f6a39365fc5b', 'service': 'aims-kafka-kafka-brokers'} |
| Đích connect (kết quả theo từng event) | 10.1.16.238:44963; K8s={'kind': 'Pod', 'namespace': 'monitoring', 'name': 'monitoring-prometheus-node-exporter-5t4tl', 'uid': 'ebca49f1-acab-4346-9bfb-fbe3bafb4b5b', 'service': 'monitoring-prometheus-node-exporter'} |
| Đích connect (kết quả theo từng event) | 127.0.0.1:51456; K8s=None |
| Đích connect (kết quả theo từng event) | 10.0.5.25:50739; K8s={'kind': 'Pod', 'namespace': 'production', 'name': 'aims-waypoint-6d558c5d7c-sctgm', 'uid': '66451426-5f89-4092-ae1e-b0f8f8c80eb1', 'service': 'aims-waypoint'} |
| Đích connect (kết quả theo từng event) | 10.0.5.154:9093; K8s={'kind': 'Pod', 'namespace': 'production', 'name': 'aims-kafka-dual-role-0', 'uid': 'c4530bcc-c897-499c-9dd7-6950ef6ffcec', 'service': 'aims-kafka-kafka-brokers'} |
| Đích connect (kết quả theo từng event) | 10.1.16.238:48913; K8s={'kind': 'Pod', 'namespace': 'monitoring', 'name': 'monitoring-prometheus-node-exporter-5t4tl', 'uid': 'ebca49f1-acab-4346-9bfb-fbe3bafb4b5b', 'service': 'monitoring-prometheus-node-exporter'} |
| Đích connect (kết quả theo từng event) | 10.1.16.237:40341; K8s={'kind': 'Pod', 'namespace': 'monitoring', 'name': 'monitoring-prometheus-node-exporter-p7sxh', 'uid': '76f95f68-69a3-4d99-8e76-64d3887afe10', 'service': 'monitoring-prometheus-node-exporter'} |
| Đích connect (kết quả theo từng event) | 10.1.16.237:49081; K8s={'kind': 'Pod', 'namespace': 'monitoring', 'name': 'monitoring-prometheus-node-exporter-p7sxh', 'uid': '76f95f68-69a3-4d99-8e76-64d3887afe10', 'service': 'monitoring-prometheus-node-exporter'} |
| Đích connect (kết quả theo từng event) | 127.0.0.1:51692; K8s=None |
| Đích connect (kết quả theo từng event) | 10.109.180.244:4317; K8s={'kind': 'Service', 'namespace': 'observability', 'name': 'otel-collector-collector', 'uid': 'a62b5cc8-87f0-41d7-8a09-48f263848993'} |
| Đích connect (kết quả theo từng event) | 127.0.0.1:54182; K8s=None |
| Đích connect (kết quả theo từng event) | 127.0.0.1:54222; K8s=None |
| Đích connect (kết quả theo từng event) | 10.1.16.238:55169; K8s={'kind': 'Pod', 'namespace': 'monitoring', 'name': 'monitoring-prometheus-node-exporter-5t4tl', 'uid': 'ebca49f1-acab-4346-9bfb-fbe3bafb4b5b', 'service': 'monitoring-prometheus-node-exporter'} |
| Đích connect (kết quả theo từng event) | 10.0.5.25:47753; K8s={'kind': 'Pod', 'namespace': 'production', 'name': 'aims-waypoint-6d558c5d7c-sctgm', 'uid': '66451426-5f89-4092-ae1e-b0f8f8c80eb1', 'service': 'aims-waypoint'} |
| Đích connect (kết quả theo từng event) | 10.1.16.237:53873; K8s={'kind': 'Pod', 'namespace': 'monitoring', 'name': 'monitoring-prometheus-node-exporter-p7sxh', 'uid': '76f95f68-69a3-4d99-8e76-64d3887afe10', 'service': 'monitoring-prometheus-node-exporter'} |
| Đích connect (kết quả theo từng event) | 127.0.0.1:54432; K8s=None |
| Đích connect (kết quả theo từng event) | 10.0.5.25:52211; K8s={'kind': 'Pod', 'namespace': 'production', 'name': 'aims-waypoint-6d558c5d7c-sctgm', 'uid': '66451426-5f89-4092-ae1e-b0f8f8c80eb1', 'service': 'aims-waypoint'} |
| Đích connect (kết quả theo từng event) | 127.0.0.1:34388; K8s=None |
| Đích connect (kết quả theo từng event) | 10.1.16.238:39461; K8s={'kind': 'Pod', 'namespace': 'monitoring', 'name': 'monitoring-prometheus-node-exporter-5t4tl', 'uid': 'ebca49f1-acab-4346-9bfb-fbe3bafb4b5b', 'service': 'monitoring-prometheus-node-exporter'} |
| Đích connect (kết quả theo từng event) | 127.0.0.1:34590; K8s=None |
| Đích connect (kết quả theo từng event) | 127.0.0.1:34632; K8s=None |
| Đích connect (kết quả theo từng event) | 10.1.16.238:59901; K8s={'kind': 'Pod', 'namespace': 'monitoring', 'name': 'monitoring-prometheus-node-exporter-5t4tl', 'uid': 'ebca49f1-acab-4346-9bfb-fbe3bafb4b5b', 'service': 'monitoring-prometheus-node-exporter'} |

## Phạm vi quan sát

```json
{
  "inventory_at": 1792701836.551934,
  "inventory_age_seconds": 43.91945433616638,
  "pod_name": "inventory-service-695bf6f445-ctv74",
  "connect_policy_selected": true,
  "connect_policy": "sentinel-rca-runtime-v1",
  "subscription_started_at": 1792701539.1337283,
  "subscription_started_before_pre_window": true,
  "transport_loss": "not_measured_no_exact_event_completeness_guarantee",
  "subscriber_lag_seconds": 0.2787356376647949,
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
  "lifecycle_subscription_started_at": 1792701444.9165325,
  "last_runtime_event_received_at": 1792701880.468217
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
| process | exit | {"status": "exited", "exit_status": 0, "signal": null, "return_observed": false, "return_value": null} | {} |
| process | exec | {"status": "executed", "return_observed": false, "return_value": null} | {} |
| process | exit | {"status": "exited", "exit_status": 0, "signal": null, "return_observed": false, "return_value": null} | {} |
| process | exec | {"status": "executed", "return_observed": false, "return_value": null} | {} |
| process | exit | {"status": "exited", "exit_status": 0, "signal": null, "return_observed": false, "return_value": null} | {} |
| process | exec | {"status": "executed", "return_observed": false, "return_value": null} | {} |
| process | exit | {"status": "exited", "exit_status": 0, "signal": null, "return_observed": false, "return_value": null} | {} |
| process | exec | {"status": "executed", "return_observed": false, "return_value": null} | {} |
| process | exit | {"status": "exited", "exit_status": 0, "signal": null, "return_observed": false, "return_value": null} | {} |

## Process nghi vấn (thứ tự ưu tiên điều tra, không phải kết luận)

| Hạng | Binary | Điểm | Lý do |
|---|---|---|---|
| 1 | "/usr/local/bin/python" | 2 | started_in_window |
| 2 | "/usr/local/bin/python" | 2 | started_in_window |
| 3 | "/usr/local/bin/python" | 2 | started_in_window |
| 4 | "/usr/local/bin/python" | 2 | started_in_window |
| 5 | "/usr/local/bin/python" | 2 | started_in_window |

## Đích mạng đang hoạt động (148 lần gửi, lấy mẫu 10 s/socket)

- "[\"10.0.2.48\", 9093]"
- "[\"10.0.4.17\", 9093]"
- "[\"10.0.5.154\", 9093]"
- "[\"10.0.5.25\", 47753]"
- "[\"10.0.5.25\", 50739]"
- "[\"10.0.5.25\", 52211]"
- "[\"10.1.16.237\", 40341]"
- "[\"10.1.16.237\", 49081]"
- "[\"10.1.16.237\", 53873]"
- "[\"10.1.16.238\", 39461]"
- "[\"10.1.16.238\", 44963]"
- "[\"10.1.16.238\", 48913]"
- "[\"10.1.16.238\", 55169]"
- "[\"10.1.16.238\", 59901]"
- "[\"10.109.129.182\", 5432]"
- "[\"10.109.180.244\", 4317]"
- "[\"10.96.0.10\", 53]"
- "[\"127.0.0.1\", 34388]"
- "[\"127.0.0.1\", 34590]"
- "[\"127.0.0.1\", 34632]"
- "[\"127.0.0.1\", 51456]"
- "[\"127.0.0.1\", 51692]"
- "[\"127.0.0.1\", 54182]"
- "[\"127.0.0.1\", 54222]"
- "[\"127.0.0.1\", 54432]"
- "[\"127.0.0.1\", 8000]"
- "[\"<nil>\", null]"

Cây chứa bằng chứng quan sát; chưa phải kết luận nguyên nhân gốc.
