# testbed — tài sản của cụm thử nghiệm

Những file này không phải code phát hiện, nhưng pipeline hiện hành cần chúng
để tái lập thí nghiệm trên cụm Kubernetes `production` (ứng dụng AIMS).

| File | Dùng ở đâu |
|---|---|
| `traffic/set_aims_traffic_regime.sh` | Đổi chế độ tải normal (steady/toolmix/peak/burst/recovery/idle); gọi bởi `pipeline/matched_traffic.py`, `syscall_study/syscall_capture_campaign.py` |
| `k8s/aims-sentinel-loadgen.yaml`, `k8s/production-loadgens.yaml` | Các Deployment phát tải mà script trên điều khiển |
| `k8s/tetragon-sentinel-pulse-exec-provenance.yaml` | TracingPolicy ghi lại `execve` của binary tấn công để có mốc thời gian kernel độc lập; được băm trong `pipeline/plan_matched_run.py` |
| `attack/runtime_attack_blind_b1.c` | Mã nguồn binary mô phỏng tấn công dùng trong campaign attack/đối chứng |
