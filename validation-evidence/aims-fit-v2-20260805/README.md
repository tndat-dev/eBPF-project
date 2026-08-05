# AIMS fit-v2 frozen evaluation evidence

Snapshot sao từ control plane ngày 05-08-2026 sau khi blind matrix hoàn tất.
Fit-v2 là candidate bị từ chối promotion; thư mục này không phải model release.

## Nội dung

- `aims-independent-validation-fit-v2.json`: run-02--03, SHA-256
  `c08d5bc35c48799d4963a558f6c60c19314f02619cf4f207e41e51b48b2f8fb7`.
- `aims-blind-normal-test-fit-v2.json`: run-04--05, SHA-256
  `eb1d8b8b2b4424f140d0cdaf6b0ab91e0f37e3d0dad76e4d61f8d83616f6659a`.
- `aims-blind-matrix/report.json`: aggregate 40 workload-trial/200 scenario,
  SHA-256 `b14c3abdab1ac32e8c67f9c359eff3184150bc61c92e6d7b7cf4aac4dc513ea3`.
- `aims-blind-matrix/*/timestamp/report.json`: 40 nested final reports. Không
  copy JSONL syscall/decision thô để giữ bundle gọn.
- `aims-fit-v2-paper-statistics.{json,md}`: derived artifact tái tạo được
  byte-for-byte từ các report trên.

## Tái tạo thống kê

Chạy từ repository root:

```bash
python3 ml-service/paper_statistics.py \
  --normal validation-evidence/aims-fit-v2-20260805/aims-independent-validation-fit-v2.json \
  --normal validation-evidence/aims-fit-v2-20260805/aims-blind-normal-test-fit-v2.json \
  --attack validation-evidence/aims-fit-v2-20260805/aims-blind-matrix/report.json \
  --output /tmp/aims-fit-v2-paper-statistics.json
```

Expected SHA-256:

```text
d88c9984fb1718448bb60d226431fa6e52e77787d3ac899d79303cfe829d1d41  aims-fit-v2-paper-statistics.json
2cbe4929df9a3da9093cd0da0cb064f02fa7c5991ae50dac8aa4a0062d51493a  aims-fit-v2-paper-statistics.md
```

Absolute paths bên trong report là provenance từ author VM. Loader ưu tiên
hash và tự resolve nested report tương đối khi bundle được chuyển máy.
