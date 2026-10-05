# Projected counters C2 — canary hai worker

**Final safety review amendment 10:02 ICT:** hai timer review đã exit 0.
Source và capture hashes khớp; measured span 899,026 s (.239) / 898,444 s
(.238), trong duration 900 s và slack 2 s. Coverage đạt 15/15 và 19/19 node
keys, không missing/unexpected key. Xem `SAFETY_REVIEW_10.1.16.239.json` và
`SAFETY_REVIEW_10.1.16.238.json`. Không còn review ngầm; không chạy ML,
không automatic promotion. Các checkpoint/lịch bên dưới giữ làm lịch sử.

**Terminal amendment 10:00 ICT:** cả hai collector đã terminal exit 0, full
capture validation valid, raw checksum được kiểm tra lại khớp; .239 có 38.832
row/1.776 snapshot, .238 có 40.075 row/1.775 snapshot. Hard loss/integrity và
cadence violation 0; p99 window-start-to-feature-emit 0,544774/0,542088 s.
Còn chờ safety review tự động duration/source/coverage khoảng 10:01; không
coi capture-valid là ML hoặc operational normal gate PASS.

Run `pulse-projected-counter-c2-20261003T024600Z` trên `10.1.16.239` và
`10.1.16.238`. Start thực tế **09:44:12 ICT ngày 03/10/2026**; timestamp trong
run ID là nhãn đăng ký, không dùng thay START receipt.

Duration đăng ký 900 s, collect-only, không ML, không automatic promotion.
Control collector/resolver giữ active. Source readonly riêng trên worker;
không thay `/opt/sentinel-pulse`, model, policy hoặc AIMS.

Checkpoint 09:48:16 ICT: 480 snapshot/node, availability 1,0, hard counters và
cadence violation 0. Hai unit đang active, chưa terminal. Dự kiến quét lại
full validation và safety review khoảng **10:01 ICT**. Không sửa checkpoint
start thành kết quả pass.

`FROZEN_MODEL_WORKLOAD_KEYS.json` chứa 21 key đọc từ manifest R10-C1 đã freeze.
Expectation mỗi node lấy start metadata giao với danh sách này; phải kiểm tra
union coverage, không tự suy ra expectation từ những row đã quan sát.

Regression 03/10 của main source, lệnh `python -m pytest -q
tests/test_sentinel_pulse*.py`: host **370 passed, 20 subtests passed in 27.49s**;
VM **370 passed, 20 subtests passed in 34.31s**. Kết quả test không thay kết quả
live của hai canary còn đang chạy.

Expectation đã đăng ký: worker3 15 key, worker4 19 key; union kỳ vọng với 16 key
worker1 là 21. Không coi expected union là observed coverage PASS.

Đã mở timer review tự động trên hai worker, lịch SSH xác nhận **10:00:57 và
10:00:58 ICT ngày 03/10**. Unit `sentinel-pulse-projection-review-20261003` dùng
source riêng readonly, hash evaluator và expectation ghi trong `REVIEW_TIMER`
receipts. Nó quét full capture và tạo `SAFETY_REVIEW.json` riêng, không ghi đè,
không triển khai ML. Kiểm tra lại **10:03 ICT**; không cần giữ phiên SSH mở.
