# Sentinel Pulse — phát hiện hành vi bất thường của container bằng eBPF

Đồ án xây dựng một hệ thống theo dõi các container trên Kubernetes ở mức kernel:
một chương trình eBPF đếm các lời gọi hệ thống (syscall) của từng container, cứ
0,5 giây gom thành một vector đặc trưng, rồi một mô hình học máy đã huấn luyện
trên dữ liệu bình thường chấm điểm xem cửa sổ đó có "lạ" hay không. Khi có tín
hiệu, một dịch vụ riêng ghép các sự kiện chi tiết (process, file, kết nối mạng)
thành đồ thị bằng chứng để người vận hành điều tra.

Mục tiêu: phát hiện trong khoảng 1–2 giây, precision và recall cao, số cảnh báo
nhầm trên dữ liệu bình thường ở mức chấp nhận được (không đòi hỏi bằng 0).
Hệ thống hiện chạy ở chế độ **shadow**: chỉ ghi "cảnh báo thử" để đánh giá, chưa
gửi cảnh báo thật hay tự cách ly pod.

## Đọc ở đâu

| Tài liệu | Nội dung |
|---|---|
| [docs/STATUS.md](docs/STATUS.md) | Trạng thái hiện tại, kết quả, thuật ngữ, cách kiểm tra |
| [TODO.md](TODO.md) | Việc đã xong và việc tiếp theo theo mức ưu tiên |
| [sentinel_pulse/README.md](sentinel_pulse/README.md) | Bản đồ mã nguồn |
| [testbed/README.md](testbed/README.md) | Tài sản của cụm thử nghiệm (tải, binary tấn công, policy) |
| [DOCS_INDEX.md](DOCS_INDEX.md) | Danh mục tài liệu, kể cả báo cáo chi tiết cũ |

## Cấu trúc repo

```
sentinel_pulse/        mã nguồn (collector, detector, pipeline, attack, syscall_study, rca)
tests/                 kiểm thử (pytest)
testbed/               script phát tải, mã binary tấn công, manifest K8s của cụm thử nghiệm
scripts/               công cụ SSH vào cụm và kiểm kê tài nguyên
validation-evidence/   biên nhận và kết quả thí nghiệm (không sửa nội dung đã niêm phong)
docs/                  báo cáo trạng thái
```

## Chạy test

```bash
python3 -m venv ~/.venvs/sentinel-pulse
~/.venvs/sentinel-pulse/bin/pip install -r sentinel_pulse/requirements-lock.txt pytest
~/.venvs/sentinel-pulse/bin/python -m pytest -q -p no:cacheprovider tests
```

## Cụm thử nghiệm

6 node Ubuntu x86-64: master `10.1.16.234` (k8s-master), `.235`, `.236`; worker
`.237` (worker1), `.238` (worker4), `.239` (worker3). Kết quả lớn nằm trên NFS
`/mnt/sentinel-pulse-archive`. `scripts/ssh_lab.py` là helper SSH (đọc mật khẩu
từ biến môi trường `LAB_SSH_PASSWORD`).

Code của các thế hệ thí nghiệm trước (detector v8/AIMS, agent_runtime, lifecycle
500 ms B1–B7, recovery coordinator…) đã được gỡ khỏi nhánh hiện hành; toàn bộ cây
cũ còn ở tag Git `archive/pre-refactor-20261018`.
