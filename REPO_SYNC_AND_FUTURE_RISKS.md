# Kiểm tra đồng bộ host–VM và rủi ro cần cải thiện

Ngày kiểm tra: **15/10/2026** (Asia/Bangkok). Phạm vi là repo eBPF/Sentinel Pulse,
checkout vận hành và trạng thái cluster liên quan trực tiếp đến candidate.
Đây là snapshot hiện hành; không khẳng định mọi clone hoặc raw data đều đã
đồng bộ.

## Kết luận đồng bộ

| Vị trí | Trạng thái quan sát | Ý nghĩa |
|---|---|---|
| Host `/home/tndat/Downloads/eBPF-project` | Branch `experiment/syscall-id-histogram-pilot`, commit `87a38be`; `origin` cùng SHA; working tree sạch trước cập nhật audit | Revision đã push, nguồn Git hiện hành |
| VM `/home/dat/eBPF-project-host-sync-67b9585` | Worktree riêng ở commit `87a38be`, sạch; full test pass | Mirror an toàn của host branch, tạo riêng để không đè checkout cũ |
| VM `/home/dat/eBPF-project` | Branch `main`, commit `ca682ef`, **37 mục dirty** | Chưa đồng bộ; không pull/reset/stash/clean và không ghi đè |
| Runtime frozen trên NFS | `/mnt/sentinel-pulse-archive/runtime-2c1a72d-20261013/source`, commit `2c1a72d`, sạch | Checkout vận hành tách biệt; không thay bằng Git head mới nếu chưa đăng ký lại candidate |

Host và worktree mirror VM cùng commit nên nội dung **tracked** giống hệt theo
Git. Việc đó không đồng bộ file untracked/ignored, raw telemetry, model output
hoặc checkout cũ. Checkout `/home/dat/eBPF-project` vẫn ở `ca682ef`, cũ hơn
nhánh host 167 commit tại lần so sánh, có 17 file tracked sửa đổi và 20 mục
untracked (4 source/test mới cùng evidence lịch sử). Không file nào bị xóa hoặc
ghi đè. Trong 19 source/test thay đổi được so SHA, 10 file byte-identical với
host; 9 file khác phiên bản nhưng các chức năng revision provenance, contract
v3, observer và test đã có bản tương ứng trong host branch. Hai báo cáo cũ và
raw evidence của checkout này chưa được đồng bộ; không thể tuyên bố *mọi file*
hay mọi clone đã đồng bộ. Candidate runtime tiếp tục bind commit `2c1a72d` và
manifest riêng; Git head mới không tự động trở thành runtime đã deploy.

Các commit đã push trong nhánh host: `ce45c27` (pacing C7), `f5ef974` (link
tài liệu), `67b9585` (canary/review và C6), `703bb73` (status/audit),
`87a38be` (audit mirror). Không stage đại trà raw campaign.

## Kiểm chứng code và môi trường

- VM worktree tại `67b9585`: **1.235 passed**, 20 subtests passed, 2 cảnh báo
  deprecation; pytest dùng `/home/dat/ml-venv`, hoàn thành trong 92,43 giây.
- VM checkout cũ `ca682ef` với các sửa đổi cục bộ: **576 passed**, 2 cảnh báo
  deprecation trong 85,43 giây. Đây là test collection của nhánh cũ, không
  thay thế bộ test đầy đủ ở host branch; test không làm mất 37 thay đổi cục bộ.
- Host report gần nhất: **1.194 passed, 7 skipped**, 20 subtests. Host venv
  thiếu `torch`, trong khi root `requirements.txt` khai báo `torch>=2.2`; do đó
  một số test ML bị bỏ qua và coverage không tương đương VM. Host có Python
  3.12.3, pytest 9.1.1, NumPy 2.5.2, scikit-learn 1.9.0.
- `compileall`, `bash -n` và kiểm tra link Markdown đã qua; lần quét link gần
  nhất không còn link nội bộ gãy. Quét các pattern secret phổ biến không tìm
  private key, GitHub token hay access-key literal trong source đã quét. Đây
  là heuristic, không thay thế secret scanner chuyên dụng.
- Repo có **2.044 tracked files**, trong đó 1.364 nằm dưới
  `validation-evidence/`; kích thước worktree khoảng **1,4 GiB**, phần lớn là
  evidence/raw. `.gitignore` loại một số JSONL/pickle lớn, nhưng các lần commit
  evidence vẫn cần allow-list và kiểm tra dung lượng.

Test count không thể so như regression tuyệt đối: commit giống nhau nhưng môi
trường Python khác; VM có Torch còn host venv thiếu Torch. Root
`requirements.txt` chủ yếu dùng lower bounds, chưa khóa cả môi trường test.
`sentinel_pulse/requirements-lock.txt` chỉ khóa môi trường candidate cụ thể,
không phải lock đầy đủ toàn repo. Nên tái lập CI trong container/venv khóa rõ
Python và dependencies, đồng thời fail nếu test quan trọng bị skip.

## Candidate Pulse và trạng thái cluster

- Candidate manifest: `747c4eed2a9a74321d0ac3b716c201c449f946665252baa1ca314b1f18278a08`;
  policy preview: `fd0be94a4ca7f2cd64b97bf5c7dc074763405f821ab346e8e19bb5975d10f401`.
- Normal A1: 24 giờ mỗi worker; **33.148.914 decision**, **11.388.831 scored**,
  **30.412 preview-positive**. Tỷ lệ raw là **0,267% scored rows** (window có
  chồng lấn); nhãn chưa adjudicate nên không gọi là FPR. Decision ít hơn
  capture **565 dòng**, alignment chưa chứng minh.
- B3: 30 phút/node; p99 feature-window-end-to-score `.237/.238/.239` là
  **0,516/0,555/0,220 giây**. Không phải kernel-to-preview/alert hoặc quality
  metric; `.238` giữ 3 cadence gaps. B3/B4 hiện `inactive/dead`.
- SSH/`kubectl` kiểm tra ngày 15/10: **6/6 node Ready, v1.34.10**, Ubuntu
  24.04/kernel `6.8.0-138-generic`; Tetragon **6 agent 2/2 Running** và operator
  1/1 Running. Ba AIMS load-generator hiện 1/1 Ready. Policy
  `sentinel-pulse-exec-provenance` đã được xác nhận enabled trên đủ agent trong
  lần kiểm tra trước.
- Các service `sentinel-pulse-observation-campaign`, `...-attack` và
  `...-normal-control` báo `Result=success`, `ActiveState=active`,
  `SubState=exited`: đều là oneshot đã thoát, không phải soak/attack đang chạy.
  Không thấy unit/candidate scorer 500 ms hiện hành hoặc tiến trình Pulse live;
  unit attack 500 ms được liệt kê là các pilot cũ ở trạng thái failed. Vì vậy
  chưa có blind attack evaluation mới cho candidate hiện hành.
- `sentinel-pulse-observation-attack.service` thoát `Result=success` nhưng dùng
  source/config C2 cũ. Nó **không** tạo attack matrix cho idle-aware candidate
  hiện hành. Candidate này chưa có confusion matrix, precision, recall, FPR
  hay kernel-to-preview đo live.
- Syscall A2 terminal `completed_exploratory_addition_study`: **105/105 model**,
  `unknowns={}`; `fresh_blind_complete=false`, precision/recall/FPR và
  kernel-to-alert null. A2 dùng C3 đã lộ, histogram entry-only 1 giây; không
  phải blind comparison và không cần chờ tiếp.

## Điểm yếu và thứ tự cải thiện

| Mức | Điểm yếu đã thấy | Hướng cải thiện |
|---|---|---|
| Cao | Candidate chỉ chạy shadow/preview; chưa có attack/control matrix gắn với model/policy hiện hành | Run mới: scorer idle-aware 500 ms đồng thời với blind attack; ghép workload, pod UID, container, revision và cgroup; lưu preview latency, miss, unknown, normal controls riêng. Không gọi preview là alert serving |
| Cao | A1 có 30.412 preview-positive chờ adjudication; chênh 565 capture/decision | Đối soát theo identity/window/source offset; chia interval 30 s cùng health/traffic context; giữ positive và unknown đến khi có căn cứ |
| Cao | Không có candidate 500 ms đang chạy; baseline collector là 1 s | Bật bounded canary sau khi có quyền root hợp lệ, preregister budget/rollback và xác minh source/model binding; đo lại cadence thật |
| Cao | 18 file trong `sentinel_pulse`/`scripts` dùng `StrictHostKeyChecking=no` | Chuyển transport sang known-hosts pinning và `StrictHostKeyChecking=yes`; cấp SSH key riêng hạn quyền, kiểm thử bootstrap host-key thay vì tắt xác minh |
| Cao | Có 7 vị trí `pickle.load`; SHA manifest không bảo vệ nếu cùng lúc thay artifact và manifest | Chỉ load từ root tin cậy; ký manifest bằng khóa ngoài data store hoặc chuyển định dạng; không nhận pickle chưa xác thực |
| Trung bình | Host/mirror đã cùng revision, nhưng checkout `main` trên VM cũ hơn 167 commit, có 37 mục dirty; report/raw evidence chưa mirror | Tiếp tục dùng worktree branch rõ ràng; review rồi cherry-pick/port có chọn lọc nếu cần; không reset hoặc xóa tự động |
| Trung bình | Dependency test/train chưa khóa thống nhất; host thiếu Torch nên bỏ qua test ML | Lock đầy đủ toàn môi trường và CI chuẩn; test quan trọng không được silently skip |
| Trung bình | Repo ~1,4 GiB với nhiều evidence, dễ commit raw hoặc làm cạn storage | Manifest/hash/receipt ở Git; raw ở NFS/object store có quota/retention/backup; stage allow-list |
| Trung bình | Nhiều systemd unit legacy `failed`/`active,exited`, dễ nhầm với process sống | Status checker đọc `Result`, terminal, PID và timestamp; chỉ retire sau owner/source/output audit |
| Nghiên cứu | C2 19-key và idle-aware 21-key khác nhau; một số `pod-slice` không có model; A2 không cùng observable Pulse | Coverage theo key; C2/A2 chỉ exploratory; blind study mới dùng 500 ms/249 chiều và support/policy đồng nhất |

SSH login hoạt động, nhưng trong lượt kiểm tra này `sudo` từ user `dat` từ chối
password SSH. Vì vậy không tự khởi động B4 hay thay loader root-owned; cần
credential sudo hợp lệ hoặc thao tác quản trị đã xác thực. Đây là giới hạn xác
thực, không phải lỗi SSH; không dùng privileged pod để lách quyền.

## Kết luận

**Host và worktree mirror VM đã đồng bộ ở `87a38be`; checkout VM cũ chưa đồng bộ
và được giữ nguyên.** Test checkout VM cũ cũng pass, nhưng chỉ 576 test thuộc
revision cũ; host/mirror mới hơn có coverage lớn hơn. A1/B3 cung cấp
normal/timing evidence, không phải confusion matrix. A2 đã kết thúc
exploratory; Pulse tiếp tục độc lập với nó. Để có matrix candidate hợp lệ:
adjudicate normal exposure, rồi triển khai preview scorer 500 ms cùng blind
attack mới, ghép identity/revision và Tetragon kernel timestamp, kèm paired
normal controls. Chưa thực hiện bước này vì hiện không có scorer/loader live;
không dùng kết quả C2 cũ làm kết quả candidate mới.
