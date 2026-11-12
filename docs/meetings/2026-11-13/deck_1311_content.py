# Content of the 13/11 deck: the current ML model explained step by step. Numbers from validation-evidence/results-20261107..20261112
# (token-explain for the worked examples) and notes/WORKLOG.md.

slide('Cấu trúc bài trình bày (tiến độ 06/11 – 13/11/2026)', notes=[
    'Kết quả chính của tuần',
    'Kiến trúc hệ thống, probe eBPF và code của từng phần',
    'Mô hình ML hiện tại lidds-ml-v5, giải thích từng bước: token, chuỗi theo thread, xác suất Witten–Bell, điểm cửa sổ, ngưỡng, quyết định',
    'Ví dụ thật trên LID-DS 2021: từng con số của một cảnh báo',
    'Mô hình trên cụm, chi phí',
    'Kiểm từng lựa chọn của mô hình; mô hình làm được gì và không làm được gì; nghiên cứu các điểm yếu còn lại (12–13/11)',
    'Kết quả dataset và live, binary vô hại, đường cảnh báo và RCA',
    'Tiến độ, việc tiếp theo, câu hỏi cho thầy',
], note_size=18)

slide('Kết quả chính', [
    ['', 'Recall', 'Báo nhầm / control', 'p95'],
    ['LID-DS 2021 official (lidds-ml-v5)', '97,40% (1.238/1.271)', '0,33% (26/7.938)', '1,47 s'],
    ['Live blind pulse-live-v5-1110, tập chính', '314/314', '0/314', '0,49 s (0,68 s tới Alertmanager)'],
    ['Kỳ vọng', '≥ 95%', '≤ 5% (control)', '≤ 3 s'],
], [3.4, 2.0, 2.0, 2.6], notes=[
    '**Mô hình:** mô hình ngôn ngữ thống kê trên chuỗi syscall, chỉ học từ normal, không nhãn tấn công, không luật.',
    '**Mỗi lựa chọn thiết kế đã được kiểm lại** bằng protocol đăng ký trước: chỉ 5/39 syscall có hook là cần; tham số phẳng quanh bộ đang dùng; Gumbel là quy tắc ngưỡng tốt nhất đã thử.',
    '**Giới hạn:** mô hình đo độ lạ, không đo ý đồ: binary vô hại bị gắn cờ 314/314, lệnh quản trị 419/436; tấn công chỉ dùng chuỗi đã thấy 0/544 (mô phỏng).',
])

slide('Mô hình ML: bài toán và ý tưởng', notes=[
    '**Bài toán:** mỗi 0,5 s trả lời "container này có vừa làm điều mà normal của nó hầu như không bao giờ làm không?". Không được thấy tấn công khi học; phải bắt tấn công chưa biết, báo trong vài giây.',
    '**Ý tưởng:** coi syscall như một ngôn ngữ. Mỗi lần syscall trả về là một "từ" (token); chuỗi token của một thread là một "câu". Mô hình học từ normal xác suất của từ tiếp theo khi biết 3 từ trước nó (mô hình n-gram).',
    '**Báo khi một chuỗi rất bất ngờ** (xác suất rất thấp) với normal của chính workload đó.',
    '**Thống kê thuần:** học chỉ là đếm, không mạng nơ-ron, không gradient. LSTM lớn đã thử, không hơn 4-gram.',
    '**Ba quan sát dẫn tới thiết kế:** (1) exploit thường giữ tập syscall, chỉ đổi đường dẫn, số byte, mã lỗi; (2) thứ tự các bước chỉ có nghĩa trong cùng thread; (3) nhiều exploit chỉ lộ trong một cửa sổ, và lộ sớm.',
], note_size=17)

slide('Sáu bước của mô hình', [
    ['Bước', 'Vào', 'Ra', 'Ở đâu trên cụm'],
    ['1. Token', 'Một lần syscall trả về', 'Một token 32 bit', 'Kernel (probe eBPF)'],
    ['2. Chuỗi', 'Token của một thread', '4-gram: token và 3 token trước nó', 'Kernel đếm (cgroup, cửa sổ 0,5 s, 4-gram)'],
    ['3. Xác suất', '4-gram', 'P(token | 3 token trước)', 'Worker trên mỗi node'],
    ['4. Điểm', 'Mọi 4-gram của cửa sổ', 'Trung bình 10 độ bất ngờ lớn nhất', 'Worker'],
    ['5. Ngưỡng', 'Điểm của normal khi học', 'Một ngưỡng cho mỗi workload', 'Lúc fit, trước lượt chạy'],
    ['6. Quyết định', 'Điểm và ngưỡng', 'Báo nếu điểm > ngưỡng', 'Worker → bridge → Alertmanager'],
], [1.6, 2.4, 3.2, 3.2], size=14, notes=[
    '**Cùng một code ở hai nơi:** token_model.py trên cụm, lidds_ml_tokens.py trên dataset; cho cùng xác suất tới sai số 10⁻¹², có test kiểm.',
])

slide('Code của từng bước', [
    ['Bước', 'Trên cụm (kernel, worker)', 'Trên dataset (LID-DS 2021)'],
    ['1. Token', 'ebpf/pulse_tokens.bpf.h: pulse_tok_return; ebpf/pulse_counter.bpf.c: pulse_record_call; ebpf/pulse_token_ids.h', 'lidds_ml_tokens.py: token(); lidds_ml_token_alphabets.py: ALPHABETS'],
    ['2. Chuỗi', 'pulse_tokens.bpf.h: pulse_tok_emit (map pulse_grams); pulse_counter_loader.c: drain_grams; collector/token_capture.py', 'lidds_ml_tokens.py: window_tokens()'],
    ['3. Xác suất', 'detector/token_model.py: CountTokenLM.learn, base, prob', 'lidds_ml_tokens.py: TokenLM'],
    ['4. Điểm', 'token_model.py: CountTokenLM.window_score', 'lidds_ml_tokens.py: window_scores()'],
    ['5. Ngưỡng', 'scripts/analysis/token_branch_fit.py: crossfit_one, fit_crossfit, trimmed_gumbel', 'lidds_ml_token_crossfit.py; lidds_ml_v4.py; lidds_ml_v2.py: gumbel, threshold'],
    ['6. Quyết định', 'token_model.py: TokenBranch.score; pipeline/matched_worker.py; ops/alert_bridge.py', 'lidds_ml_v2.py: rows, score; lidds_ml_v5.py'],
], [1.3, 5.0, 3.7], size=12, notes=[
    'Đường dẫn trên cụm tính từ sentinel_pulse/ (trừ scripts/); đường dẫn dataset nằm trong scripts/analysis/.',
])

slide('Kiến trúc hệ thống', notes=[
    '**Mỗi worker:** probe eBPF dựng token, đếm 4-gram; loader đọc cửa sổ đã đóng mỗi 0,5 s; worker chấm điểm và ghi decision. **Master:** bridge → Alertmanager → RCA. Mô hình học offline từ normal của cụm trước mỗi lượt.',
], note_size=13, img='/tmp/claude-1000/-home-tndat-Downloads-eBPF-project/d1d13a88-05e8-4b39-9713-6ed9238ff484/scratchpad/fig/overview.png')

slide('Code của các thành phần', [
    ['Thành phần', 'Code'],
    ['Probe eBPF', 'sentinel_pulse/ebpf/pulse_counter.bpf.c, pulse_tokens.bpf.h, pulse_token_ids.h (make tokens)'],
    ['Loader', 'sentinel_pulse/ebpf/pulse_counter_loader.c'],
    ['Resolver (pod, cgroup, workload)', 'sentinel_pulse/collector/cgroup_resolver.py'],
    ['Worker chấm điểm', 'sentinel_pulse/pipeline/matched_worker.py, detector/token_model.py, collector/token_capture.py'],
    ['Bridge cảnh báo', 'sentinel_pulse/ops/alert_bridge.py'],
    ['RCA', 'sentinel_pulse/rca/service.py, ranking.py, tree.py, runtime_events.py'],
    ['Học mô hình trên cụm', 'scripts/analysis/token_branch_fit.py'],
    ['Dựng và chạy một lượt', 'sentinel_pulse/pipeline/plan_matched_run.py, scripts/launch_run.sh'],
    ['Campaign tấn công và đối chứng', 'sentinel_pulse/attack/preview_campaign.py'],
    ['Phân tích lượt live', 'scripts/analysis/pulse_live_v4.py'],
], [3.0, 7.0], size=13)

slide('Bước 1: từ syscall thành token (bảng chữ select1f)', [
    ['Thứ tự', 'Trường hợp', 'Token', 'Ví dụ'],
    ['1', 'Một trong 27 syscall giữ mã lỗi, trả về lỗi', 'tên!mã lỗi', 'openat!ENOENT'],
    ['2', 'Mở file thành công', 'tên:chế độ:thư mục đầu', 'openat:r:/etc'],
    ['3', 'Đọc hoặc ghi thành công n byte', 'tên#⌊log₂ n⌋ (tối đa 15)', 'read 4.096 byte → read#12'],
    ['4', 'Mọi trường hợp khác', 'chỉ tên', 'getpid'],
], [1.0, 3.6, 2.8, 2.6], size=15, notes=[
    '**Cỡ là cỡ thật sự trả về:** read#3 = 8–15 byte, write#4 = 16–31 byte, writev#14 = 16–32 KB.',
    '**Thư mục đầu:** thành phần đầu của đường dẫn tuyệt đối (/etc, /tmp, /app); "/" nếu file ở gốc, "rel" nếu đường dẫn tương đối.',
    '**Mỗi quy tắc nhắm một loại thông tin mà exploit đổi:** đường dẫn ra ngoài thư mục quen (ZipSlip, CVE-2019-5418), cỡ đọc ghi bất thường (Heartbleed), mã lỗi.',
    '**Trong kernel:** số syscall ở bit 23–31, loại token ở bit 21–22, chi tiết ở các bit còn lại (mã lỗi, nhóm cỡ, cờ ghi cùng mã băm FNV-1a của thư mục).',
], note_size=14)

slide('select1f và probe1f là gì', notes=[
    '**Bảng chữ** = bộ quy tắc biến một lần syscall thành token. Tên ghép từ các lựa chọn:',
    '**select:** chỉ 27 syscall được chọn giữ mã lỗi (bảng chữ "full" giữ mã lỗi của mọi syscall).',
    '**1:** cỡ đọc ghi theo ⌊log₂ n⌋, đủ 16 nhóm (bảng chữ cũ gộp hai nhóm liền nhau).',
    '**f:** thêm futex vào nhóm giữ mã lỗi (ví dụ futex!EAGAIN).',
    '**probe1f:** cùng quy tắc với select1f, nhưng token sắp theo thứ tự probe phát trên cụm (39 syscall có hook phát lúc trả về, các syscall khác lúc vào). Chỉ dùng để kiểm trên dataset rằng thứ tự này không làm mất gì.',
    '**Code:** scripts/analysis/lidds_ml_token_alphabets.py (SELECT_ERR, ALPHABETS["select1f"], ALPHABETS["probe1f"]); token trên dataset: lidds_ml_tokens.py: token(); trong kernel: sentinel_pulse/ebpf/pulse_tokens.bpf.h: pulse_tok_return.',
], note_size=17)

slide('Loại thông tin nào trong token mang tín hiệu (development, 544 tấn công)', [
    ['Bảng chữ', 'Phát hiện', 'Báo nhầm', 'p95'],
    ['**select1f (đang dùng)**', '**530**', '**0,56%**', '**1,45 s**'],
    ['probe1f: theo đúng thứ tự probe phát', '530', '0,56%', '1,49 s'],
    ['Bỏ mã lỗi', '528', '0,50%', '1,53 s'],
    ['Bỏ chế độ mở và thư mục', '523', '0,56%', '1,51 s'],
    ['Cỡ yêu cầu lúc vào thay cỡ trả về', '502', '0,38%', '2,29 s'],
    ['Bỏ cỡ đọc ghi', '490', '0,56%', '2,58 s'],
    ['Chỉ tên syscall', '487', '0,56%', '2,59 s'],
], [4.4, 1.8, 1.8, 1.6], size=14, notes=[
    '**Cỡ đọc ghi mang nhiều tín hiệu nhất,** và phải là cỡ trả về: đây là lý do probe móc lúc syscall trả về (raw_tp/sys_exit).',
    '**Thứ tự phát token của probe không làm mất gì:** syscall không cần giá trị trả về phát token lúc vào.',
], note_size=15)

slide('Probe eBPF: ba điểm gắn', [
    ['Điểm gắn (hàm)', 'Chạy khi nào', 'Dùng cho', 'Code'],
    ['raw_tp/sys_enter (pulse_sys_enter, pulse_record_call)', 'mỗi syscall bắt đầu', 'lọc cgroup (allow-list); giữ trạng thái thread; phát token tên cho mọi syscall **không** thuộc 39 syscall có hook', 'ebpf/pulse_counter.bpf.c'],
    ['raw_tp/sys_exit (pulse_tok_sys_exit, pulse_tok_return)', 'syscall trả về', '39 syscall có hook: token có mã lỗi, cỡ đọc ghi, chế độ mở và thư mục đầu', 'ebpf/pulse_tokens.bpf.h'],
    ['fexit/__seccomp_filter (pulse_seccomp_skip)', 'khi seccomp bỏ qua syscall', 'syscall bị chặn không tới sys_enter, sys_exit: phát token tên ở đây, vẫn đúng một token', 'ebpf/pulse_counter.bpf.c'],
], [2.8, 1.7, 3.8, 1.9], size=12, notes=[
    '**39 syscall có hook** là nhóm cần giá trị trả về, phát token ở sys_exit; danh sách: sentinel_pulse/ebpf/pulse_token_ids.h (PULSE_HOOKED_ROWS).',
    '**Ghi vào map:** pulse_tok_emit cộng 1 vào mục (cgroup, cửa sổ, 4-gram) của map pulse_grams; loader pulse_counter_loader.c: drain_grams đọc cửa sổ đã đóng mỗi 0,5 s rồi xoá.',
], note_size=13)

slide('Probe eBPF trong kernel', note_size=13, img='/tmp/claude-1000/-home-tndat-Downloads-eBPF-project/d1d13a88-05e8-4b39-9713-6ed9238ff484/scratchpad/fig/probe.png')

slide('Bước 2: từ token thành chuỗi theo thread', notes=[
    '**Mỗi thread giữ 4 token gần nhất.** Ở mỗi sự kiện, mô hình nhìn 4-gram (t₋₃, t₋₂, t₋₁, t) của đúng thread đó; đầu thread thì gram ngắn hơn.',
    '**Vì sao theo thread:** service có nhiều thread chạy xen kẽ; "mở → đọc → đóng" chỉ có nghĩa trong cùng một thread. Số đếm của cả container (mô hình cũ) không thấy exploit chạy trong process của dịch vụ: Heartbleed lọt 113/120, ZipSlip 114/118.',
    '**Lịch sử không bị cắt ở biên cửa sổ.** Gram thuộc cửa sổ 0,5 s chứa thời điểm của sự kiện; thread đổi cgroup thì bắt đầu lịch sử mới.',
    '**Kernel đếm thẳng** số lần mỗi (cgroup, cửa sổ, 4-gram) xuất hiện; cuối cửa sổ chỉ chuyển bảng đếm lên user space, không chuyển từng sự kiện.',
    '**fexit/__seccomp_filter** giữ cho syscall bị seccomp bỏ qua vẫn có đúng một token; thư mục lấy bằng cách đi ngược cây dentry từ fd vừa mở.',
    '**Code:** ebpf/pulse_tokens.bpf.h: pulse_tok_emit; dataset: lidds_ml_tokens.py: window_tokens().',
], note_size=17)

slide('Sự kiện là gì, vì sao mỗi sự kiện cho đúng một 4-gram', [
    ['Mỗi cửa sổ 0,5 s (lượt v5)', 'Trung vị', 'p99', 'Lớn nhất'],
    ['Sự kiện của một container', '51', '2.179', '12.381'],
    ['4-gram khác nhau của một container', '26', '651', '1.995'],
    ['Sự kiện của một node (mọi container được theo dõi)', '6.284', '18.710', '26.552'],
    ['4-gram khác nhau của một node (số mục map cần)', '1.950', '5.450', '6.901'],
], [5.2, 1.6, 1.6, 1.6], size=13, notes=[
    '**Sự kiện** = một lần syscall của một thread trong container được theo dõi, cho đúng một token. **4-gram của nó** = token đó cùng 3 token ngay trước trong cùng thread; lịch sử trượt một ô mỗi sự kiện: thread a, b, c, d, e → (a,b,c,d), (b,c,d,e). n sự kiện cho n gram.',
    '**Nhiều syscall trong 0,5 s:** kernel không lưu từng sự kiện; map pulse_grams giữ một mục cho mỗi (cgroup, cửa sổ, gram khác nhau) kèm bộ đếm. Map 262.144 mục; cửa sổ nặng nhất dùng 2,6%; segment cuối: 0 lần chèn thất bại.',
    '**Code:** scripts/analysis/token_load.py; biên nhận validation-evidence/results-20261113/ml-final-study/token-load.json.',
], note_size=12)

slide('Bước 3: xác suất của token tiếp theo – học là đếm', [
    ['Đại lượng', 'Nghĩa'],
    ['c(h, w)', 'Số lần token w theo sau ngữ cảnh h trong normal'],
    ['c(h)', 'Số lần ngữ cảnh h xuất hiện'],
    ['T(h)', 'Số token khác nhau từng theo sau h'],
    ['Mức nền P₀(w)', 'P(tên syscall) × P(biến thể | tên), mỗi số đếm cộng ½'],
    ['Witten–Bell Pₖ (k = 1, 2, 3)', 'Pₖ = [c(hₖ, w) + T(hₖ)·Pₖ₋₁] / [c(hₖ) + T(hₖ)]'],
], [3.0, 7.0], size=15, notes=[
    '**Mức nền** cho token chưa từng thấy một xác suất nhỏ nhưng khác 0: openat!EACCES chưa thấy vẫn có xác suất cao hơn nhiều so với một syscall chưa từng gọi như ptrace.',
    '**Ngữ cảnh đều đặn** (T nhỏ so với c) tin vào số đếm của chính nó: token chưa từng theo sau nó bị nhân với T/(c + T), rất nhỏ.',
    '**Kết quả:** 4-gram chưa thấy nhưng gồm các bước quen có xác suất vừa phải; 4-gram có token lạ sau ngữ cảnh đều đặn có xác suất cực nhỏ. Độ bất ngờ của sự kiện là −ln P₃.',
    '**Code:** sentinel_pulse/detector/token_model.py: CountTokenLM.learn, base (mức nền), prob (Witten–Bell).',
], note_size=14)

slide('Ví dụ thật: từng mức của một sự kiện (CVE-2019-5418)', [
    ['Mức', 'Ngữ cảnh', 'c(h)', 'T(h)', 'c(h, w)', '−ln P'],
    ['P₀: chỉ token write#4', '', '', '', '', '19,07'],
    ['P₁', 'stat', '6.105.129', '22', '0', '31,61'],
    ['P₂', 'close, stat', '189.681', '11', '0', '41,36'],
    ['P₃', 'read, close, stat', '58.109', '11', '0', '49,94'],
], [2.6, 2.4, 1.6, 0.9, 1.1, 1.0], size=15, notes=[
    '**Sự kiện:** 4-gram (read, close, stat, write#4) trong cửa sổ báo của bản ghi tấn công aggressive_torvalds_8369. write#4 (ghi 16–31 byte) chưa từng có trong normal của kịch bản (270 bản ghi, 96 triệu sự kiện, 88 token).',
    '**Đọc bảng:** token tự nó đã hiếm (19,07). "stat" xuất hiện hơn 6 triệu lần và chỉ 22 token khác nhau từng theo sau, không có write#4. Ngữ cảnh càng dài càng đều đặn, nên mỗi mức làm sự kiện bất ngờ hơn: cuối cùng xác suất khoảng e⁻⁵⁰.',
    '**Code:** scripts/analysis/lidds_token_explain.py: backoff(); biên nhận results-20261112/token-explain/.',
], note_size=15)

slide('Bước 4: điểm của cửa sổ 0,5 s – ví dụ cửa sổ báo', [
    ['4-gram (t₋₃, t₋₂, t₋₁, t)', '−ln P₃', 'Token cuối đã thấy'],
    ['read, close, stat, write#4', '49,94', 'không'],
    ['newfstatat, newfstatat, stat, open:r:/etc', '48,74', 'không'],
    ['write#2, setsockopt, getpid, select', '37,64', 'có'],
    ['getpid, getpid, openat!ENOENT, write#6', '30,72', 'có'],
    ['5 gram khác (write#5, write#8, write#9, recvfrom…)', '28,78 … 22,35', '4 có, 1 không'],
    ['stat, write#4, write#4, write#4', '19,07', 'không'],
], [5.6, 2.0, 2.4], size=14, notes=[
    '**Điểm** = trung bình 10 độ bất ngờ lớn nhất = 316,84 / 10 = **31,68** (cửa sổ 6.688 sự kiện, 1.317 gram khác nhau; cả 10 gram đều chưa từng thấy trong normal).',
    '**Đọc ví dụ:** lỗi đọc file tuỳ ý của Rails: service mở một file trong /etc để đọc (open:r:/etc chưa từng có), rồi ghi phản hồi với cỡ lạ.',
    '**Vì sao top 10:** trung bình cả cửa sổ làm loãng vài sự kiện lạ giữa hàng nghìn sự kiện quen; lấy 1 giá trị thì một sự kiện hiếm của normal cũng báo (development: top 1 chỉ 123/544, top 20 492/544).',
    '**Code:** token_model.py: CountTokenLM.window_score.',
], note_size=14)

slide('Bước 5: ngưỡng chỉ từ normal – ví dụ CVE-2019-5418', [
    ['Bước', 'Giá trị'],
    ['1. Cross-fit 5 fold: chấm mỗi bản ghi normal bằng mô hình không học nó', '270 bản ghi, fold theo sha256 của tên'],
    ['2. Cực đại của mỗi bản ghi, bỏ 1% cao nhất', '270 cực đại; bỏ 3 (lớn nhất 26,43), giữ 267'],
    ['3. Trung bình M̄, độ lệch chuẩn σ', '10,13 và 2,79'],
    ['4. Gumbel theo moment: β = (√6/π)·σ, μ = M̄ − 0,5772·β', 'μ = 8,88, β = 2,17'],
    ['5. τ = μ − β·ln(−ln(1 − α′)), α′ = 0,00018 (= M̄ + 6,27·σ)', '27,61'],
    ['Cửa sổ báo của bản ghi tấn công', '31,68 > 27,61: báo'],
    ['Cửa sổ cao nhất của mọi bản ghi normal test (development)', '23,36: không báo'],
], [6.0, 4.0], size=14, notes=[
    '**Vì sao cross-fit:** chấm normal bằng chính mô hình đã học nó cho điểm thấp hơn dữ liệu mới, ngưỡng sẽ quá thấp. Mô hình chấm thật học trên toàn bộ dữ liệu.',
    '**Trên cụm:** đơn vị cực đại là khối 60 s của một container; fold là các đoạn 30 phút liền nhau.',
    '**Code:** scripts/analysis/token_branch_fit.py: crossfit_one, fit_crossfit, trimmed_gumbel; dataset: lidds_ml_token_crossfit.py, lidds_ml_v4.py, lidds_ml_v2.py.',
], note_size=14)

slide('Ngưỡng Gumbel có đúng không (development)', [
    ['Quy tắc ngưỡng (chỉ dùng normal)', 'Báo nhầm ≤ 6', '≤ 12', '≤ 20'],
    ['**Gumbel theo moment, bỏ 1% (đang dùng)**', '**530**', '**530**', '**530**'],
    ['Gumbel theo moment, mọi cực đại', '525', '530', '530'],
    ['Phân bố chuẩn', '525', '530', '530'],
    ['Gumbel hợp lý cực đại', '495', '530', '530'],
    ['GEV hợp lý cực đại', 'không có', '459', '496'],
    ['Cực đại giữ ra lớn nhất (conformal)', 'không có', 'không có', '497'],
], [4.6, 1.8, 1.6, 1.6], size=14, notes=[
    '**Như một phân bố thì không:** Anderson–Darling bác Gumbel ở 15/15 kịch bản; ở α′ = 0,00018 tỉ lệ bản ghi normal vượt ngưỡng cao hơn α′ khoảng 10 lần.',
    '**Cách đọc đúng:** ngưỡng = trung bình + 6,27 độ lệch chuẩn của các cực đại; α′ là núm chỉnh, không phải tỉ lệ báo nhầm được bảo đảm.',
    '**Như một quy tắc thì tốt nhất đã thử** ở mọi ngân sách báo nhầm.',
], note_size=14)

slide('Bước 6 và ba ví dụ tấn công thật (LID-DS 2021 development)', [
    ['Kịch bản', 'Ngưỡng τ', 'Điểm cửa sổ báo', 'Báo sau exploit', 'Cao nhất trước exploit', 'Cao nhất trong normal test'],
    ['CVE-2019-5418 (Rails đọc file tuỳ ý)', '27,61', '31,68', '0,25 s', '8,65', '23,36'],
    ['ZipSlip (giải nén ghi ra ngoài)', '18,98', '28,01', '0,54 s', '7,16', '18,85'],
    ['Heartbleed CVE-2014-0160', '6,05', '9,27', '0,49 s', '2,32', '5,75'],
], [3.0, 1.2, 1.4, 1.4, 1.6, 1.6], size=14, notes=[
    '**Quyết định:** một cửa sổ có điểm > τ là báo, thời điểm báo là cuối cửa sổ. Ví dụ CVE-2019-5418 chỉ có đúng 1 cửa sổ vượt ngưỡng trong 35: quy tắc hai cửa sổ liền nhau sẽ bỏ lỡ.',
    '**ZipSlip:** open:w:/etc (ghi file vào /etc). **Heartbleed:** đọc yêu cầu 8–15 byte (read#3) rồi trả khối 16–32 KB lặp lại (writev#14): đúng dấu hiệu lộ bộ nhớ, token chỉ có tên không thấy được.',
    '**Biên hẹp:** ở ZipSlip, normal cao nhất 18,85 sát ngưỡng 18,98: giải nén file normal tạo thư mục mới ở gốc cũng lạ với mô hình.',
    'Bản ghi ví dụ là bản đầu tiên theo tên bị báo (không chọn theo kết quả); cách tính tái lập đúng 36/36, 35/35, 36/36, 0 báo nhầm.',
    '**Code:** quyết định: token_model.py: TokenBranch.score; ví dụ: lidds_token_explain.py.',
], note_size=13)

slide('Mô hình trên cụm', [
    ['Thành phần', 'LID-DS 2021', 'Cụm'],
    ['Đơn vị học', 'Một mô hình mỗi kịch bản', 'Một mô hình mỗi workload (21 workload, ~1,5 MB nén)'],
    ['Dữ liệu học', 'Bản ghi training và validation', '12 giờ capture normal + normal của lượt trước ngoài các trial'],
    ['Đơn vị cực đại', 'Một bản ghi', 'Khối 60 s của một container'],
    ['Cross-fit', '5 fold theo sha256 của tên', 'Đoạn 30 phút liền nhau, chia vào 5 fold'],
], [2.2, 3.4, 4.4], size=14, notes=[
    '**Ví dụ binary vô hại (lượt 1109, RabbitMQ):** gram (getpid, clock_nanosleep, getpid, clock_nanosleep) chưa từng có, 6 lần với −ln P₃ = 34,0; điểm (6 × 34,0 + 4 × 7,0)/10 = 23,2 > ngưỡng 13,4: báo. Trong order-service chỉ 3 lần, điểm 11,3 < 13,3: không báo.',
    '**Chi phí:** probe thêm ~0,4–0,5 µs mỗi syscall đơn giản của container được theo dõi; worker 0,30–0,31 core mỗi node; chấm một cửa sổ p95 0,18 s sau khi đóng.',
    '**Code:** học: token_branch_fit.py; nhận cửa sổ token: collector/token_capture.py; chi phí probe: scripts/overhead_ab.sh, analysis/overhead_ab.py.',
], note_size=14)

slide('Kiểm từng syscall có hook (development)', [
    ['Bỏ chi tiết của', 'Phát hiện (gốc 530)', 'Báo nhầm (gốc 6)', 'Thay đổi ở'],
    ['write', '490', '6', 'CVE-2019-5418 −36, ZipSlip −4'],
    ['open', '526', '6', 'ZipSlip −4'],
    ['read', '528', '7', 'ZipSlip −2'],
    ['pread', '529', '6', 'ZipSlip −1'],
    ['recv, recvfrom', '530', '9', '3 kịch bản'],
    ['send, sendto / stat', '530', '7 / 7', ''],
    ['24 syscall còn lại', '530', '6', 'không đổi gì'],
], [2.6, 2.0, 1.8, 3.6], size=14, notes=[
    '**8/39 syscall không có trong dữ liệu.** Loại lùi còn 5: open, read, recv/recvfrom, stat, write, giữ đúng 530/544 và 6 báo nhầm.',
    '**Official, chấm một lần đã khai:** 5 syscall cho 1.238/1.271 với 17 báo nhầm (39 syscall: 1.238 với 26). Chưa đổi probe: cần lượt thu và live mới.',
    '**Thêm 13 syscall khác** (mã lỗi accept, clone, poll, select…; cỡ getdents, getdents64, poll, epoll_wait, select): không tăng phát hiện.',
    '**Code:** scripts/analysis/lidds_token_cache.py, lidds_token_study.py.',
], note_size=14)

slide('Tham số của mô hình (development)', [
    ['Tham số', 'Giá trị: phát hiện / báo nhầm (đang dùng in đậm)'],
    ['Độ dài gram', '2: 458/3 · 3: 530/8 · **4: 530/6** · 5: 526/6 · 6: 493/6'],
    ['Số giá trị lấy trung bình', '1: 123/7 · 3: 528/5 · 5: 529/7 · **10: 530/6** · 20: 492/7'],
    ['Mức α′', '0,001: 530/15 · 0,0005: 530/10 · **0,00018: 530/6** · 0,0001: 527/6'],
    ['Số fold', '3: 530/7 · **5: 530/6** · 10: 530/7'],
    ['Phần cực đại bỏ đi', '0: 523/4 · 0,5%: 524/6 · **1%: 530/6** · 2%: 530/9 · 5%: 530/15'],
], [2.6, 7.4], size=14, notes=[
    '**Quanh bộ đang dùng kết quả phẳng;** chỉ hỏng ở các cực (lấy 1 hay 20 giá trị, gram dài 2 hay 6). Bảng không dùng để chọn lại.',
    '**Cửa sổ 0,5 s và khối 60 s** được cố định từ trước theo mục tiêu độ trễ, không có trong bảng.',
    '**Code:** lidds_token_study.py (bước q2).',
], note_size=15)

slide('Mô hình hay luật đếm 4-gram chưa thấy', [
    ['Ngân sách báo nhầm (bản ghi normal)', 'Mô hình', 'Luật đếm 4-gram chưa thấy'],
    ['≤ 3', '472/544', 'không có điểm nào'],
    ['≤ 6', '530/544', '444/544'],
    ['≤ 12', '530/544', '488/544'],
    ['≤ 34', '531/544', '526/544'],
], [4.0, 2.4, 3.6], size=15, notes=[
    '**Ở báo nhầm thấp, mô hình hơn 86 bản ghi:** 53,4% bản ghi normal có ít nhất một 4-gram chưa thấy; mô hình chấm được mức độ lạ, luật đếm thì không.',
    '**Tấn công blind chỉ dùng chuỗi đã thấy** (bỏ mọi sự kiện có gram hoặc token chưa thấy): mô hình 0/544, luật 0. Mô phỏng bán tổng hợp, không phải exploit thật.',
    '**Code:** lidds_token_study.py (bước q4).',
])

slide('Mô hình làm được gì và không làm được gì', [
    ['Làm được', 'Không làm được'],
    ['Bắt tấn công chưa biết khi nó tạo token hoặc chuỗi lạ với normal của chính workload', 'Phân biệt process mới vô hại với tấn công: cả hai đều lạ'],
    ['Chấm mức độ lạ: ở báo nhầm thấp hơn hẳn luật đếm chuỗi chưa thấy', 'Bắt tấn công chỉ dùng chuỗi đã thấy (0/544 trong mô phỏng)'],
    ['Báo trong một cửa sổ, thường dưới 1 s sau khi exploit bắt đầu', 'Bảo đảm tỉ lệ báo nhầm theo α′ (Gumbel không giữ)'],
    ['Học không cần nhãn; cùng code trên dataset và trên cụm', 'Bắt exploit không để lại dấu vết (28 bản ghi Juice-Shop)'],
], [5.0, 5.0], size=15)

slide('Nghiên cứu các điểm yếu còn lại (12–13/11)', [
    ['Câu hỏi', 'Kết quả', 'Quyết định'],
    ['A. Recall live chỉ do burst khởi chạy qua kubectl exec?', 'Bỏ mọi gram của binary vô hại và lệnh quản trị cùng trial: vẫn 314/314; 0 trial chỉ nhờ burst', 'Recall đo đúng hành vi tấn công'],
    ['B. Học thêm lệnh quản trị như normal (bỏ-một-lệnh)?', 'Lệnh chưa học vẫn bị gắn cờ 362/439 (82,5%); recall tụt 303/314', 'Không đạt (≤ 20%)'],
    ['C. Ngưỡng theo phân vị thực nghiệm của 134.905 khối 60 s?', 'Gánh giảm một nửa nhưng recall 281/314; LID-DS 498/544, 13 báo nhầm', 'Bị loại, giữ Gumbel'],
    ['D. Tín hiệu tần suất cho tấn công chỉ dùng chuỗi đã thấy?', 'Riêng tín hiệu 225/544 (mô hình 0); ghép: 530/544, 12 báo nhầm, CB-DS 4', 'Trượt CB-DS (≤ 3) một báo nhầm'],
], [3.6, 4.6, 1.8], size=12, notes=[
    '**Protocol ml-final-study-v1** đăng ký trước khi viết code (12/11 21:50). Không ứng viên nào đạt tiêu chí: **ML cuối giữ lidds-ml-v5**. Tiếp theo: rule sau ML.',
    '**Code:** live_attribution.py (A, B), token_branch_fit.py --dump-maxima + cluster_threshold.py (C), lidds_token_rate.py (D); biên nhận validation-evidence/results-20261113/ml-final-study/.',
], note_size=12)

slide('Kết quả: LID-DS 2021 official và lượt live blind pulse-live-v5-1110', [
    ['', 'Recall', 'Báo nhầm / control', 'p95', 'Binary vô hại bị gắn cờ'],
    ['Mô hình đếm ban đầu (cây và support), official', '63,89%', '2,71%', '5,29 s', ''],
    ['**lidds-ml-v5 (chỉ token), official**', '**97,40%**', '**0,33%**', '**1,47 s**', ''],
    ['pulse-live-v5-1110, tập chính', '314/314', '0/314', '0,49 s', '314/314'],
], [3.8, 1.4, 1.8, 1.2, 1.8], size=14, notes=[
    '**Theo kịch bản:** 14/15 đạt 100%; Juice-Shop 52/85. CB-DS 891/891 với 3 báo nhầm.',
    '**Học thêm normal giảm gánh 2,5 lần** (0,17 đợt/replica-giờ).',
    '**Lệnh quản trị thật qua kubectl exec:** 419/436 bị gắn cờ. Gate đăng ký trước (mô hình gộp, bỏ qua hoặc ngưỡng riêng sau execve) làm mất exploit thật trên development (315–509/544 thay vì 530): bị loại.',
    '**Code:** scripts/analysis/lidds_ml_v5.py (dataset), pulse_live_v4.py (live).',
], note_size=14)

slide('Đường cảnh báo và RCA (lượt v5)', [
    ['Chỉ số', 'Kết quả'],
    ['Kernel → Alertmanager (push), tấn công', '521/522 trial, p50 0,51 s, p95 0,68 s'],
    ['Tấn công có case RCA riêng', '467/522 (89,5%)'],
    ['Binary tấn công đứng hạng 1', '464/467 (99,4%)'],
    ['Cảnh báo → case', 'p50 2,33 s, p95 2,61 s'],
], [4.4, 5.6], size=15, notes=[
    '**14 tấn công mất case do điều kiện đua:** mô hình báo trên burst dựng process, trước khi binary có sự kiện exec. Đã sửa (xét exec tới lúc quyết định, xét lại sau 2 s), chưa đo live.',
    '**Hạng 1 có lợi thế từ thiết kế campaign:** tấn công luôn chạy sau binary vô hại; thứ tự ngược lại chưa đo.',
    '**Code:** ops/alert_bridge.py, rca/service.py; phân tích: alert_delivery_latency.py, bridge_delivery.py, rca_coverage.py, rca_follow_up.py.',
])

slide('Tuần này: các lượt chạy và sự cố', [
    ['Lượt / job', 'Thời gian', 'Kết quả'],
    ['Probe token, đo chi phí 3 lần', '07/11', 'Bản cuối không còn ftrace_ops'],
    ['pulse-token-capture-1107', '07–08/11', 'Thu normal 12 giờ, 24 segment'],
    ['lidds-ml-v5', '10/11', 'Chỉ token: 97,40% / 0,33%; gate bị loại'],
    ['pulse-live-v5-1110', '11–12/11', 'Live blind 24 giờ: 314/314, control 0/314'],
    ['token-design-study-v1, token-explain', '11–12/11', 'Kiểm từng lựa chọn; ba ví dụ thật'],
    ['ml-final-study-v1', '12–13/11', 'A–D xong; ML giữ lidds-ml-v5'],
    ['Đổi cấu hình VM, dọn cụm', '12/11', '6 node 16 vCPU / 36 GB; NFS 490 → 356 GB'],
], [4.0, 1.4, 4.6], size=14, notes=[
    '**Sự cố:** vCenter khởi động lại 2 lần (09/11); host ESXi nghẽn 3,5 phút (11/11) vì VM được cấp gấp ~3 lần RAM thật; sau đổi VM, replica Postgres lệch timeline và 11 pod ngoài mesh được tạo lại.',
], note_size=14)

slide('Tiến độ (ước lượng)', [
    ['Hạng mục', 'Hoàn thành', 'Còn lại'],
    ['ML trên dataset (LID-DS 2021, CB-DS)', '~95%', 'LID-DS 2019 khi mô hình chốt'],
    ['Probe token và chi phí', '~85%', 'Chi phí trên request thật, tải cực đại của map, bản 5 syscall'],
    ['Live blind của ML', '~85%', 'Bản sửa RCA, thứ tự trial ngẫu nhiên, thêm kỹ thuật tấn công'],
    ['Process mới vô hại (binary, lệnh quản trị)', '~15%', 'Chưa có cách giữ được kết quả LID-DS'],
    ['RCA và đường cảnh báo', '~90%', 'Đo bản sửa điều kiện đua; hàng đợi bền cho bridge'],
    ['So sánh có và không có luật', '~10%', 'Sau khi ML chốt'],
    ['**Đồ án tổng thể**', '**~85%**', 'Tăng từ ~70% ở buổi 06/11'],
], [3.6, 1.4, 5.0], size=13)

slide('Việc tiếp theo và câu hỏi cho thầy', notes=[
    '**Process mới vô hại:** chấm riêng process vào qua runtime exec bằng mô hình học từ các lần exec vô hại; điều kiện là giữ kết quả LID-DS 2021. Rule giảm binary vô hại chỉ thêm sau khi ML chốt, rồi so sánh có và không có rule.',
    '**Tín hiệu cho tấn công chỉ dùng chuỗi đã thấy:** cần thứ mô hình hiện tại không có (tần suất, ngữ cảnh process).',
    '**Lượt thu và live mới** trên cấu hình VM mới: bản sửa RCA, thứ tự ngẫu nhiên, thêm kỹ thuật ATT&CK, chi phí trên request thật, tải cực đại của map.',
    '**LID-DS 2019:** chấm đúng một lần khi mô hình đã chốt cho paper.',
    '**Cần thầy cho ý kiến:** (1) binary vô hại để là giới hạn của đồ án hay phải giải quyết trước khi bảo vệ; (2) có đổi probe sang 5 syscall; (3) exploit thật trên cụm có cần cho bản paper.',
    '**Rule sau khi chốt ML:** R1 hạ cảnh báo khi trong cửa sổ chỉ có runtime exec của tool có sẵn trong image; R2 gắn nhãn drift cho binary không có trong image; so sánh có và không có rule.',
], note_size=16)
