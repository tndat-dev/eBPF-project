import re
p='deck_1311_content.py'; s=open(p).read()
FIG='/tmp/claude-1000/-home-tndat-Downloads-eBPF-project/d1d13a88-05e8-4b39-9713-6ed9238ff484/scratchpad/fig'

def insert_after_slide(title, code):
    """Insert code after the slide(...) call whose title starts with title."""
    global s
    i = s.index(f"slide('{title}")
    j = s.find("\nslide(", i + 1)
    j = len(s) if j < 0 else j
    s = s[:j].rstrip('\n') + '\n\n' + code.strip('\n') + '\n' + s[j:]

def add_note(title, text):
    """Append a bullet to the notes list of a slide."""
    global s
    i = s.index(f"slide('{title}")
    j = s.find("\nslide(", i + 1); j = len(s) if j < 0 else j
    block = s[i:j]
    k = block.index('notes=[')
    end = block.index('\n]', k)
    block = block[:end] + f"\n    {text!r}," + block[end:]
    s = s[:i] + block + s[j:]

insert_after_slide('Sáu bước của mô hình', f'''
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
], note_size=13, img='{FIG}/overview.png')

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
''')

insert_after_slide('Bước 1: từ syscall thành token', '''
slide('select1f và probe1f là gì', notes=[
    '**Bảng chữ** = bộ quy tắc biến một lần syscall thành token. Tên ghép từ các lựa chọn:',
    '**select:** chỉ 27 syscall được chọn giữ mã lỗi (bảng chữ "full" giữ mã lỗi của mọi syscall).',
    '**1:** cỡ đọc ghi theo ⌊log₂ n⌋, đủ 16 nhóm (bảng chữ cũ gộp hai nhóm liền nhau).',
    '**f:** thêm futex vào nhóm giữ mã lỗi (ví dụ futex!EAGAIN).',
    '**probe1f:** cùng quy tắc với select1f, nhưng token sắp theo thứ tự probe phát trên cụm (39 syscall có hook phát lúc trả về, các syscall khác lúc vào). Chỉ dùng để kiểm trên dataset rằng thứ tự này không làm mất gì.',
    '**Code:** scripts/analysis/lidds_ml_token_alphabets.py (SELECT_ERR, ALPHABETS["select1f"], ALPHABETS["probe1f"]); token trên dataset: lidds_ml_tokens.py: token(); trong kernel: sentinel_pulse/ebpf/pulse_tokens.bpf.h: pulse_tok_return.',
], note_size=17)
''')

insert_after_slide('Loại thông tin nào trong token', f'''
slide('Probe eBPF: ba điểm gắn', [
    ['Điểm gắn (hàm)', 'Chạy khi nào', 'Dùng cho', 'Code'],
    ['raw_tp/sys_enter (pulse_sys_enter, pulse_record_call)', 'mỗi syscall bắt đầu', 'lọc cgroup (allow-list); giữ trạng thái thread; phát token tên cho mọi syscall **không** thuộc 39 syscall có hook', 'ebpf/pulse_counter.bpf.c'],
    ['raw_tp/sys_exit (pulse_tok_sys_exit, pulse_tok_return)', 'syscall trả về', '39 syscall có hook: token có mã lỗi, cỡ đọc ghi, chế độ mở và thư mục đầu', 'ebpf/pulse_tokens.bpf.h'],
    ['fexit/__seccomp_filter (pulse_seccomp_skip)', 'khi seccomp bỏ qua syscall', 'syscall bị chặn không tới sys_enter, sys_exit: phát token tên ở đây, vẫn đúng một token', 'ebpf/pulse_counter.bpf.c'],
], [2.8, 1.7, 3.8, 1.9], size=12, notes=[
    '**39 syscall có hook** là nhóm cần giá trị trả về, phát token ở sys_exit; danh sách: sentinel_pulse/ebpf/pulse_token_ids.h (PULSE_HOOKED_ROWS).',
    '**Ghi vào map:** pulse_tok_emit cộng 1 vào mục (cgroup, cửa sổ, 4-gram) của map pulse_grams; loader pulse_counter_loader.c: drain_grams đọc cửa sổ đã đóng mỗi 0,5 s rồi xoá.',
], note_size=13)

slide('Probe eBPF trong kernel', note_size=13, img='{FIG}/probe.png')
''')

insert_after_slide('Bước 2: từ token thành chuỗi theo thread', '''
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
''')

insert_after_slide('Mô hình làm được gì và không làm được gì', '''
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
''')

codes = {
 'Bước 2: từ token thành chuỗi theo thread': '**Code:** ebpf/pulse_tokens.bpf.h: pulse_tok_emit; dataset: lidds_ml_tokens.py: window_tokens().',
 'Bước 3: xác suất của token tiếp theo': '**Code:** sentinel_pulse/detector/token_model.py: CountTokenLM.learn, base (mức nền), prob (Witten–Bell).',
 'Ví dụ thật: từng mức của một sự kiện': '**Code:** scripts/analysis/lidds_token_explain.py: backoff(); biên nhận results-20261112/token-explain/.',
 'Bước 4: điểm của cửa sổ 0,5 s': '**Code:** token_model.py: CountTokenLM.window_score.',
 'Bước 5: ngưỡng chỉ từ normal': '**Code:** scripts/analysis/token_branch_fit.py: crossfit_one, fit_crossfit, trimmed_gumbel; dataset: lidds_ml_token_crossfit.py, lidds_ml_v4.py, lidds_ml_v2.py.',
 'Bước 6 và ba ví dụ tấn công thật': '**Code:** quyết định: token_model.py: TokenBranch.score; ví dụ: lidds_token_explain.py.',
 'Mô hình trên cụm': '**Code:** học: token_branch_fit.py; nhận cửa sổ token: collector/token_capture.py; chi phí probe: scripts/overhead_ab.sh, analysis/overhead_ab.py.',
 'Kiểm từng syscall có hook': '**Code:** scripts/analysis/lidds_token_cache.py, lidds_token_study.py.',
 'Tham số của mô hình': '**Code:** lidds_token_study.py (bước q2).',
 'Mô hình hay luật đếm 4-gram chưa thấy': '**Code:** lidds_token_study.py (bước q4).',
 'Kết quả: LID-DS 2021 official': '**Code:** scripts/analysis/lidds_ml_v5.py (dataset), pulse_live_v4.py (live).',
 'Đường cảnh báo và RCA': '**Code:** ops/alert_bridge.py, rca/service.py; phân tích: alert_delivery_latency.py, bridge_delivery.py, rca_coverage.py, rca_follow_up.py.',
}
for t, c in codes.items():
    add_note(t, c)

# owner's edits in the report, mirrored
s = s.replace("    ['pulse-live-v4-1109, tập chính', '315/315', '3/315', '0,49 s', '313/315'],\n", "")
s = s.replace("slide('Kết quả: LID-DS 2021 official và hai lượt live blind 24 giờ'", "slide('Kết quả: LID-DS 2021 official và lượt live blind pulse-live-v5-1110'")
s = s.replace("'**Học thêm normal giảm gánh cảnh báo 0,41 → 0,17 đợt/replica-giờ.** Host ESXi nghẽn 3,5 phút ở lượt v5: bỏ khoảng nghẽn không đổi tỉ lệ nào.'", "'**Học thêm normal giảm gánh 2,5 lần** (0,17 đợt/replica-giờ).'")
s = s.replace("    ['lidds-ml-v3, v4, v5', '07–10/11', 'select1f, cross-fit, chỉ token; gate bị loại'],\n", "    ['lidds-ml-v5', '10/11', 'Chỉ token: 97,40% / 0,33%; gate bị loại'],\n")
s = s.replace("    ['pulse-live-v4-1109, pulse-live-v5-1110', '09–12/11', 'Hai lượt live blind 24 giờ, đều đạt kỳ vọng'],\n", "    ['pulse-live-v5-1110', '11–12/11', 'Live blind 24 giờ: 314/314, control 0/314'],\n")
s = s.replace("    ['Đổi cấu hình VM, dọn cụm', '12/11',", "    ['ml-final-study-v1', '12–13/11', 'A–D xong; ML giữ lidds-ml-v5'],\n    ['Đổi cấu hình VM, dọn cụm', '12/11',")
s = s.replace("    ['**Đồ án tốt nghiệp tổng thể**', '**~85%**', 'Tăng từ ~70% ở buổi 06/11'],\n    ['**Bản paper hội nghị hàng đầu**', '**~50%**', 'Process vô hại, tấn công chỉ dùng chuỗi đã thấy, exploit thật trên cụm, baseline'],\n", "    ['**Đồ án tổng thể**', '**~85%**', 'Tăng từ ~70% ở buổi 06/11'],\n")
add_note('Việc tiếp theo và câu hỏi cho thầy', '**Rule sau khi chốt ML:** R1 hạ cảnh báo khi trong cửa sổ chỉ có runtime exec của tool có sẵn trong image; R2 gắn nhãn drift cho binary không có trong image; so sánh có và không có rule.')
open(p,'w').write(s)
print(s.count("slide("))
