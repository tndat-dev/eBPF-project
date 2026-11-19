# Content of the 20/11 deck (progress 13/11 -> 20/11/2026), run by docs/meetings/2026-11-13/make_deck_1311.py on the owner's
# 13/11 deck. Numbers from notes/WORKLOG.md and validation-evidence/results-20261113..20261119 (same as the report).
FIG = sys.argv[4]

slide('Cấu trúc bài trình bày (tiến độ 13/11 – 20/11/2026)', notes=[
    'Kết quả chính',
    'Hệ thống: kiến trúc, probe có thẻ dòng dõi, code của từng phần',
    'Process mới vô hại: học thêm hoạt động quản trị, tách theo dòng dõi',
    'Chi phí thẻ dòng dõi, sức chứa map; luật R1, R2 và nhánh tần suất',
    'Lượt live thứ ba pulse-live-v6-1117 (26 giờ, 735 trial)',
    'LID-DS 2019: lượt chấm của v5, quy tắc độ phân giải của nhãn, development và cấu hình t3',
    'Vòng cải thiện D1–D18 và lượt live cuối pulse-live-final-1119 (đang chạy)',
    'Paper, code, dọn tài nguyên; tiến độ, việc tiếp theo, câu hỏi cho thầy',
], note_size=18)

slide('Kết quả chính', [
    ['', 'Recall', 'Báo nhầm / control', 'p95'],
    ['Live blind pulse-live-v6-1117, tập chính', '315/315', '1/315', '0,45 s'],
    ['Tấn công pha loãng PAD 30 / PAD 300', '105/105 / 105/105', '', ''],
    ['LID-DS 2021 official, v5 / t3', '1.238 / 1.236 trên 1.271', '26 / 15 trên 7.938', '1,47 / 1,54 s'],
    ['LID-DS 2019, v5, dung sai nhãn 1 s', '1.056/1.162 (90,88%)', '34/7.706 (0,44%)', '10,55 s'],
    ['LID-DS 2019 holdout 70%, t3, dung sai 1 s', '817/841 (97,15%)', '25/5.395 (0,46%)', '10,95 s'],
    ['Kỳ vọng', '≥ 95%', '≤ 5% (control), ≤ 1% (bản ghi)', '≤ 3 s'],
], [3.6, 2.3, 2.4, 1.7], notes=[
    '**Lượt v6 chạy lidds-ml-v5; sau đó chọn lidds-ml-v5-t3** (top 3, amendment 1) cho lượt live cuối đang chạy.',
    '**Thẻ dòng dõi:** chỉ chấm phần native thì lệnh quản trị 1/475, binary vô hại 1/525 bị gắn cờ (cả cửa sổ: 460/475, 525/525).',
    '**Luật R1 không nhận:** xoá báo nhầm quản trị nhưng cũng xoá mọi tấn công dùng tool của image (314/315 → 0/315).',
    '**LID-DS 2019:** t3 đạt recall và báo nhầm trên holdout; p95 không đạt (cận dưới của dữ liệu 9,39 s). Holdout đã được v5 chấm trước khi chia; dung sai đặt sau lượt chấm.',
])

slide('Kiến trúc hệ thống', notes=[
    '**Hệ thống của lượt live cuối:** thẻ dòng dõi (chương trình BPF thứ tư gắn vào sched_process_fork); mô hình t3; map 4-gram đầy thì báo cửa sổ nặng nhất (D1); bridge có hàng đợi bền và nhãn stream native/session (D3). Hình 5 trang và bảng ánh xạ code: docs/architecture/.',
], note_size=13, img=f'{FIG}/overview.png')

slide('Probe eBPF và thẻ dòng dõi', notes=[
    '**Native:** cây process của workload. **Session:** vào qua runtime exec và mọi con của nó. Con nhận thẻ của cha lúc fork; proof trên pod thật 8/8. Chỉ là telemetry, không dùng để báo.',
], note_size=13, img=f'{FIG}/probe.png')

slide('Code của các thành phần', [
    ['Thành phần', 'Code'],
    ['Probe eBPF (token, 4-gram, thẻ dòng dõi)', 'sentinel_pulse/ebpf/pulse_counter.bpf.c, pulse_tokens.bpf.h (pulse_tok_lineage, pulse_tok_fork), pulse_token_ids.h'],
    ['Loader', 'sentinel_pulse/ebpf/pulse_counter_loader.c'],
    ['Worker chấm điểm', 'sentinel_pulse/pipeline/matched_worker.py, detector/token_model.py, collector/token_capture.py'],
    ['Học mô hình trên cụm', 'scripts/analysis/token_branch_fit.py'],
    ['Bridge cảnh báo, RCA', 'sentinel_pulse/ops/alert_bridge.py, sentinel_pulse/rca/service.py'],
    ['Campaign tấn công và đối chứng', 'sentinel_pulse/attack/preview_campaign.py'],
    ['Phân tích lượt v6', 'scripts/analysis/pulse_live_v4.py, native_stream.py, rule_e_benefit.py, rca_coverage.py, model_aging.py'],
    ['LID-DS 2019', 'sentinel_pulse/lidds/lidds2019.py, scripts/analysis/lidds2019_token.py, scripts/lidds2019_token_run.sh'],
    ['Proof thẻ dòng dõi, proof token', 'scripts/lineage_probe_proof.py, scripts/token_probe_proof.py'],
    ['Map đầy (D1), hàng đợi bền (D3)', 'collector/token_capture.py (MapOverflow), ops/alert_bridge.py (PushQueue, stream_of)'],
    ['Mô tả kiến trúc và luồng code', 'docs/architecture/KIEN_TRUC.md, docs/LUONG_CODE.md'],
], [3.0, 7.0], size=12)

slide('Process mới vô hại: học thêm, rồi tách theo dòng dõi', [
    ['Hướng (ml-final-study-v1, dữ liệu v5)', 'Kết quả', 'Quyết định'],
    ['Học thêm mọi lệnh quản trị (B)', 'Lệnh giữ ra vẫn bị gắn cờ 362/439; recall 314 → 303/314', 'Không đạt'],
    ['Học lệnh quản trị của fold khác (B2)', '372/439 vẫn bị gắn cờ', 'Không đạt'],
    ['Chấm phần native (proxy B3)', 'Control 0/525, quản trị 0/439, binary vô hại 0/523', 'Đo trên lượt live'],
    ['Mô hình riêng cho phiên exec (B3)', 'Ngưỡng 37,7: bắt 0/522 tấn công', 'Không dùng'],
], [3.4, 4.4, 2.2], size=14, notes=[
    '**Amendment 2:** thêm thẻ dòng dõi vào probe như telemetry, đường cảnh báo không đổi; kiểm trên lượt v6 (giả thuyết H1).',
    'Code: scripts/analysis/live_attribution.py, session_model.py.',
])

slide('Chi phí thẻ dòng dõi và sức chứa map 4-gram', [
    ['Syscall/s (một cgroup, mọi syscall là gram mới)', 'Gram mỗi cửa sổ', 'Gram không ghi được', 'Đọc map'],
    ['200.000', '97.168', '0', '0,22 s'],
    ['300.000', '142.610', '0', '0,33 s'],
    ['400.000', '148.695', '949.878', '0,44 s'],
    ['800.000', '258.401', '4.888.620', '0,64 s'],
], [4.2, 2.0, 2.2, 1.6], size=14, notes=[
    '**Thẻ dòng dõi không có chi phí đo được:** 12 ô (3 worker × 4 thao tác), khoảng tin cậy đều chứa 0 trừ một ô âm; fork + exit + wait 332–385 µs.',
    '**Map dư khoảng 20 lần:** cửa sổ nặng nhất của node ở lượt v5 có 6.901 gram. Map đầy thì worker không biết cửa sổ thiếu: đường né, ghi là giới hạn.',
    'Code: scripts/overhead_ab.sh, testbed/bench/gram_stress.c, scripts/map_capacity_test.py.',
])

slide('Luật sau mô hình (campaign v5) và nhánh tần suất', [
    ['Tập chính v5', 'Chỉ mô hình', 'Mô hình + luật'],
    ['Recall tấn công', '314/314', '314/314'],
    ['Báo nhầm lệnh quản trị (tool của image)', '256/262 (97,7%)', '0/262'],
    ['Exec vô hại không thuộc image', '314/314', '314/314 (nhãn drift)'],
], [4.6, 2.7, 2.7], size=14, notes=[
    '**R1:** hạ cảnh báo khi cửa sổ chỉ có exec của binary có trong image. **R2:** giữ cảnh báo của binary không thuộc image, gắn nhãn drift.',
    '**Nhánh tần suất:** không thêm phát hiện nào (LID-DS 530 → 530, CB-DS 891 → 891), chỉ thêm báo nhầm (6 → 12, 3 → 4); giữ shadow.',
    'Code: scripts/analysis/rule_e_benefit.py, lidds_token_rate.py.',
])

slide('Lượt live thứ ba pulse-live-v6-1117: thiết kế', notes=[
    '**Protocol pulse-live-v6-v1 + amendment 1**, đăng ký trước khi thu normal: H0 lặp lại, H1 dòng native, H3 pha loãng, H4 tấn công bằng tool của image và mặt hại R1, H5 lệnh quản trị chưa thấy, H6 thứ tự và hạng RCA.',
    '**Normal 12 giờ** (16–17/11), 0 lần chèn thất bại. **Mô hình có lão hoá:** v5 cũ vượt ngưỡng 0,59% khối normal mới, so với 0,26% trên dữ liệu giữ ra → học lại 21 mô hình, cùng thuật toán và tham số.',
    '**735 trial trong 26 giờ:** 525 cơ bản, 105 PAD 30, 105 PAD 300 (chèn 30 / 300 cặp getpid + sched_yield sau mỗi thao tác tấn công).',
    '**Mỗi trial thêm:** một lệnh quản trị từ bộ 10 tool chưa dùng, một bước tấn công chỉ dùng sh, cat, ls của image (lotl); thứ tự các bước xáo bằng seed.',
    'Code: sentinel_pulse/attack/preview_campaign.py, scripts/analysis/model_aging.py, token_branch_fit.py.',
], note_size=16)

slide('Lượt v6: kết quả (H0, H3)', [
    ['Chỉ số', 'Kỳ vọng', 'Tập chính', 'Mọi tốc độ'],
    ['Recall', '≥ 95%', '315/315', '524/525'],
    ['Precision', '≥ 95%', '99,68%', '99,81%'],
    ['Control dương', '≤ 5%', '1/315', '1/525'],
    ['p95 kernel → cuối cửa sổ báo', '≤ 3 s', '0,45 s', '0,46 s'],
    ['Pha loãng PAD 30 / PAD 300', '≥ 95%', '105/105 / 105/105', ''],
    ['Binary vô hại bị gắn cờ', 'báo kèm', '315/315', '525/525'],
    ['Lệnh quản trị chưa thấy bị gắn cờ', 'báo kèm', '275/284', '460/475'],
    ['Tấn công lotl bị bắt', 'báo kèm', '314/315', '524/525'],
], [3.8, 1.5, 2.6, 2.1], size=14, notes=[
    '**Lặp lại đạt sau khi đổi cụm và học lại.** Điểm là trung bình 10 sự kiện bất ngờ nhất, nên chèn syscall quen không làm loãng gram lạ.',
    'Map không rơi gram nào. Gánh 4 đợt / 51,1 replica-giờ: khoảng normal ngắn, không so được với v5.',
])

slide('Lượt v6: dòng native (H1)', [
    ['Khoảng (mọi tốc độ)', 'Cả cửa sổ (đường cảnh báo)', 'Chỉ phần native'],
    ['Control', '1/525', '1/525'],
    ['Lệnh quản trị (bộ v6)', '460/475', '1/475'],
    ['Binary vô hại', '525/525', '1/525'],
    ['Tấn công (fixture)', '524/525', '0/525'],
    ['Tấn công bằng tool của image', '524/525', '1/525'],
], [3.6, 3.2, 3.2], size=15, notes=[
    '**H1 đạt:** cơ chế học được đầu tiên tách process vô hại mới khỏi hành vi của workload.',
    '**Giá (đã ghi trong protocol):** tấn công của campaign vào qua kubectl exec nên thuộc dòng session. Chỉ chấm native không thay được đường cảnh báo; dòng session cần cách xử lý riêng.',
    'Code: scripts/analysis/native_stream.py.',
])

slide('Lượt v6: mặt hại của luật R1 (H4, H5)', [
    ['Tập chính', 'Chỉ mô hình', 'Mô hình + R1'],
    ['Tấn công bằng tool của image (lotl)', '314/315', '0/315'],
    ['Lệnh quản trị chưa từng thấy', '275/284', '0/284'],
    ['Tấn công fixture', '315/315', '315/315'],
], [4.6, 2.7, 2.7], size=15, notes=[
    '**R1 không phân biệt người vận hành chạy cat với kẻ tấn công chạy cat.**',
    '**Kết luận: R1 không được nhận.** Lợi và hại đến từ cùng một điều kiện; không có ngưỡng nào giữ cái này mà bỏ cái kia.',
    'Code: scripts/analysis/rule_e_benefit.py.',
])

slide('Lượt v6: đường cảnh báo và RCA (H6)', [
    ['Chỉ số', 'Kết quả'],
    ['Bridge → Alertmanager', '3.233/3.233 đợt; decision → Alertmanager p95 1,21 s'],
    ['Kernel → Alertmanager (push), tấn công', '721/735 trial, p50 0,49 s, p95 1,53 s'],
    ['Tấn công có case riêng (sau bản sửa RCA)', '711/735 (96,7%)'],
    ['Fixture hạng 1: chạy sau / trước binary vô hại', '75,5% / 76,4%'],
], [4.6, 5.4], size=15, notes=[
    '**Thứ tự không còn quyết định hạng 1.** Mức thấp hơn v5 (99,4%) vì mỗi trial v6 có hai tấn công: trong 162/170 case fixture không đứng đầu, hạng 1 là process của bước lotl (sh, cat, rm) — phân tích thăm dò.',
    'Code: sentinel_pulse/ops/alert_bridge.py, sentinel_pulse/rca/service.py, scripts/analysis/rca_coverage.py.',
])

slide('LID-DS 2019: chấm một lần (dung sai nhãn 1 s)', [
    ['Kịch bản', 'Phát hiện', 'Báo nhầm', 'p95'],
    ['Bruteforce_CWE-307', '92/98', '5/744', '14,37 s'],
    ['CVE-2012-2122', '152/155', '1/990', '1,17 s'],
    ['CVE-2014-0160 (Heartbleed)', '24/100', '5/750', '11,19 s'],
    ['CVE-2017-7529', '157/174', '0/733', '1,15 s'],
    ['CVE-2018-3760', '133/137', '0/834', '1,06 s'],
    ['CVE-2019-5418', '98/98', '0/731', '1,25 s'],
    ['EPS, PHP, SQL, ZipSlip', '400/400', '23/2.924', '2,24–5,56 s'],
    ['Tổng', '1.056/1.162 (90,88%)', '34/7.706 (0,44%)', '10,55 s'],
], [3.4, 2.5, 2.3, 1.8], size=13, notes=[
    '**C1 không đạt** (recall ≥ 95%, báo nhầm ≤ 1%, p95 ≤ 3 s): báo nhầm đạt; Heartbleed 24/100 (76 bản ghi không có cảnh báo); p95 cao ở Bruteforce, Heartbleed, PHP, SQL.',
], note_size=14)

slide('LID-DS 2019: quy tắc đánh giá và phần còn lại', notes=[
    '**Mốc exploit của 2019 là số nguyên giây,** cửa sổ báo định vị tới micro giây: bản ghi tấn công tính là phát hiện khi cửa sổ báo kết thúc sau (mốc nhãn − 1 s); độ trễ tính từ mốc đó.',
    '**Quy tắc đặt sau lượt chấm** (amendment 1), trên chính cảnh báo của lượt chấm duy nhất; cùng quy tắc trên LID-DS 2021 official vẫn 1.238/1.271.',
    '**Còn lại:** Heartbleed 76/100 bản ghi không có cảnh báo nào; độ trễ cao vì hành vi lạ đầu tiên đến nhiều giây sau mốc nhãn. Mã lỗi của trace 2019 cùng định dạng 2021.',
    'Code: scripts/analysis/lidds2019_token.py (lệnh tolerance).',
], note_size=16)

slide('LID-DS 2019: thử cải thiện trên 30% development', [
    ['Ứng viên (23 đã thử)', '2019 dev, dung sai 1 s', 'Báo nhầm', 'p95', 'LID-DS 2021 dev'],
    ['lidds-ml-v5 (giữ)', '295/321', '6/2.311', '10,08 s', '530 / 6 (giữ)'],
    ['top 5', '310/321', '6/2.311', '11,13 s', '529 / 7 (hỏng)'],
    ['n 5', '310/321', '8/2.311', '11,13 s', '526 / 6 (hỏng)'],
    ['α′ 0,001', '310/321', '18/2.311', '11,13 s', '530 / 15 (hỏng)'],
], [2.6, 2.4, 1.6, 1.4, 2.0], size=13, note_size=13, notes=[
    '**Protocol lidds2019-development-v1** (đăng ký 18/11 20:28): ứng viên phải giữ LID-DS 2021 development (≥ 530/544, ≤ 6 báo nhầm) và CB-DS.',
    '**Theo protocol gốc: giữ lidds-ml-v5.** Ứng viên tăng recall chỉ tăng ở Heartbleed (7/23 → 22/23) và đều hỏng mức 2021; sau đó amendment 1 nới mức này một phát hiện (slide sau).',
    '**Mở rộng:** 90 tổ hợp (n × top-k × trim × α′, chấm lại cả LID-DS 2021) và nhánh tần suất: chỉ cấu hình gốc qua điều kiện; không tổ hợp nào hơn 530 trên 2021 development.',
    '**Cận dưới độ trễ:** cửa sổ đầu tiên có gram chưa thấy sau mốc exploit đến ở p95 9,39 s (Bruteforce 13,1 s, Heartbleed 10,7 s): không bộ phát hiện dựa trên độ lạ nào đạt p95 ≤ 3 s trên dữ liệu này. C1 là giới hạn của dữ liệu.',
    'Code: scripts/analysis/lidds2019_dev.py, scripts/lidds2019_dev_run.sh.',
])

slide('LID-DS 2019: cấu hình t3 (amendment 1)', [
    ['Tập', 'Cấu hình', 'Phát hiện', 'Báo nhầm', 'p95'],
    ['LID-DS 2021 official', 'v5', '1.238/1.271 (97,40%)', '26/7.938 (0,33%)', '1,47 s'],
    ['LID-DS 2021 official', 't3', '1.236/1.271 (97,25%)', '15/7.938 (0,19%)', '1,54 s'],
    ['LID-DS 2019 holdout, dung sai 1 s', 'v5', '761/841 (90,49%)', '28/5.395 (0,52%)', '10,57 s'],
    ['LID-DS 2019 holdout, dung sai 1 s', 't3', '817/841 (97,15%)', '25/5.395 (0,46%)', '10,95 s'],
], [3.0, 1.2, 2.4, 2.2, 1.2], size=13, note_size=13, notes=[
    '**Amendment 1** (đăng ký 18/11 21:08, trước hai lượt chấm): chủ đồ án nới mức 2021 development một phát hiện, khi đã biết kết quả development; chọn n 4, top 3, trim 0,5%, α′ 0,0003.',
    '**2021:** ít hơn 2 phát hiện, ít hơn 11 báo nhầm, mức đăng ký vẫn đạt. **2019:** recall và báo nhầm đạt, p95 không đạt; phần tăng ở Heartbleed (17 → 73/77).',
    '**Công bố:** holdout đã được v5 chấm trước khi chia; quy tắc dung sai đặt sau lượt chấm.',
    'Code: scripts/analysis/lidds2019_dev.py, scripts/lidds2019_amendment1_run.sh.',
])

slide('Vòng cải thiện D1–D18: hướng được nhận', [
    ['Hướng', 'Kết quả', 'Quyết định'],
    ['D1 map 4-gram đầy thành cảnh báo', 'Báo đúng cgroup gây đầy, trễ 0 s', 'Nhận'],
    ['D2 mốc cuối cửa sổ của loader', 'Tính từ hằng số cửa sổ', 'Nhận'],
    ['D3 hàng đợi bền cho bridge', 'Giữ trên đĩa, thử lại tới 1 giờ', 'Nhận'],
    ['D7 chi phí trên request thật', 'p50 +10,5 ms, p95 +15,9 ms (+5,7%), 0 lỗi', 'Đo xong'],
    ['D9 học lại sau mỗi lần đổi cụm', 'Quy tắc vận hành', 'Nhận'],
    ['D12 tấn công chậm, bật-tắt', '0,1 và 0,5 lần/s; chu kỳ 10 s', 'Lượt cuối'],
    ['D13 né bằng io_uring', 'Seccomp trả EPERM trong pod', 'Đã đóng'],
    ['D18 Falco event-generator', '14 hành động, bản tĩnh chạy cả trong image musl', 'Lượt cuối'],
], [3.6, 4.4, 2.0], size=13, note_size=13, notes=[
    '**Protocol improvement-round-v1** (+ amendment 1–4) đăng ký trước mọi phép tính; lượt v7 dừng trước tấn công để làm vòng này. Thêm: nhãn stream trên cảnh báo, ghi sự kiện Kubernetes.',
    'Code: collector/token_capture.py, ops/alert_bridge.py, scripts/map_overflow_test.py, scripts/app_overhead_ab.py, attack/preview_campaign.py.',
])

slide('Vòng cải thiện D1–D18: hướng không nhận', [
    ['Hướng', 'Kết quả'],
    ['D4 ghép top 3 và top 10', 'LID-DS 2021 development 7 báo nhầm'],
    ['D5 mô hình riêng cho dòng session', 'Gắn cờ lệnh quản trị 470/475, binary vô hại 525/525'],
    ['D6 probe chỉ hook 5 họ syscall', 'Không nhanh hơn ở mọi thao tác'],
    ['D8 token chi tiết hơn', 'Mất 3 phát hiện LID-DS 2021 development'],
    ['D10, D11 gom sự cố, đồng thuận replica', 'Lượt v6 chỉ 4 đợt normal, đều một replica'],
    ['D14 Kneser-Ney', 'LID-DS 2019 development 288/321'],
    ['D15 CUSUM', 'LID-DS 2021 development 9–46 báo nhầm'],
    ['D16 ngưỡng GEV gộp hình dạng', 'Trên 2021 official mất 3 phát hiện'],
    ['D17 ngữ cảnh process', 'CB-DS 3 → 2 báo nhầm, 2019 không đổi'],
], [4.0, 6.0], size=13, note_size=14, notes=[
    '**Không cần chạy lại dataset:** không hướng được nhận nào đổi cách chấm trên dataset.',
    'Code: scripts/analysis/improvement_offline.py, rich_token_cache.py, session_channel.py, burden_context.py.',
])

slide('Lượt live cuối pulse-live-final-1119 (đang chạy)', [
    ['Hạng mục', 'Nội dung'],
    ['Hệ thống', 't3, bộ mô hình pulse-live-v7-fit-1118, probe pulse-tokens-final-f8ccbb2'],
    ['Campaign', '945 trial: 525 cơ bản, 210 chậm (0,5 và 0,1/s), 105 PAD 300, 105 bật-tắt'],
    ['Mỗi trial', 'control, lệnh quản trị, binary vô hại, tấn công, lotl, event-generator'],
    ['Thời lượng', '45 giờ, 19/11 09:50 → khoảng 21/11 06:50; 6 giờ normal cuối'],
    ['Diễn tập', 'Mọi bước chạy; bridge 37/37; 138 s mỗi trial'],
    ['19/11 22:41', '309/945 cặp xong'],
], [2.4, 7.6], size=13, note_size=13, notes=[
    '**Protocol pulse-live-final-v1** (đăng ký 09:39): H0, H3 pha loãng, H7 tấn công chậm, H8 bật-tắt; báo cáo kèm lotl, event-generator, quản trị, binary vô hại, dòng native, gánh, RCA.',
    '**Sự cố nhỏ:** bộ ghi sự kiện K8s dừng theo phiên SSH, chạy lại sau 70 phút; phần mất thật khoảng 10 phút, trước tấn công.',
    'Code: pipeline/plan_matched_run.py, scripts/launch_run.sh, scripts/k8s_events_record.py.',
])

slide('Paper, mã nguồn và tài nguyên', notes=[
    '**Paper** theo phương pháp PaperOrchestra, form USENIX Security \'27 (hạn cycle 2: 26/01/2027): bản nháp 13 trang; 53 tài liệu, 47 đã kiểm; số v6 và LID-DS 2019 đã điền; hình tổng quan đã vẽ; còn cập nhật t3 và lượt cuối. Code: paper/latex/, paper/tools/.',
    '**Tài liệu mới:** docs/LUONG_CODE.md (luồng code, ví dụ thật, quy trình và lệnh), docs/architecture/KIEN_TRUC.md (thành phần của hình kiến trúc và code).',
    '**Chú thích tiếng Việt cho toàn bộ code** (177 file), kiểm tự động là chỉ đổi comment; hướng dẫn đọc code notes/CODE_READING_GUIDE.md.',
    '**Kiểm toán số liệu đồ án:** 130/130 câu khớp biên nhận (scripts/audit/headline_numbers.py).',
    '**Dọn tài nguyên:** nén không mất dữ liệu segment của 5 lượt (2.360 file, kiểm SHA-256), NFS trống 595 GB; xoá unit, config, file tạm của các lượt đã xong. Code: scripts/compress_raw_frames.py.',
], note_size=16)

slide('Tuần này: các lượt chạy và job', [
    ['Lượt / job', 'Thời gian', 'Kết quả'],
    ['ml-final-study-v1 B2, B3; thẻ dòng dõi', '13/11', 'Học thêm không đạt; proof thẻ 8/8'],
    ['Luật R1, R2; nhánh tần suất', '15/11', 'Quản trị 97,7% → 0; tần suất không thêm gì'],
    ['Chi phí thẻ; sức chứa map', '16/11', 'Không đo được; dư khoảng 20 lần'],
    ['pulse-token-capture-v6-1116, fit', '16–17/11', 'Normal 12 giờ; lão hoá 0,59%; 21 mô hình'],
    ['pulse-live-v6-1117', '17–18/11', '735/735 trial; H0, H1, H3 đạt; R1 không nhận'],
    ['LID-DS 2019 (một lần)', '18/11', '90,88% (dung sai nhãn 1 s); C1 không đạt'],
    ['LID-DS 2019 development (30%)', '18/11', '23 + 90 ứng viên; giữ v5 theo protocol gốc'],
    ['LID-DS 2019 amendment 1 (t3)', '18/11', 'Holdout 817/841; 2021 official 1.236, 15 báo nhầm'],
    ['Fit v7 (t3); vòng cải thiện D1–D18', '18–19/11', '21 mô hình; nhận D1, D2, D3'],
    ['Diễn tập; pulse-live-final-1119', '19–21/11', 'Diễn tập đạt; lượt cuối đang chạy'],
    ['Paper, chú thích code, dọn tài nguyên', '17–18/11', '12 trang; 177 file; NFS trống 595 GB'],
], [3.8, 1.5, 4.7], size=14, notes=[
    '**Việc đã hẹn 13/11:** lượt mới trên cấu hình VM mới (xong), LID-DS 2019 (xong), so sánh có và không có luật (xong; luật danh mục ý đồ đo lại sau lượt cuối). Không sự cố hạ tầng.',
])

slide('Tiến độ', [
    ['Hạng mục', 'Hoàn thành', 'Còn lại'],
    ['ML trên dataset', '~98%', 'LID-DS 2019: p95 là giới hạn của dữ liệu'],
    ['Probe token và chi phí', '~95%', 'Xong; chi phí trên request thật đã đo'],
    ['Lượt live của ML', '~90%', 'Lượt cuối đang chạy, phân tích sau 21/11'],
    ['Process mới vô hại', '~50%', 'Nhãn stream; dòng session cần cách xử lý riêng'],
    ['RCA và đường cảnh báo', '~95%', 'Hàng đợi bền đã có'],
    ['So sánh có và không có luật', '~70%', 'Luật danh mục ý đồ sau lượt cuối'],
    ['Viết đồ án (LaTeX)', '~88%', 'Cập nhật t3 và lượt cuối'],
    ['Paper', '~50%', 'Cập nhật t3, lượt cuối, vòng chỉnh'],
    ['Đồ án tổng thể', '~92%', 'Tăng từ ~85% ở buổi 13/11'],
], [3.8, 1.6, 4.6], size=14, notes=['Các tỉ lệ là ước lượng, không phải số đo.'])

slide('Việc tiếp theo và câu hỏi cho thầy', notes=[
    '**Sau 21/11:** phân tích lượt cuối theo protocol, so sánh có và không có luật danh mục ý đồ, cập nhật đồ án, paper, báo cáo, slide sang t3 và kết quả lượt cuối.',
    '**Dòng session:** cảnh báo đã mang nhãn stream; mô hình riêng cho session (D5) không tách được tấn công khỏi lệnh quản trị.',
    '**Câu hỏi 1:** LID-DS 2019 — t3 đạt recall và báo nhầm, p95 không xuống 3 s vì cận dưới của dữ liệu (9,39 s); đồng ý để độ trễ 2019 là giới hạn?',
    '**Câu hỏi 2:** dòng session — để là giới hạn của đồ án, hay làm đường cảnh báo theo dòng dõi trước khi bảo vệ?',
    '**Câu hỏi 3:** paper có cần baseline tự chạy (STIDE, Isolation Forest) ngoài các số đã công bố không?',
], note_size=17)
