# Content of the 20/11 deck (progress 13/11 -> 20/11/2026), run by docs/meetings/2026-11-13/make_deck_1311.py on the owner's
# 13/11 deck. Numbers from notes/WORKLOG.md and validation-evidence/results-20261113..20261118 (same as the report).
FIG = sys.argv[4]

slide('Cấu trúc bài trình bày (tiến độ 13/11 – 20/11/2026)', notes=[
    'Kết quả chính',
    'Hệ thống: kiến trúc, probe có thẻ dòng dõi, code của từng phần',
    'Process mới vô hại: học thêm hoạt động quản trị, tách theo dòng dõi',
    'Chi phí thẻ dòng dõi, sức chứa map; luật R1, R2 và nhánh tần suất',
    'Lượt live thứ ba pulse-live-v6-1117 (26 giờ, 735 trial)',
    'LID-DS 2019: chấm một lần, độ phân giải của nhãn, phần còn lại',
    'Paper, code, dọn tài nguyên; tiến độ, việc tiếp theo, câu hỏi cho thầy',
], note_size=18)

slide('Kết quả chính', [
    ['', 'Recall', 'Báo nhầm / control', 'p95'],
    ['Live blind pulse-live-v6-1117, tập chính', '315/315', '1/315', '0,45 s'],
    ['Tấn công pha loãng PAD 30 / PAD 300', '105/105 / 105/105', '', ''],
    ['LID-DS 2021 official (không đổi)', '1.238/1.271 (97,40%)', '26/7.938 (0,33%)', '1,47 s'],
    ['LID-DS 2019 (một lần, đăng ký)', '723/1.162 (62,22%)', '34/7.706 (0,44%)', '10,48 s'],
    ['Kỳ vọng', '≥ 95%', '≤ 5% (control), ≤ 1% (bản ghi)', '≤ 3 s'],
], [3.6, 2.3, 2.4, 1.7], notes=[
    '**Mô hình giữ lidds-ml-v5;** trên cụm học lại từ normal mới (pulse-live-v6-fit-1117).',
    '**Thẻ dòng dõi:** chỉ chấm phần native thì lệnh quản trị 1/475, binary vô hại 1/525 bị gắn cờ (cả cửa sổ: 460/475, 525/525).',
    '**Luật R1 không nhận:** xoá báo nhầm quản trị nhưng cũng xoá mọi tấn công dùng tool của image (314/315 → 0/315).',
    '**LID-DS 2019 không đạt C1;** với dung sai nhãn 1 s (phân tích sau): 1.056/1.162 (90,88%), vẫn dưới 95%.',
])

slide('Kiến trúc hệ thống', notes=[
    '**Không đổi so với 13/11**, trừ thẻ dòng dõi trong probe: chương trình BPF thứ tư gắn vào sched_process_fork; loader cộng hai dòng thành cửa sổ như cũ và in thêm phần session. Worker chấm như lượt v5.',
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
    ['Proof thẻ dòng dõi', 'scripts/lineage_probe_proof.py'],
], [3.0, 7.0], size=13)

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

slide('LID-DS 2019: chấm một lần (lidds2019-confirmation-v2)', [
    ['Kịch bản', 'Đăng ký', 'Dung sai 1 s (sau)', 'Báo nhầm'],
    ['Bruteforce_CWE-307', '92/98', '92/98', '5/744'],
    ['CVE-2012-2122', '91/155', '152/155', '1/990'],
    ['CVE-2014-0160 (Heartbleed)', '24/100', '24/100', '5/750'],
    ['CVE-2017-7529', '30/174', '157/174', '0/733'],
    ['CVE-2018-3760', '52/137', '133/137', '0/834'],
    ['CVE-2019-5418', '34/98', '98/98', '0/731'],
    ['EPS, PHP, SQL, ZipSlip', '400/400', '400/400', '23/2.924'],
    ['Tổng', '723/1.162 (62,22%)', '1.056/1.162 (90,88%)', '34/7.706 (0,44%)'],
], [3.4, 2.3, 2.5, 1.8], size=13, notes=[
    '**C1 không đạt** (recall ≥ 95%, báo nhầm ≤ 1%, p95 ≤ 3 s): chỉ báo nhầm đạt, p95 10,48 s. Driver tái lập đúng official 2021 trước khi đọc 2019.',
], note_size=14)

slide('LID-DS 2019: độ phân giải của nhãn và phần còn lại', notes=[
    '**Mốc exploit của 2019 là số nguyên giây.** 353/439 bản ghi lọt có cửa sổ báo kết thúc trước mốc nhãn (trung bình 0,36 s), không báo sau đó.',
    '**Amendment 1 (đăng ký sau khi thấy thất bại, báo bên cạnh):** dung sai 1 s → 1.056/1.162 (90,88%), báo nhầm không đổi; LID-DS 2021 official vẫn 1.238/1.271.',
    '**Còn lại:** Heartbleed 76/100 bản ghi không có cảnh báo nào; độ trễ Bruteforce và Heartbleed kéo p95 lên 10,55 s. Mã lỗi của trace 2019 cùng định dạng 2021.',
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
    '**Kết quả: giữ lidds-ml-v5, không chấm thêm gì.** Ứng viên tăng recall chỉ tăng ở Heartbleed (7/23 → 22/23) và đều hỏng mức 2021.',
    '**Mở rộng:** 90 tổ hợp (n × top-k × trim × α′, chấm lại cả LID-DS 2021) và nhánh tần suất: chỉ cấu hình gốc qua điều kiện; không tổ hợp nào hơn 530 trên 2021 development.',
    '**Cận dưới độ trễ:** cửa sổ đầu tiên có gram chưa thấy sau mốc exploit đến ở p95 9,39 s (Bruteforce 13,1 s, Heartbleed 10,7 s): không bộ phát hiện dựa trên độ lạ nào đạt p95 ≤ 3 s trên dữ liệu này. C1 là giới hạn của dữ liệu.',
    'Code: scripts/analysis/lidds2019_dev.py, scripts/lidds2019_dev_run.sh.',
])

slide('Paper, mã nguồn và tài nguyên', notes=[
    '**Paper** theo phương pháp PaperOrchestra, form USENIX Security \'27 (hạn cycle 2: 26/01/2027): bản nháp 12 trang; 53 tài liệu, 47 đã kiểm; bib sinh từ metadata đã kiểm; còn 14 chỗ chờ số. Code: paper/latex/, paper/tools/.',
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
    ['LID-DS 2019 và amendment 1', '18/11', '62,22%; dung sai 1 s 90,88%'],
    ['LID-DS 2019 development (30%)', '18/11', '23 ứng viên; giữ v5'],
    ['Paper, chú thích code, dọn tài nguyên', '17–18/11', '12 trang; 177 file; NFS trống 595 GB'],
], [3.8, 1.5, 4.7], size=14, notes=[
    '**Việc đã hẹn 13/11:** lượt mới trên cấu hình VM mới (xong), LID-DS 2019 (xong), so sánh có và không có luật (xong). Không sự cố hạ tầng.',
])

slide('Tiến độ', [
    ['Hạng mục', 'Hoàn thành', 'Còn lại'],
    ['ML trên dataset', '~97%', 'LID-DS 2019: ghi là giới hạn'],
    ['Probe token và chi phí', '~90%', 'Chi phí trên request thật'],
    ['Live blind của ML', '~95%', 'Ba lượt xong'],
    ['Process mới vô hại', '~45%', 'Dòng session cần cách xử lý riêng'],
    ['RCA và đường cảnh báo', '~92%', 'Hàng đợi bền cho bridge'],
    ['So sánh có và không có luật', '~70%', 'Luật theo dòng dõi nếu làm tiếp'],
    ['Viết đồ án (LaTeX)', '~90%', 'Chỉnh văn, phụ lục'],
    ['Paper', '~45%', 'Điền số, hình, vòng chỉnh'],
    ['Đồ án tổng thể', '~90%', 'Tăng từ ~85% ở buổi 13/11'],
], [3.8, 1.6, 4.6], size=14, notes=['Các tỉ lệ là ước lượng, không phải số đo.'])

slide('Việc tiếp theo và câu hỏi cho thầy', notes=[
    '**Dòng session:** đường cảnh báo theo dòng dõi (native dùng mô hình workload, session báo kèm cho người vận hành); cần protocol mới và một lượt live.',
    '**Paper:** điền số v6 và LID-DS 2019, tiêu đề, abstract, hình, vòng chỉnh, ẩn danh.',
    '**Câu hỏi 1:** LID-DS 2019 — thử trên development không cải thiện được mà vẫn giữ LID-DS 2021; đồng ý để kết quả đăng ký là giới hạn?',
    '**Câu hỏi 2:** dòng session — để là giới hạn của đồ án, hay làm đường cảnh báo theo dòng dõi trước khi bảo vệ?',
    '**Câu hỏi 3:** paper có cần baseline tự chạy (STIDE, Isolation Forest) ngoài các số đã công bố không?',
], note_size=17)
