"""Progress report 13/11 -> 20/11/2026, built inside the owner's edited 13/11 report (cover page, styles, footers, numbering).

Usage (from an empty work dir): unzip docs/Bao_cao_tien_do_06_11-13_11.docx into x/, then
    python3 report_build.py FIGDIR        # FIGDIR holds overview.png and probe.png: docs/architecture/export/1-tong-quan.png, 2-probe-ebpf.png
    python3 ../2026-11-13/report_toc.py <skill>/scripts/office/soffice.py   # fills the TOC page numbers, writes out.docx
Every number comes from notes/WORKLOG.md and validation-evidence/results-20261113..20261119 (the thesis audit checks the
same numbers against the receipts).
"""
import re
import shutil
import sys
from xml.sax.saxutils import escape

from PIL import Image

DOC = 'x/word/document.xml'
FIG = sys.argv[1]
d = open(DOC, encoding='utf-8').read()

BORDER = ''.join(f'<w:{e} w:val="single" w:sz="4" w:space="0" w:color="000000"/>' for e in ('top', 'left', 'bottom', 'right'))
RPR28 = '<w:rFonts w:eastAsia="Arial" w:cs="Arial"/>{b}<w:i w:val="false"/><w:iCs w:val="false"/><w:color w:val="000000"/><w:sz w:val="28"/><w:szCs w:val="28"/>'


def runs(text):
    """'**bold** rest' -> runs."""
    out = []
    for i, part in enumerate(text.split('**')):
        if part:
            rpr = '<w:rPr><w:b/><w:bCs/></w:rPr>' if i % 2 else '<w:rPr></w:rPr>'
            out.append(f'<w:r>{rpr}<w:t xml:space="preserve">{escape(part)}</w:t></w:r>')
    return ''.join(out)


def left(text):
    return '<w:jc w:val="left"/>' if ('/' in text or '_' in text) else ''


def P(text, style='BodyText'):
    return f'<w:p><w:pPr><w:pStyle w:val="{style}"/>{left(text)}<w:rPr></w:rPr></w:pPr>{runs(text)}</w:p>'


def B(text):
    return (f'<w:p><w:pPr><w:pStyle w:val="Compact"/><w:numPr><w:ilvl w:val="0"/><w:numId w:val="1"/></w:numPr>{left(text)}'
            f'<w:rPr></w:rPr></w:pPr>{runs(text)}</w:p>')


def CODE(text):
    return P('**Code:** ' + text)


def cell(text, w, head):
    shade = '<w:shd w:color="auto" w:fill="F2F2F2" w:val="clear"/>' if head else ''
    rs = ''
    for i, part in enumerate(text.split('**')):
        if part:
            b = '<w:b/><w:bCs/>' if head or i % 2 else ''
            rs += f'<w:r><w:rPr>{b}<w:sz w:val="22"/><w:szCs w:val="22"/></w:rPr><w:t xml:space="preserve">{escape(part)}</w:t></w:r>'
    return (f'<w:tc><w:tcPr><w:tcW w:w="{w}" w:type="dxa"/><w:tcBorders>{BORDER}</w:tcBorders>{shade}</w:tcPr>'
            f'<w:p><w:pPr><w:pStyle w:val="Normal"/><w:spacing w:lineRule="auto" w:line="276" w:before="0" w:after="0"/>'
            f'<w:jc w:val="left"/><w:rPr></w:rPr></w:pPr>{rs}</w:p></w:tc>')


def T(rows, weights):
    ws = [round(9638 * x / sum(weights)) for x in weights]
    ws[-1] = 9638 - sum(ws[:-1])
    grid = ''.join(f'<w:gridCol w:w="{w}"/>' for w in ws)
    trs = ''
    for i, r in enumerate(rows):
        trpr = '<w:trPr><w:tblHeader w:val="true"/><w:cantSplit/></w:trPr>' if i == 0 else '<w:trPr><w:cantSplit/></w:trPr>'
        trs += '<w:tr>' + trpr + ''.join(cell(t, w, i == 0) for t, w in zip(r, ws)) + '</w:tr>'
    return (f'<w:tbl><w:tblPr><w:tblW w:w="9638" w:type="dxa"/><w:jc w:val="left"/><w:tblInd w:w="95" w:type="dxa"/>'
            f'<w:tblLayout w:type="fixed"/><w:tblCellMar><w:top w:w="70" w:type="dxa"/><w:left w:w="100" w:type="dxa"/>'
            f'<w:bottom w:w="70" w:type="dxa"/><w:right w:w="100" w:type="dxa"/></w:tblCellMar></w:tblPr>'
            f'<w:tblGrid>{grid}</w:tblGrid>{trs}</w:tbl>') + P('', 'BodyText')


FIGS = {'overview': ('rId2', 'image1.png'), 'probe': ('rId3', 'image2.png')}


def IMG(name, caption, width_in=6.6):
    """The two figures reuse the 13/11 image parts (rId2, rId3), whose files are replaced by the new renders."""
    rid, media = FIGS[name]
    shutil.copy(f'{FIG}/{name}.png', f'x/word/media/{media}')
    im = Image.open(f'{FIG}/{name}.png')
    cx = int(width_in * 914400)
    cy = int(cx * im.size[1] / im.size[0])
    n = 1 if name == 'overview' else 2
    drawing = (f'<w:drawing><wp:inline distT="0" distB="0" distL="0" distR="0"><wp:extent cx="{cx}" cy="{cy}"/>'
               f'<wp:docPr id="{900 + n}" name="Hinh {n}"/><wp:cNvGraphicFramePr><a:graphicFrameLocks noChangeAspect="1"/></wp:cNvGraphicFramePr>'
               f'<a:graphic><a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/picture"><pic:pic>'
               f'<pic:nvPicPr><pic:cNvPr id="{900 + n}" name="{name}.png"/><pic:cNvPicPr/></pic:nvPicPr>'
               f'<pic:blipFill><a:blip r:embed="{rid}"/><a:stretch><a:fillRect/></a:stretch></pic:blipFill>'
               f'<pic:spPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="{cx}" cy="{cy}"/></a:xfrm><a:prstGeom prst="rect"><a:avLst/></a:prstGeom></pic:spPr>'
               f'</pic:pic></a:graphicData></a:graphic></wp:inline></w:drawing>')
    pic = (f'<w:p><w:pPr><w:pStyle w:val="Normal"/><w:keepNext/><w:spacing w:before="120" w:after="60"/><w:jc w:val="center"/><w:rPr></w:rPr></w:pPr>'
           f'<w:r><w:rPr></w:rPr>{drawing}</w:r></w:p>')
    cap = (f'<w:p><w:pPr><w:pStyle w:val="Normal"/><w:spacing w:before="0" w:after="160"/><w:jc w:val="center"/><w:rPr></w:rPr></w:pPr>'
           f'<w:r><w:rPr><w:i/><w:iCs/><w:sz w:val="24"/><w:szCs w:val="24"/></w:rPr><w:t xml:space="preserve">{escape(caption)}</w:t></w:r></w:p>')
    return pic + cap


BOOK = [0]


def H1(text):
    BOOK[0] += 1
    return (f'<w:p><w:pPr><w:pStyle w:val="Heading1"/><w:rPr></w:rPr></w:pPr><w:bookmarkStart w:id="{BOOK[0]}" w:name="h{BOOK[0]}"/>'
            f'<w:r><w:rPr><w:b/><w:bCs/></w:rPr><w:t>{escape(text)}</w:t></w:r><w:bookmarkEnd w:id="{BOOK[0]}"/></w:p>')


def H2(text):
    return f'<w:p><w:pPr><w:pStyle w:val="Heading2"/><w:rPr></w:rPr></w:pPr><w:r><w:rPr></w:rPr><w:t>{escape(text)}</w:t></w:r></w:p>'


def TOC(text, level):
    b = '<w:b/><w:bCs/>' if level == 1 else '<w:b w:val="false"/><w:bCs w:val="false"/>'
    spacing = '<w:spacing w:before="100" w:after="80"/><w:ind w:left="0"/>' if level == 1 else '<w:spacing w:before="0" w:after="40"/><w:ind w:left="360"/>'
    rpr = RPR28.format(b=b)
    return (f'<w:p><w:pPr><w:pStyle w:val="Normal"/><w:tabs><w:tab w:val="clear" w:pos="720"/><w:tab w:val="right" w:pos="9638" w:leader="dot"/></w:tabs>'
            f'{spacing}<w:rPr></w:rPr></w:pPr><w:r><w:rPr>{rpr}</w:rPr><w:t>{escape(text)}</w:t></w:r>'
            f'<w:r><w:rPr>{rpr}</w:rPr><w:tab/><w:t>1</w:t></w:r></w:p>')


# ===================================================================================================== content
S = []          # (level, title) for the TOC
BODY = []


def h1(t):
    S.append((1, t))
    BODY.append(H1(t))


def h2(t):
    S.append((2, t))
    BODY.append(H2(t))


def add(*xs):
    BODY.extend(xs)


h1('1. Tóm tắt nhanh')
add(
    B('**Mô hình ML: lidds-ml-v5-t3** (mô hình ngôn ngữ 4-gram trên token syscall, chỉ học từ normal; điểm cửa sổ là trung bình 3 thay vì 10 độ bất ngờ lớn nhất, bỏ 0,5% cực đại, α′ 0,0003). Chủ đồ án chọn cấu hình này sau thử nghiệm trên phần development của LID-DS 2019 (amendment 1). Lượt live v6 bên dưới vẫn chạy lidds-ml-v5.'),
    B('**Cấu hình t3:** LID-DS 2021 official 1.236/1.271 (97,25%), báo nhầm 15/7.938 (0,19%), p95 1,54 s (v5: 1.238, 26, 1,47 s); LID-DS 2019 holdout 70% với dung sai nhãn 1 s 817/841 (97,15%), báo nhầm 25/5.395 (0,46%), p95 10,95 s (v5: 761/841). Holdout đã được v5 chấm trước khi chia, và quy tắc dung sai đặt sau lượt chấm.'),
    B('**Vòng cải thiện improvement-round-v1 (D1–D18), trước lượt live cuối:** nhận cảnh báo khi map 4-gram đầy, sửa mốc cửa sổ của loader, hàng đợi bền cho bridge, nhãn native/session trên cảnh báo, ghi sự kiện Kubernetes, tấn công chậm và bật-tắt, Falco event-generator; 10 hướng khác đo xong và không nhận. Chi phí probe trên request thật: p95 +15,9 ms (+5,7%).'),
    B('**Lượt live cuối pulse-live-final-1119 đang chạy** (từ 19/11 09:50, 45 giờ, 945 trial, kết thúc khoảng 21/11 06:50) sau một lượt diễn tập đạt; hình kiến trúc cập nhật theo hệ thống của lượt này.'),
    B('**Lượt live thứ ba pulse-live-v6-1117 (26 giờ, 735 trial) đạt mọi kỳ vọng đăng ký trước:** tấn công tập chính 315/315, control 1/315, precision 99,68%, p95 0,45 s; tấn công pha loãng bằng 30 và 300 cặp syscall quen mỗi thao tác vẫn bị bắt 105/105 ở mỗi mức.'),
    B('**Thẻ dòng dõi native/session trong probe** (telemetry, không đổi đường cảnh báo): chỉ chấm phần native thì lệnh quản trị bị gắn cờ 1/475 và binary vô hại 1/525, so với 460/475 và 525/525 khi chấm cả cửa sổ. Đây là cơ chế học được đầu tiên tách process vô hại mới khỏi hành vi của workload. Giá: tấn công của campaign vào qua kubectl exec nên không nằm trong phần native (0/525).'),
    B('**Luật R1 (hạ cảnh báo khi chỉ có tool có sẵn trong image) không được nhận:** nó xoá báo nhầm lệnh quản trị (97,7% về 0) nhưng cũng xoá mọi tấn công dùng tool của image (314/315 về 0/315).'),
    B('**LID-DS 2019 với lidds-ml-v5 (lượt chấm theo protocol, dung sai nhãn 1 s):** phát hiện 1.056/1.162 (90,88%), báo nhầm 34/7.706 (0,44%), p95 10,55 s; không đạt C1 vì Heartbleed (24/100) và độ trễ. Trên 30% development không ứng viên nào giữ đúng mức LID-DS 2021 cũ mà tăng recall; nới mức đó một phát hiện (amendment 1) thì t3 qua và được chọn (mục 6.4).'),
    B('**Ngoài ra:** chi phí của thẻ dòng dõi không đo được; map 4-gram dư khoảng 20 lần so với tải thật; RCA sau bản sửa có case riêng cho 711/735 tấn công; paper bản nháp 12 trang theo form USENIX Security; chú thích tiếng Việt cho toàn bộ code và hướng dẫn đọc code; dọn tài nguyên (NFS trống 595 GB).'),
)

h1('2. Hệ thống sau tuần này')
h2('2.1 Kiến trúc')
add(
    P('Hình 1 là hệ thống của lượt live cuối. So với 13/11: (1) thẻ dòng dõi trong kernel, một chương trình BPF thứ tư gắn vào sched_process_fork, mỗi 4-gram được đếm riêng theo dòng dõi của thread, loader cộng hai dòng lại thành cửa sổ như cũ và in thêm phần session; (2) mô hình t3; (3) map 4-gram đầy thì worker báo cửa sổ nặng nhất (D1); (4) bridge giữ đợt chưa giao trong hàng đợi bền trên đĩa và gắn nhãn stream native/session cho cảnh báo (D3). Hình vẽ đầy đủ 5 trang (tổng quan, probe, worker và mô hình, đường cảnh báo, học và đánh giá; mỗi hộp ghi đường dẫn code) và bảng ánh xạ từng thành phần sang code nằm trong docs/architecture/. Phần RCA tạm bỏ khỏi hình, sẽ cập nhật sau.', 'FirstParagraph'),
    IMG('overview', 'Hình 1. Kiến trúc hệ thống của lượt live cuối (hình draw.io, trang 1: tổng quan).'),
    T([['Thành phần', 'Code'],
       ['Probe eBPF (token, 4-gram, thẻ dòng dõi)', 'sentinel_pulse/ebpf/pulse_counter.bpf.c, pulse_tokens.bpf.h (pulse_tok_lineage, pulse_tok_fork), pulse_token_ids.h'],
       ['Loader', 'sentinel_pulse/ebpf/pulse_counter_loader.c'],
       ['Worker chấm điểm', 'sentinel_pulse/pipeline/matched_worker.py, sentinel_pulse/detector/token_model.py, sentinel_pulse/collector/token_capture.py'],
       ['Học mô hình trên cụm', 'scripts/analysis/token_branch_fit.py'],
       ['Bridge cảnh báo, RCA', 'sentinel_pulse/ops/alert_bridge.py, sentinel_pulse/rca/service.py'],
       ['Campaign tấn công và đối chứng', 'sentinel_pulse/attack/preview_campaign.py'],
       ['Cảnh báo map đầy (D1), hàng đợi bền (D3)', 'sentinel_pulse/collector/token_capture.py (MapOverflow), sentinel_pulse/ops/alert_bridge.py (PushQueue, stream_of)'],
       ['Dựng và chạy một lượt', 'sentinel_pulse/pipeline/plan_matched_run.py, scripts/launch_run.sh, scripts/k8s_events_record.py'],
       ['Hình kiến trúc và mô tả code', 'docs/architecture/ (make_architecture_drawio.py, KIEN_TRUC.md), docs/LUONG_CODE.md']], [3.2, 6.8]),
)
h2('2.2 Probe và thẻ dòng dõi')
add(
    P('Mỗi thread mang một thẻ: native (cây process của chính workload) hoặc session (vào qua runtime exec, và mọi process con của nó). Lúc fork, thread con nhận thẻ của cha trước khi chạy. Thread lần đầu gặp mà chưa có trạng thái thì lấy thẻ của thread-group leader; không có thì lấy của cha nếu cha cùng cgroup; không có nữa thì là native khi pid của nó trong pid namespace là 1 (entrypoint của container), còn lại là session.', 'FirstParagraph'),
    IMG('probe', 'Hình 2. Probe eBPF (hình draw.io, trang 2): bốn chương trình BPF, các map, bố cục token 32 bit, loader.'),
    B('**Proof trên pod thật đạt 8/8:** vòng lặp của container và process con mà pid 1 fork là native; lệnh vào qua exec và con của nó là session; process con chạy nền sống lâu hơn phiên đã thoát vẫn giữ thẻ session. Proof token cũ vẫn đạt trên cả ba worker (mỗi syscall đúng một token).'),
    B('LID-DS 2021 không có runtime exec, nên mọi sự kiện là native và kết quả dataset không đổi.'),
    B('**Bản build của lượt cuối pulse-tokens-final-f8ccbb2** thêm cảnh báo khi map đầy và sửa mốc cửa sổ của loader; proof token đạt trên cả ba worker (361.900 / 442.796 / 393.644 lời gọi, mỗi lời gọi đúng một token).'),
    CODE('sentinel_pulse/ebpf/pulse_tokens.bpf.h, sentinel_pulse/ebpf/pulse_counter_loader.c; proof scripts/lineage_probe_proof.py; biên nhận validation-evidence/results-20261113/lineage-probe/.'),
)

h1('3. Process mới vô hại: học thêm, rồi tách theo dòng dõi')
add(P('Protocol ml-final-study-v1 (đăng ký 12/11, cùng amendment 1 và 2, trước mọi dòng code) thử hai hướng học, không dùng luật, trên dữ liệu của lượt v5.', 'FirstParagraph'))
h2('3.1 Học thêm hoạt động quản trị như normal không đủ')
add(
    B('Học thêm mọi lệnh quản trị trừ lệnh đang thử: lệnh bị giữ ra vẫn bị gắn cờ 362/439 (82,5%), so với 422/439 (96,1%) của mô hình v5. Học lệnh quản trị của các fold khác (B2): 372/439 (84,7%).'),
    B('Học thêm có giá: recall tập chính giảm từ 314/314 xuống 303/314. Mức chấp nhận đã đăng ký (lệnh giữ ra ≤ 20%) không đạt, nên mô hình không đổi.'),
)
h2('3.2 Tách theo dòng dõi')
add(
    B('**Proxy trên dữ liệu v5 (B3):** coi gram mà mô hình v5 chưa thấy là của phiên exec. Chấm phần còn lại (native) bằng đúng mô hình v5: control 0/525, lệnh quản trị 0/439, binary vô hại 0/523.'),
    B('**Mô hình riêng cho phiên exec thì không dùng được:** với cùng quy tắc ngưỡng Gumbel trên vài trăm phiên ngắn, ngưỡng là 37,7 (42,4 khi học cả binary vô hại), cao hơn mọi điểm đã đo, nên bắt 0/522 tấn công.'),
    B('**Quyết định (amendment 2):** chỉ thêm thẻ dòng dõi vào probe như telemetry và đo trên lượt live sau (giả thuyết H1, mục 5.3). Đường cảnh báo không đổi.'),
    CODE('scripts/analysis/live_attribution.py (B), scripts/analysis/session_model.py (B2, B3); biên nhận validation-evidence/results-20261113/ml-final-study/.'),
)
h2('3.3 Chi phí của thẻ dòng dõi và sức chứa của map')
add(
    B('**Thẻ dòng dõi không có chi phí đo được** (amendment 3 của token-probe-overhead-v1, 5 vòng, 3 worker): ở 12 ô (3 worker × 4 thao tác), khoảng tin cậy của tỉ lệ so với bản build v5 đều chứa 0, trừ một ô âm. Một lần fork + exit + wait tốn 332–385 µs trên các VM này, lớn hơn nhiều phần việc của hook.'),
    P('**Sức chứa của map 4-gram** (protocol map-capacity-v1): bộ sinh tải trong một cgroup, mọi syscall là một gram mới (trường hợp xấu nhất).'),
    T([['Syscall/s', 'Gram mỗi cửa sổ (trung vị)', 'Gram không ghi được', 'Thời gian đọc map'],
       ['100.000', '49.682', '0', '0,11 s'],
       ['200.000', '97.168', '0', '0,22 s'],
       ['300.000', '142.610', '0', '0,33 s'],
       ['400.000', '148.695', '949.878', '0,44 s'],
       ['800.000', '258.401', '4.888.620', '0,64 s']], [2, 3, 2.6, 2.4]),
    B('Map bắt đầu bỏ gram ở 400.000 syscall/s trên một cgroup. Cửa sổ nặng nhất của cả node ở lượt v5 chỉ có 6.901 gram, nên tải thật còn cách giới hạn khoảng 20 lần. Khi map đầy, worker không biết cửa sổ bị thiếu: đây là một đường né cho kẻ tấn công tạo tải lớn, ghi là giới hạn.'),
    CODE('scripts/overhead_ab.sh, scripts/analysis/overhead_ab.py; testbed/bench/gram_stress.c, scripts/map_capacity_test.py; biên nhận validation-evidence/results-20261116/lineage-overhead/, map-capacity/.'),
)

h1('4. Luật sau mô hình và nhánh tần suất')
h2('4.1 Luật R1 và R2 trên campaign v5')
add(
    P('Theo thứ tự "chốt ML trước, thêm luật sau", luật chạy trên cảnh báo của mô hình: R1 hạ một cảnh báo xuống mức thông tin khi cửa sổ chỉ có runtime exec của binary có sẵn trong image; R2 giữ cảnh báo của binary không thuộc image và gắn nhãn drift. Số đo tách rõ mô hình một mình và mô hình + luật.', 'FirstParagraph'),
    T([['Tập chính (6, 12, 24 lần/s)', 'Chỉ mô hình', 'Mô hình + luật'],
       ['Recall tấn công', '314/314', '314/314'],
       ['Báo nhầm lệnh quản trị (tool của image)', '256/262 (97,7%)', '0/262'],
       ['Exec vô hại không thuộc image', '314/314', '314/314 (giữ, nhãn drift)']], [4.6, 2.7, 2.7]),
    B('Mặt hại của R1 chỉ đo được khi có tấn công dùng chính tool của image; lượt v6 thêm bước đó (mục 5.4).'),
    CODE('scripts/analysis/rule_e_benefit.py; biên nhận validation-evidence/results-20261115/rule-e-benefit/.'),
)
h2('4.2 Nhánh tần suất (cho tấn công chỉ dùng chuỗi đã thấy)')
add(
    T([['Nhánh (cùng ngân sách)', 'LID-DS development: phát hiện / báo nhầm', 'CB-DS: phát hiện / báo nhầm'],
       ['Chỉ token (mô hình v5)', '530 / 6', '891 / 3'],
       ['Chỉ tần suất', '225 / 7', '891 / 3'],
       ['Token hoặc tần suất', '530 / 12', '891 / 4']], [3.6, 3.4, 3.0]),
    B('Nhánh tần suất không thêm phát hiện nào và chỉ thêm báo nhầm, nên không được nhận; nó giữ ở chế độ shadow. Giá trị của nó chỉ đo được bằng tấn công pha loãng trên cụm (mục 5.2).'),
    CODE('scripts/analysis/lidds_token_rate.py; biên nhận validation-evidence/results-20261115/w3b-rate-signal/.'),
)

h1('5. Lượt live thứ ba: pulse-live-v6-1117')
h2('5.1 Thiết kế lượt')
add(
    B('**Protocol pulse-live-v6-v1 và amendment 1**, đăng ký trước khi thu normal. Giả thuyết: H0 lặp lại kết quả v5, H1 dòng native, H3 pha loãng, H4 tấn công bằng tool của image và mặt hại của R1, H5 lệnh quản trị chưa từng thấy, H6 thứ tự bước và hạng RCA.'),
    B('**Thu normal 12 giờ** (pulse-token-capture-v6-1116, 16/11 14:14 tới 17/11 02:14): 3 worker, 0 lần chèn gram thất bại.'),
    B('**Mô hình có lão hoá:** mô hình v5 không đổi chấm normal mới cho 278/47.082 khối 60 s vượt ngưỡng (0,59%), so với 350/134.905 (0,26%) trên dữ liệu giữ ra của chính nó; phần tăng dồn vào các workload được tạo lại khi khôi phục cụm 12/11 (Redis 3,81%). Vì vậy mô hình được học lại: 21 mô hình, cùng thuật toán và tham số.'),
    B('**Campaign 735 trial trong 26 giờ:** 525 trial cơ bản như hai lượt trước, 105 trial PAD 30 và 105 trial PAD 300 (sau mỗi thao tác tấn công chèn 30 hoặc 300 cặp getpid + sched_yield). Mỗi trial còn có một lệnh quản trị lấy từ bộ 10 tool chưa lượt nào dùng, và một bước tấn công chỉ dùng sh, cat, ls có sẵn trong image (lotl). Thứ tự các bước sau control được xáo bằng seed.'),
    CODE('sentinel_pulse/attack/preview_campaign.py; scripts/analysis/model_aging.py, token_branch_fit.py; protocol sentinel_pulse/protocol/pulse-live-v6-v1.json, pulse-live-v6-v1-amendment-1.json.'),
)
h2('5.2 Kết quả chính (H0, H3)')
add(
    T([['Chỉ số', 'Kỳ vọng', 'Tập chính (6, 12, 24 lần/s)', 'Mọi tốc độ'],
       ['Recall', '≥ 95%', '315/315', '524/525'],
       ['Precision', '≥ 95%', '99,68%', '99,81%'],
       ['Control dương', '≤ 5%', '1/315 (0,32%)', '1/525'],
       ['p95 kernel → cuối cửa sổ báo', '≤ 3 s', '0,45 s (p50 0,25 s)', '0,46 s'],
       ['Tấn công pha loãng PAD 30 / PAD 300', '≥ 95%', '105/105 / 105/105', ''],
       ['Binary vô hại bị gắn cờ', 'báo kèm', '315/315', '525/525'],
       ['Lệnh quản trị chưa từng thấy bị gắn cờ', 'báo kèm', '275/284', '460/475'],
       ['Tấn công bằng tool của image bị bắt', 'báo kèm', '314/315', '524/525']], [3.6, 1.4, 2.8, 2.2]),
    B('**Lặp lại đạt sau khi đổi cụm và học lại**, kể cả hai mức pha loãng: điểm cửa sổ là trung bình 10 sự kiện bất ngờ nhất, nên chèn syscall quen không làm loãng các gram lạ của tấn công.'),
    B('Gánh cảnh báo 4 đợt trên 51,1 replica-giờ. Campaign chiếm gần trọn lượt nên khoảng normal rất ngắn; con số này không so được với lượt v5.'),
    B('Map 4-gram không rơi gram nào; issue chỉ có khoảng trống nhịp (9, 7, 1 lần trên ba worker).'),
    CODE('scripts/analysis/pulse_live_v4.py; biên nhận validation-evidence/results-20261118/pulse-live-v6-1117/.'),
)
h2('5.3 Dòng native (H1)')
add(
    T([['Khoảng (mọi tốc độ)', 'Cả cửa sổ (đường cảnh báo)', 'Chỉ phần native'],
       ['Control', '1/525', '1/525'],
       ['Lệnh quản trị (bộ v6)', '460/475', '1/475'],
       ['Binary vô hại', '525/525', '1/525'],
       ['Tấn công (fixture)', '524/525', '0/525'],
       ['Tấn công bằng tool của image', '524/525', '1/525']], [3.6, 3.2, 3.2]),
    B('**H1 đạt:** phần native gần như không gắn cờ lệnh quản trị và binary vô hại (mức đăng ký ≤ 5%).'),
    B('**Cái giá đã ghi trước trong protocol:** tấn công của campaign vào qua kubectl exec nên thuộc dòng session; phần native không bắt tấn công nào. Chỉ chấm phần native không thay được đường cảnh báo; quyết định phải biết cửa sổ báo đến từ dòng nào, và dòng session cần cách xử lý riêng.'),
    CODE('scripts/analysis/native_stream.py.'),
)
h2('5.4 Mặt hại của luật R1 (H4, H5)')
add(
    B('**R1 xoá mọi tấn công dùng tool của image:** mô hình một mình bắt 314/315 ở tập chính; có R1 còn 0/315. R1 không phân biệt người vận hành chạy cat với kẻ tấn công chạy cat.'),
    B('**Lệnh quản trị chưa từng thấy:** mô hình một mình gắn cờ 275/284; có R1 còn 0/284. Tấn công fixture 315/315 ở cả hai hệ.'),
    B('**Kết luận: R1 không được nhận.** Lợi và hại đến từ cùng một điều kiện, nên không có ngưỡng nào giữ cái này mà bỏ cái kia.'),
    CODE('scripts/analysis/rule_e_benefit.py.'),
)
h2('5.5 Đường cảnh báo và RCA (H6)')
add(
    T([['Chỉ số', 'Kết quả'],
       ['Bridge → Alertmanager', '3.233/3.233 đợt; decision → Alertmanager p95 1,21 s'],
       ['Kernel → Alertmanager (push), tấn công', '721/735 trial, p50 0,49 s, p95 1,53 s'],
       ['Chấm điểm (cửa sổ đóng → điểm)', 'p50 0,17 s, p95 0,23 s'],
       ['Tấn công có case riêng (sau bản sửa RCA)', '711/735 (96,7%)'],
       ['Binary fixture hạng 1: chạy sau / trước binary vô hại', '268/355 (75,5%) / 272/356 (76,4%)']], [4.6, 5.4]),
    B('**Thứ tự bước không còn quyết định hạng 1 (H6).** Mức thấp hơn lượt v5 (99,4%) đến từ thiết kế trial của v6: mỗi trial có hai tấn công. Phân tích thăm dò: trong 162/170 case mà fixture không đứng đầu, nghi phạm hạng 1 là process của bước lotl trong cùng trial (sh, cat, rm).'),
    B('24 tấn công không có case riêng: 15 bị gộp vào case của binary vô hại cùng trial, 9 vào case khác.'),
    CODE('sentinel_pulse/ops/alert_bridge.py, sentinel_pulse/rca/service.py; scripts/analysis/rca_coverage.py, rca_follow_up.py.'),
)
h2('5.6 Chốt mô hình')
add(
    B('**Lượt v6 chạy lidds-ml-v5** (thuật toán, bảng chữ select1f, tham số, quy tắc ngưỡng) với bộ mô hình pulse-live-v6-fit-1117 (học lại từ normal mới). Không có "v6" của thuật toán; "v6" chỉ là tên lượt chạy.'),
    B('**Sau đó chủ đồ án chọn lidds-ml-v5-t3** (mục 6.4); bộ mô hình trên cụm học lại với cấu hình này: pulse-live-v7-fit-1118, cùng dữ liệu normal, 21 mô hình. Khối 60 s giữ ra vượt ngưỡng 1.057/132.971 (0,795%), so với 443 (0,333%) của bộ v6: gánh cảnh báo trên cụm có thể cao hơn, đo ở lượt cuối.'),
    B('Đường cảnh báo chỉ dùng nhánh token; nhánh đếm, cây, support và nhánh tần suất giữ ở chế độ shadow.'),
)

h1('6. LID-DS 2019')
h2('6.1 Kết quả (chấm một lần)')
add(
    P('Protocol lidds2019-confirmation-v2 (đăng ký 17/11, trước khi chuyển đổi hay chấm bản ghi nào) giữ nguyên mô hình và mọi tham số. Mỗi kịch bản học từ 200 bản ghi training và 50 bản ghi validation; mọi bản ghi test là blind. Trước khi đọc dữ liệu 2019, driver phải tái lập đúng official 2021, và nó tái lập đúng (1.238/1.271, 26/7.938, p95 1,47 s). Mức C1: recall ≥ 95%, bản ghi normal bị báo nhầm ≤ 1%, p95 ≤ 3 s. Số dưới đây tính theo độ phân giải 1 s của nhãn (mục 6.2).', 'FirstParagraph'),
    T([['Kịch bản', 'Phát hiện', 'Báo nhầm', 'p95'],
       ['Bruteforce_CWE-307', '92/98', '5/744', '14,37 s'],
       ['CVE-2012-2122', '152/155', '1/990', '1,17 s'],
       ['CVE-2014-0160 (Heartbleed)', '24/100', '5/750', '11,19 s'],
       ['CVE-2017-7529', '157/174', '0/733', '1,15 s'],
       ['CVE-2018-3760', '133/137', '0/834', '1,06 s'],
       ['CVE-2019-5418', '98/98', '0/731', '1,25 s'],
       ['EPS_CWE-434', '99/99', '8/722', '2,39 s'],
       ['PHP_CWE-434', '103/103', '0/759', '5,56 s'],
       ['SQL_Injection_CWE-89', '100/100', '13/728', '4,67 s'],
       ['ZipSlip', '98/98', '2/715', '2,24 s'],
       ['**Tổng**', '**1.056/1.162 (90,88%)**', '**34/7.706 (0,44%)**', '**10,55 s**']], [3.4, 2.6, 2.2, 1.8]),
    B('**C1 không đạt:** mức báo nhầm đạt; recall dưới 95% (Heartbleed 24/100, 76 bản ghi không có cảnh báo nào) và p95 trên 3 s (Bruteforce, Heartbleed, PHP, SQL injection).'),
    CODE('sentinel_pulse/lidds/lidds2019.py, scripts/analysis/lidds_ml_token_crossfit.py, scripts/analysis/lidds2019_token.py, scripts/lidds2019_token_run.sh; biên nhận validation-evidence/results-20261118/lidds2019-confirmation/.'),
)
h2('6.2 Quy tắc đánh giá: độ phân giải của nhãn')
add(
    B('**Mọi thời điểm exploit của LID-DS 2019 là số nguyên giây,** trong khi cửa sổ báo dài 0,5 s và được định vị tới micro giây. Một bản ghi tấn công được tính là phát hiện khi có cửa sổ báo kết thúc sau (mốc nhãn − 1 s); độ trễ tính từ mốc đó; bản ghi normal không đổi.'),
    B('**Quy tắc này đặt sau lượt chấm** (amendment 1 của protocol), trên chính các cảnh báo của lượt chấm duy nhất. Cùng quy tắc trên LID-DS 2021 official, nơi nhãn chính xác, vẫn cho 1.238/1.271: không thêm phát hiện nào khi nhãn chính xác.'),
    B('**Kiểm thêm:** định dạng mã lỗi của trace 2019 giống 2021 (không phải lỗi chuyển đổi).'),
    CODE('scripts/analysis/lidds2019_token.py (lệnh tolerance); protocol sentinel_pulse/protocol/lidds2019-confirmation-v2-amendment-1.json; biên nhận tolerance.json.'),
)
h2('6.3 Phần còn lại và thử cải thiện trên phần development')
add(
    B('**Thử cải thiện trên phần development** (protocol lidds2019-development-v1, đăng ký 18/11 20:28, sau lượt chấm): 30% bản ghi test 2019 chia theo sha256 (321 tấn công, 2.311 normal) làm development. 23 ứng viên: độ dài gram, top-k, α′, trim, thêm chi tiết token cho từng syscall. Mỗi ứng viên phải giữ LID-DS 2021 development (≥ 530/544, ≤ 6 báo nhầm) và CB-DS (891, ≤ 3).'),
    T([['Ứng viên', '2019 development (dung sai 1 s)', 'Báo nhầm', 'p95', 'LID-DS 2021 development'],
       ['lidds-ml-v5 (giữ)', '295/321', '6/2.311', '10,08 s', '530 / 6 (giữ)'],
       ['top 5', '310/321', '6/2.311', '11,13 s', '529 / 7 (hỏng)'],
       ['n 5', '310/321', '8/2.311', '11,13 s', '526 / 6 (hỏng)'],
       ['α′ 0,001', '310/321', '18/2.311', '11,13 s', '530 / 15 (hỏng)']], [2.4, 2.6, 1.6, 1.4, 2.4]),
    B('**Kết quả theo protocol: giữ lidds-ml-v5, không chấm thêm gì** (không chạy lại official 2021, không chấm phần holdout). Không ứng viên nào vừa giữ LID-DS 2021 vừa tăng recall 2019.'),
    B('**Đọc kết quả:** mọi ứng viên tăng recall chỉ tăng ở Heartbleed (development 7/23 → 22/23) và đều hỏng mức LID-DS 2021. Không ứng viên nào đưa p95 về gần 3 s (9,4–11,1 s), vì độ trễ của Bruteforce (p95 14,1 s) và Heartbleed không phụ thuộc các tham số này. Vì vậy C1 không đạt được bằng các thay đổi đã thử; kết quả đăng ký là giới hạn của đồ án.'),
    B('**Mở rộng (cùng protocol, chỉ phần development):** 90 tổ hợp độ dài gram × top-k × trim × α′, mỗi tổ hợp chấm lại cả LID-DS 2021 development: chỉ cấu hình gốc qua điều kiện; 72 tổ hợp đạt ≥ 305/321 trên 2019 nhưng đều mất phát hiện hoặc thêm báo nhầm trên 2021 (gần nhất: 529/544 với 5 báo nhầm). Không tổ hợp nào phát hiện quá 530 trên LID-DS 2021 development trong 6 báo nhầm. Nhánh tần suất không thêm phát hiện nào ở 2019.'),
    B('**Cận dưới của độ trễ (phát hiện mới):** cửa sổ đầu tiên sau mốc exploit có gram hay token chưa từng thấy đến ở p95 9,39 s (Bruteforce 13,11 s, Heartbleed 10,69 s, PHP 4,55 s, SQL 3,52 s; sáu kịch bản còn lại ≤ 1,34 s). Không bộ phát hiện nào dựa trên chuỗi chưa thấy đạt p95 ≤ 3 s trên LID-DS 2019: giới hạn nằm ở dữ liệu, không ở mô hình.'),
    CODE('scripts/analysis/lidds2019_dev.py, scripts/lidds2019_dev_run.sh; biên nhận validation-evidence/results-20261118/lidds2019-development/.'),
)
h2('6.4 Cấu hình t3 (amendment 1)')
add(
    P('Amendment 1 của lidds2019-development-v1 (đăng ký 18/11 21:08, trước hai lượt chấm dưới đây) nới mức LID-DS 2021 development thêm một phát hiện theo quyết định của chủ đồ án, khi đã biết kết quả development, và chọn tổ hợp n 4, top 3, trim 0,5%, α′ 0,0003 (2021 development 529/544 với 5 báo nhầm; 2019 development 310/321 với 9 báo nhầm). Hai lượt chấm: LID-DS 2021 official, rồi 70% holdout của 2019. Trước mỗi lượt, cấu hình gốc tái lập đúng kết quả đã đăng ký của lidds-ml-v5.', 'FirstParagraph'),
    T([['Tập', 'Cấu hình', 'Phát hiện', 'Báo nhầm', 'p95'],
       ['LID-DS 2021 official', 'lidds-ml-v5', '1.238/1.271 (97,40%)', '26/7.938 (0,33%)', '1,47 s'],
       ['LID-DS 2021 official', 't3', '1.236/1.271 (97,25%)', '15/7.938 (0,19%)', '1,54 s'],
       ['LID-DS 2019 holdout, dung sai nhãn 1 s', 'lidds-ml-v5', '761/841 (90,49%)', '28/5.395 (0,52%)', '10,57 s'],
       ['LID-DS 2019 holdout, dung sai nhãn 1 s', 't3', '817/841 (97,15%)', '25/5.395 (0,46%)', '10,95 s']], [3.2, 1.6, 2.2, 1.9, 1.1]),
    B('**LID-DS 2021:** ít hơn 2 phát hiện (ZipSlip 83 → 81), ít hơn 11 bản ghi báo nhầm; mức đăng ký cho 2021 vẫn đạt.'),
    B('**LID-DS 2019:** C1 đạt recall và báo nhầm, không đạt p95 (cận dưới 9,39 s ở mục 6.3). Phần tăng nằm ở Heartbleed (17 → 73/77); các kịch bản khác không đổi số phát hiện.'),
    B('**Công bố trong mọi tài liệu:** các bản ghi holdout đã được lidds-ml-v5 chấm trong lượt chấm theo protocol trước khi chia; quy tắc dung sai nhãn 1 s đặt sau lượt chấm đó; mức 2021 development được nới khi đã biết kết quả development.'),
    CODE('scripts/analysis/lidds2019_dev.py (official, holdout), scripts/lidds2019_amendment1_run.sh; protocol sentinel_pulse/protocol/lidds2019-development-v1-amendment-1.json; biên nhận official2021.json, holdout.json trong validation-evidence/results-20261118/lidds2019-development/.'),
)

h1('7. Vòng cải thiện trước lượt live cuối (improvement-round-v1)')
add(
    P('Chủ đồ án dừng lượt live v7 (18/11 19:28 UTC, trước mọi tấn công) để thử hết các hướng cải thiện trước, sau khi đọc lại toàn bộ research_notes/ và reports/. Protocol improvement-round-v1 (+ amendment 1–4) đăng ký trước mọi phép tính; mỗi hướng có tiêu chí nhận riêng.', 'FirstParagraph'),
    T([['Hướng', 'Kết quả', 'Quyết định'],
       ['D1 map 4-gram đầy thành cảnh báo', 'Thử trên worker1: báo đúng cgroup gây đầy, trễ 0 s', 'Nhận'],
       ['D2 mốc cuối cửa sổ của loader', 'Tính từ hằng số cửa sổ thay vì số cứng', 'Nhận'],
       ['D3 hàng đợi bền cho bridge', 'Đợt chưa giao giữ trên đĩa, thử lại tới 1 giờ', 'Nhận'],
       ['D4 ghép top 3 và top 10', 'LID-DS 2021 development 7 báo nhầm', 'Không nhận'],
       ['D5 mô hình riêng cho dòng session', 'Gắn cờ lệnh quản trị 470/475, binary vô hại 525/525', 'Không nhận'],
       ['D6 probe chỉ hook 5 họ syscall', 'Không nhanh hơn ở mọi thao tác', 'Không nhận'],
       ['D7 chi phí trên request thật', 'p50 +10,5 ms (+11%), p95 +15,9 ms (+5,7%), p99 +34,2 ms (+9,5%), 0 lỗi', 'Đo xong'],
       ['D8 token chi tiết hơn (đường dẫn 2 cấp, đích connect)', 'Mất 3 phát hiện LID-DS 2021 development', 'Không nhận'],
       ['D9 học lại sau mỗi lần đổi cụm', 'Quy tắc vận hành', 'Nhận'],
       ['D10, D11 gom sự cố, đồng thuận replica', 'Lượt v6 chỉ có 4 đợt normal, đều một replica', 'Không có lợi'],
       ['D12 tấn công chậm 0,1–0,5/s, bật-tắt', 'Thêm vào lượt cuối', 'Dùng ở lượt cuối'],
       ['D13 né bằng io_uring', 'Seccomp RuntimeDefault trả EPERM trong pod', 'Đã đóng'],
       ['D14 làm mượt Kneser-Ney', 'LID-DS 2019 development 288/321', 'Không nhận'],
       ['D15 CUSUM', 'LID-DS 2021 development 9–46 báo nhầm', 'Không nhận'],
       ['D16 ngưỡng GEV gộp hình dạng', 'Trên 2021 official mất 3 phát hiện, báo nhầm không giảm', 'Không nhận'],
       ['D17 ngữ cảnh process (reset khi execve)', 'CB-DS 3 → 2 báo nhầm, LID-DS 2019 không đổi', 'Không nhận'],
       ['D18 Falco event-generator (14 hành động)', 'Bản tĩnh dựng từ mã nguồn v0.13.0 để chạy cả trong image musl', 'Dùng ở lượt cuối']], [3.6, 4.6, 1.8]),
    B('**Thêm cho người vận hành:** nhãn stream (native/session) trên mỗi cảnh báo, chỉ để phân loại, không hạ cảnh báo; ghi sự kiện Kubernetes suốt lượt để gắn nhãn đợt cảnh báo do vận hành sau lượt.'),
    B('**Không cần chạy lại dataset:** không hướng nào được nhận làm đổi cách chấm trên dataset; t3 đã có số trên LID-DS 2021, 2019 và CB-DS.'),
    CODE('scripts/analysis/improvement_offline.py, rich_token_cache.py, session_channel.py, burden_context.py, scripts/map_overflow_test.py, scripts/app_overhead_ab.py; protocol sentinel_pulse/protocol/improvement-round-v1*.json; biên nhận validation-evidence/results-20261119/improvement-round/.'),
)

h1('8. Lượt live cuối: pulse-live-final-1119')
add(
    P('Protocol pulse-live-final-v1 đăng ký 19/11 09:39, trước lượt chạy: H0 (tập chính: recall ≥ 95%, control ≤ 5%, precision ≥ 95%, p95 ≤ 3 s), H3 (pha loãng PAD 300), H7 (tấn công chậm 0,5 và 0,1 lần/s), H8 (bật-tắt chu kỳ 10 s), cùng các tập báo cáo kèm (lotl, event-generator theo hành động, lệnh quản trị, binary vô hại, dòng native, gánh trên khoảng normal cuối, RCA).', 'FirstParagraph'),
    T([['Hạng mục', 'Nội dung'],
       ['Hệ thống', 'lidds-ml-v5-t3, bộ mô hình pulse-live-v7-fit-1118, probe pulse-tokens-final-f8ccbb2, bridge có hàng đợi bền và nhãn stream'],
       ['Campaign', '945 trial: 525 cơ bản (21 workload × 5 kịch bản × 1, 3, 6, 12, 24 lần/s), 210 chậm (0,5 và 0,1/s), 105 PAD 300, 105 bật-tắt 10 s'],
       ['Mỗi trial', 'control 15 s, rồi theo thứ tự có seed: lệnh quản trị, binary vô hại, tấn công, lotl, một hành động event-generator'],
       ['Thời lượng', '162.000 s (45 giờ): 90 phút chọn mẫu, khoảng 36 giờ campaign, khoảng 6 giờ normal cuối; từ 19/11 09:50 tới khoảng 21/11 06:50'],
       ['Diễn tập', '6 trial trên các workload khó nhất: mọi bước chạy, phân tích chạy được, bridge 37/37, 138 s mỗi trial'],
       ['Tình trạng 19/11 22:41', '309/945 cặp xong; campaign, bridge, RCA, bộ ghi sự kiện K8s và 3 worker đang chạy']], [2.4, 7.6]),
    B('**Sự cố nhỏ:** bộ ghi sự kiện Kubernetes chạy dưới dạng user unit nên dừng khi phiên SSH khởi chạy đóng (09:49); chạy lại lúc 10:59 dưới dạng system unit. API giữ sự kiện khoảng 1 giờ nên phần mất thật chỉ khoảng 10 phút, trước khi có tấn công. Script khởi chạy đã sửa cho các lượt sau.'),
    B('**Không làm gì nặng trên cụm** và không pull code lên worker tới khi lượt chạy xong; lượt chạy hết chu kỳ.'),
    CODE('sentinel_pulse/protocol/pulse-live-final-v1.json; sentinel_pulse/pipeline/plan_matched_run.py (--rehearsal, --on-off, --eventgen), sentinel_pulse/attack/preview_campaign.py, scripts/launch_run.sh, scripts/k8s_events_record.py; biên nhận diễn tập validation-evidence/results-20261119/final-rehearsal/.'),
)

h1('9. Paper')
add(
    B('**Phương pháp PaperOrchestra** (Google Research): outline → tài liệu → viết từng mục → vòng chỉnh → định dạng; Claude đóng vai các agent, không dùng API trả phí. **Form USENIX Security \'27** (cycle 2, hạn 26/01/2027).'),
    B('**Trạng thái:** bản nháp 13 trang; 53 tài liệu, 47 đã kiểm trên Semantic Scholar hoặc Crossref, file bib sinh tự động chỉ từ metadata đã kiểm; mọi chỗ chờ số của v6 và LID-DS 2019 đã điền; hình tổng quan (Figure 1) đã vẽ.'),
    B('**Việc còn lại:** cập nhật sang t3 và lượt live cuối, tiêu đề và abstract, vòng chỉnh, ẩn danh, link artifact.'),
    CODE('paper/README.md (các bước), paper/latex/paper.tex, paper/tools/s2_verify.py, paper/tools/make_bib.py.'),
)

h1('10. Mã nguồn, tài liệu đọc code, dọn tài nguyên')
add(
    B('**Chú thích tiếng Việt cho toàn bộ code** (177 file: eBPF, collector, detector, pipeline, attack, testbed, ops, RCA, LID-DS, scripts). Bộ kiểm chỉ ra mỗi thay đổi chỉ là comment (AST cho Python, bỏ comment rồi so cho C, so dòng không phải comment cho shell); test đầy đủ đạt.'),
    B('**Hướng dẫn đọc code** notes/CODE_READING_GUIDE.md: lộ trình 8 chặng, bản đồ thư mục, đường đi của dữ liệu, offline, cụm, thuật ngữ, protocol và kiểm toán, cách chạy lại, bản đọc 30 phút.'),
    B('**Tài liệu mới (19/11):** docs/LUONG_CODE.md (luồng code từ syscall tới cảnh báo, ví dụ thật của lượt cuối, quy trình chuẩn và các lệnh cần chạy); docs/architecture/KIEN_TRUC.md (từng thành phần của hình kiến trúc và file, hàm tương ứng); hình kiến trúc 5 trang và các hình TikZ của đồ án cập nhật theo hệ thống của lượt cuối.'),
    B('**Kiểm toán số liệu của đồ án:** 130/130 câu số liệu khớp biên nhận (scripts/audit/headline_numbers.py).'),
    B('**Dọn tài nguyên:** xoá script không còn chạy được (chủ đồ án đồng ý 16/11); nén không mất dữ liệu các segment của 5 lượt đã xong (2.360 file, 0 lỗi, xoá bản gốc chỉ khi SHA-256 khớp), NFS trống 595 GB; xoá unit, config và file tạm của các lượt đã xong trên master và worker.'),
    CODE('scripts/compress_raw_frames.py; notes/CODE_AUDIT.md.'),
)

h1('11. Tuần này: các lượt chạy và job')
add(
    T([['Lượt / job', 'Thời gian', 'Kết quả'],
       ['ml-final-study-v1 B2, B3', '13/11', 'Học thêm quản trị không đạt; proxy dòng native sạch; mô hình phiên không bắt tấn công'],
       ['Thẻ dòng dõi trong probe', '13/11', 'Proof 8/8 trên pod thật'],
       ['Luật R1, R2 trên campaign v5', '15/11', 'Báo nhầm quản trị 97,7% → 0, recall giữ 314/314'],
       ['Nhánh tần suất', '15/11', 'Không thêm phát hiện, chỉ thêm báo nhầm'],
       ['Chi phí thẻ dòng dõi; sức chứa map', '16/11', 'Không đo được chi phí; map dư khoảng 20 lần'],
       ['pulse-token-capture-v6-1116', '16–17/11', 'Normal 12 giờ, 0 lần chèn thất bại'],
       ['Kiểm lão hoá, fit pulse-live-v6-fit-1117', '17/11', '0,59% so với 0,26%; học lại 21 mô hình'],
       ['pulse-live-v6-1117', '17–18/11', '26 giờ, 735/735 trial; H0, H1, H3 đạt; R1 không nhận'],
       ['LID-DS 2019 (một lần, dung sai nhãn 1 s)', '18/11', '90,88%, báo nhầm 0,44%, p95 10,55 s; C1 không đạt'],
       ['LID-DS 2019 development (30%)', '18/11', '23 ứng viên; không ứng viên nào giữ 2021 mà tăng recall; giữ v5'],
       ['LID-DS 2019 amendment 1 (t3)', '18/11', 'Holdout 817/841 (dung sai 1 s); 2021 official 1.236/1.271, 15 báo nhầm'],
       ['Fit pulse-live-v7-fit-1118 (t3); lượt v7', '18–19/11', '21 mô hình; lượt v7 dừng trước tấn công để làm vòng cải thiện'],
       ['improvement-round-v1 (D1–D18)', '19/11', 'Nhận D1, D2, D3; D12, D18 vào lượt cuối; 10 hướng không nhận'],
       ['Diễn tập; pulse-live-final-1119', '19–21/11', 'Diễn tập đạt; lượt cuối 945 trial đang chạy'],
       ['Paper, chú thích code, dọn tài nguyên', '17–18/11', 'Bản nháp 12 trang; 177 file; NFS trống 595 GB'],
       ['Hình kiến trúc, tài liệu luồng code', '19/11', 'Hình 5 trang, TikZ đồ án, hình paper; LUONG_CODE.md, KIEN_TRUC.md']], [3.6, 1.6, 4.8]),
    B('**Việc đã hẹn ở buổi 13/11:** lượt thu và live mới trên cấu hình VM mới với bản sửa RCA, thứ tự ngẫu nhiên và thêm kỹ thuật tấn công (xong); LID-DS 2019 chấm một lần khi mô hình chốt (xong); luật R1, R2 và so sánh có và không có luật (xong, R1 không nhận).'),
    B('**Chủ đồ án quyết định:** không đưa ảnh có lỗ hổng hay exploit thật lên cụm và không dùng dịch vụ thử chạy thao tác trong process; dòng native vì vậy chưa thử với tấn công chạy bên trong process của dịch vụ trên cụm (bằng chứng cho trường hợp này là LID-DS 2021).'),
    B('**Sự cố:** không có sự cố hạ tầng; vài khoảng trống nhịp ngắn trên worker trong lượt v6, không mất gram.'),
)

h1('12. Tiến độ và việc tiếp theo')
add(
    T([['Hạng mục', 'Hoàn thành', 'Còn lại'],
       ['ML trên dataset (LID-DS 2021, CB-DS, LID-DS 2019)', '~98%', 'LID-DS 2019: p95 không đạt (giới hạn của dữ liệu)'],
       ['Probe token và chi phí', '~95%', 'Xong; chi phí trên request thật đã đo'],
       ['Lượt live của ML', '~90%', 'Lượt cuối đang chạy, phân tích sau 21/11'],
       ['Process mới vô hại', '~50%', 'Nhãn stream trên cảnh báo; dòng session vẫn cần cách xử lý riêng'],
       ['RCA và đường cảnh báo', '~95%', 'Hàng đợi bền đã có; đo lại ở lượt cuối'],
       ['So sánh có và không có luật', '~70%', 'Luật danh mục ý đồ trên lotl và event-generator sau lượt cuối'],
       ['Viết đồ án (LaTeX)', '~88%', 'Cập nhật sang t3 và kết quả lượt cuối, chỉnh văn'],
       ['Paper (USENIX Security \'27)', '~50%', 'Cập nhật t3, lượt cuối, abstract, vòng chỉnh'],
       ['Đồ án tổng thể', '~92%', 'Tăng từ ~85% ở buổi 13/11']], [3.8, 1.6, 4.6]),
    P('Các tỉ lệ trên là ước lượng, không phải số đo.'),
    B('**Sau lượt cuối (21/11):** phân tích theo protocol (H0, H3, H7, H8, event-generator, dòng native, gánh trên khoảng normal cuối kèm sự kiện Kubernetes, RCA, so với v6); rồi so sánh có và không có luật danh mục ý đồ; cập nhật đồ án, paper, báo cáo, slide sang t3 và kết quả lượt cuối.'),
    B('**Dòng session:** cảnh báo đã mang nhãn stream; mô hình riêng cho session (D5) không tách được tấn công khỏi lệnh quản trị, nên dòng session vẫn là giới hạn nếu không có hướng mới.'),
    B('**Paper:** hoàn thiện bản nháp theo PaperOrchestra, vòng chỉnh và kiểm số tự động như đồ án.'),
    B('**Cần thầy cho ý kiến:** (1) LID-DS 2019: t3 đạt recall và báo nhầm với dung sai nhãn 1 s, nhưng p95 không xuống 3 s vì cận dưới của dữ liệu (9,39 s); để độ trễ 2019 là giới hạn của đồ án; (2) dòng session: để là giới hạn, hay làm đường cảnh báo theo dòng dõi trước khi bảo vệ; (3) paper có cần baseline tự chạy (STIDE, Isolation Forest) ngoài các số đã công bố không.'),
)

h1('13. Giải thích thuật ngữ')
add(T([['Thuật ngữ', 'Nghĩa'],
       ['Thẻ dòng dõi (lineage)', 'Thẻ của mỗi thread: native nếu thuộc cây process của chính workload, session nếu vào qua runtime exec (kubectl exec, crictl exec) hoặc là con của process như vậy'],
       ['Dòng native / session', 'Phần của cửa sổ token do thread native / session sinh ra; loader in riêng phần session'],
       ['Telemetry', 'Dữ liệu ghi lại để phân tích, không dùng để quyết định báo'],
       ['Pha loãng (PAD)', 'Chèn thêm syscall quen (getpid + sched_yield) quanh thao tác tấn công để thử làm loãng điểm cửa sổ; PAD 30 / 300 là số cặp chèn'],
       ['Lotl (living off the land)', 'Tấn công chỉ dùng tool có sẵn trong image (sh, cat, ls) thay vì mang binary mới vào'],
       ['Luật R1 / R2', 'R1: hạ cảnh báo khi cửa sổ chỉ có exec của binary có trong image; R2: giữ cảnh báo của binary không thuộc image, gắn nhãn drift'],
       ['Lão hoá mô hình', 'Normal của cụm đổi theo thời gian, nên mô hình cũ vượt ngưỡng nhiều hơn trên normal mới'],
       ['Amendment', 'Phần sửa của một protocol, đăng ký có thời điểm; phần đăng ký sau khi thấy dữ liệu được ghi là phân tích sau'],
       ['C1', 'Mức đăng ký cho LID-DS 2019: recall ≥ 95%, bản ghi normal bị báo nhầm ≤ 1%, p95 ≤ 3 s'],
       ['Dung sai nhãn 1 s', 'Tính cả cửa sổ báo kết thúc trong 1 s trước mốc exploit, vì mốc của LID-DS 2019 làm tròn tới giây'],
       ['Shadow', 'Nhánh vẫn chạy và ghi kết quả nhưng không đi vào đường cảnh báo'],
       ['t3 (lidds-ml-v5-t3)', 'Cùng mô hình lidds-ml-v5 nhưng điểm cửa sổ là trung bình 3 độ bất ngờ lớn nhất, bỏ 0,5% cực đại khi khớp Gumbel, α′ 0,0003'],
       ['Holdout', 'Phần dữ liệu giữ lại, chỉ chấm sau khi đã chọn cấu hình trên phần development'],
       ['Tấn công chậm / bật-tắt', 'Thao tác tấn công 0,1–0,5 lần/s; hoặc chạy 10 s, nghỉ 10 s, để thử né ngưỡng theo cửa sổ'],
       ['Event-generator', 'Công cụ của Falco tạo hành vi đáng ngờ (đọc file nhạy cảm, xoá log, chạy từ /dev/shm...) để thử bộ phát hiện'],
       ['Diễn tập (rehearsal)', 'Lượt chạy ngắn, mỗi loại trial một lần, chỉ để kiểm mọi bước chạy được trước lượt chính']], [3.0, 7.0]))

h1('14. Tài liệu tham chiếu')
add(
    B('Protocol: sentinel_pulse/protocol/ml-final-study-v1 (amendment 1–2), token-probe-overhead-v1 (amendment 3), map-capacity-v1, pulse-live-v6-v1 (amendment 1), lidds2019-confirmation-v2 (amendment 1), lidds2019-development-v1 (amendment 1), pulse-live-v7-v1, improvement-round-v1 (amendment 1–4), pulse-live-final-v1.'),
    B('Biên nhận: validation-evidence/results-20261113 (lineage-probe, ml-final-study), results-20261115 (rule-e-benefit, w3b-rate-signal), results-20261116 (lineage-overhead, map-capacity), results-20261117 (model-aging, lidds2019-gate), results-20261118 (pulse-live-v6-1117, lidds2019-confirmation, lidds2019-development), results-20261119 (improvement-round, final-rehearsal).'),
    B('Kiến trúc và code: docs/architecture/ (hình 5 trang, KIEN_TRUC.md), docs/LUONG_CODE.md.'),
    B('Đồ án: thesis/ (LaTeX, mục RQ1–RQ6); nhật ký notes/WORKLOG.md, trạng thái notes/STATE.md; hướng dẫn đọc code notes/CODE_READING_GUIDE.md.'),
    B('M. Grimmer, T. Kaelble, F. Nirsberger, E. Schulze, T. Rucks, J. Hoffmann, E. Rahm. Dataset Report: LID-DS 2021. Critical Information Infrastructures Security (LNCS), 2023, pp. 63–73.'),
    B('PaperOrchestra, Google Research: github.com/google-research/paper-orchestra.'),
)

# ===================================================================================================== assemble
body_start = d.index('<w:body>') + len('<w:body>')
blocks = list(re.finditer(r'<w:p[ >].*?</w:p>|<w:tbl>.*?</w:tbl>', d[body_start:], flags=re.S))
text = lambda x: ''.join(re.findall(r'<w:t[^>]*>([^<]*)</w:t>', x))
toc_head = next(i for i, m in enumerate(blocks) if text(m.group(0)) == 'MỤC LỤC')
sect = d.index('<w:sectPr', body_start + blocks[-1].end())
head = d[:body_start + blocks[toc_head].end()]
head = head.replace('Báo cáo tiến độ từ 06/11 đến 13/11/2026', 'Báo cáo tiến độ từ 13/11 đến 20/11/2026', 1)
head = head.replace('(Giải thích chi tiết mô hình ML hiện tại lidds-ml-v5, ví dụ thật, kiểm từng lựa chọn, kết quả, việc còn lại)',
                    '(Thẻ dòng dõi, lượt live thứ ba, LID-DS 2019 và cấu hình t3, vòng cải thiện D1–D18, lượt live cuối, kiến trúc, paper)', 1)
assert 'từ 13/11 đến 20/11/2026' in head and 'vòng cải thiện D1–D18' in head
toc = ''.join(TOC(t, lv) for lv, t in S)
brk = '<w:p><w:pPr><w:pStyle w:val="Normal"/><w:spacing w:before="0" w:after="200"/><w:rPr></w:rPr></w:pPr><w:r><w:br w:type="page"/></w:r></w:p>'
d = head + toc + brk + ''.join(BODY) + d[sect:]
for decl in ('xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing"',
             'xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"',
             'xmlns:pic="http://schemas.openxmlformats.org/drawingml/2006/picture"'):
    if decl.split('=')[0] + '=' not in d[:4000]:
        d = d.replace('<w:document ', '<w:document ' + decl + ' ', 1)
open(DOC, 'w', encoding='utf-8').write(d)
print('sections', len(S), 'body blocks', len(BODY))
for f in ('x/word/footer1.xml', 'x/word/footer2.xml', 'x/word/footer3.xml'):
    t = open(f, encoding='utf-8').read()
    open(f, 'w', encoding='utf-8').write(t.replace('Báo cáo tiến độ 06/11–13/11', 'Báo cáo tiến độ 13/11–20/11'))
