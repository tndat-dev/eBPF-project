"""Insert the 13/11 additions into the owner's edited report (x/word/document.xml), keeping every owner edit."""
import re
import sys
from xml.sax.saxutils import escape
from PIL import Image

DOC = 'x/word/document.xml'
FIG = sys.argv[1]
d = open(DOC, encoding='utf-8').read()

BORDER = ''.join(f'<w:{e} w:val="single" w:sz="4" w:space="0" w:color="000000"/>' for e in ('top', 'left', 'bottom', 'right'))


def runs(text):
    """'**bold** rest' -> runs."""
    out = []
    for i, part in enumerate(text.split('**')):
        if not part:
            continue
        rpr = '<w:rPr><w:b/><w:bCs/></w:rPr>' if i % 2 else '<w:rPr></w:rPr>'
        out.append(f'<w:r>{rpr}<w:t xml:space="preserve">{escape(part)}</w:t></w:r>')
    return ''.join(out)


def P(text, style='BodyText', keep=False):
    jc = '<w:jc w:val="left"/>' if ('/' in text or '_' in text) else ''
    kn = '<w:keepNext/>' if keep else ''
    return f'<w:p><w:pPr><w:pStyle w:val="{style}"/>{kn}{jc}<w:rPr></w:rPr></w:pPr>{runs(text)}</w:p>'


def B(text):
    jc = '<w:jc w:val="left"/>' if ('/' in text or '_' in text) else ''
    return (f'<w:p><w:pPr><w:pStyle w:val="Compact"/><w:numPr><w:ilvl w:val="0"/><w:numId w:val="1"/></w:numPr>{jc}'
            f'<w:rPr></w:rPr></w:pPr>{runs(text)}</w:p>')


def H2(text):
    return f'<w:p><w:pPr><w:pStyle w:val="Heading2"/><w:rPr></w:rPr></w:pPr><w:r><w:rPr></w:rPr><w:t>{escape(text)}</w:t></w:r></w:p>'


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
            f'<w:rPr></w:rPr></w:pPr>{rs}</w:p></w:tc>')


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


IMAGES = []


def IMG(name, caption, width_in=6.6):
    im = Image.open(f'{FIG}/{name}.png')
    cx = int(width_in * 914400)
    cy = int(cx * im.size[1] / im.size[0])
    n = len(IMAGES) + 1
    rid = f'rIdFig{n}'
    IMAGES.append((rid, name))
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


def blocks():
    body = d[d.index('<w:body>'):]
    return list(re.finditer(r'<w:p[ >].*?</w:p>|<w:tbl>.*?</w:tbl>', body, flags=re.S)), d.index('<w:body>')


def text_of(x):
    return ''.join(re.findall(r'<w:t[^>]*>([^<]*)</w:t>', x)).replace('&gt;', '>').replace('&lt;', '<').replace('&amp;', '&')


def after(prefix, xml, skip_toc=True, nth=0):
    """Insert xml right after the body block whose text starts with prefix (the TOC entries are skipped)."""
    global d
    found, base = blocks()
    hits = [m for m in found if text_of(m.group(0)).startswith(prefix)
            and not (skip_toc and 'w:leader="dot"' in m.group(0))]
    if len(hits) <= nth:
        raise SystemExit(f'anchor not found: {prefix}')
    m = hits[nth]
    pos = base + m.end()
    d = d[:pos] + xml + d[pos:]


def toc_after(prefix, title):
    """A TOC entry like the one starting with prefix, for title; page filled later."""
    global d
    found, base = blocks()
    m = next(m for m in found if 'w:leader="dot"' in m.group(0) and text_of(m.group(0)).startswith(prefix))
    entry = m.group(0)
    old = re.findall(r'<w:t>([^<]*)</w:t>', entry)[0]
    new = entry.replace(f'<w:t>{old}</w:t>', f'<w:t>{escape(title)}</w:t>', 1)
    pos = base + m.end()
    d = d[:pos] + new + d[pos:]


NS = ('xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing" '
      'xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" '
      'xmlns:pic="http://schemas.openxmlformats.org/drawingml/2006/picture" ')
for decl in NS.split():
    if decl.split('=')[0] + '=' not in d[:4000]:
        d = d.replace('<w:document ', '<w:document ' + decl + ' ', 1)


# ---------------------------------------------------------------- 2.4 code of each step, 2.5 architecture
after('Code: sentinel_pulse/detector/token_model.py', ''.join([
    P('Code của từng bước (đường dẫn tính từ thư mục gốc của repo):'),
    T([['Bước', 'Trên cụm (kernel, worker)', 'Trên dataset (LID-DS 2021)'],
       ['1. Token', 'sentinel_pulse/ebpf/pulse_tokens.bpf.h: pulse_tok_return (lúc trả về); sentinel_pulse/ebpf/pulse_counter.bpf.c: pulse_record_call (lúc vào, seccomp); danh sách 39 syscall và bố cục bit: sentinel_pulse/ebpf/pulse_token_ids.h',
        'scripts/analysis/lidds_ml_tokens.py: token(); bảng chữ: scripts/analysis/lidds_ml_token_alphabets.py: ALPHABETS, facts()'],
       ['2. Chuỗi', 'pulse_tokens.bpf.h: pulse_tok_emit, map pulse_grams; sentinel_pulse/ebpf/pulse_counter_loader.c: drain_grams; sentinel_pulse/collector/token_capture.py: token_window',
        'lidds_ml_tokens.py: window_tokens()'],
       ['3. Xác suất', 'sentinel_pulse/detector/token_model.py: CountTokenLM.learn, base, prob', 'lidds_ml_tokens.py: TokenLM.base, prob'],
       ['4. Điểm', 'token_model.py: CountTokenLM.window_score', 'lidds_ml_tokens.py: window_scores()'],
       ['5. Ngưỡng', 'scripts/analysis/token_branch_fit.py: crossfit_one, fit_crossfit, trimmed_gumbel',
        'scripts/analysis/lidds_ml_token_crossfit.py; lidds_ml_v4.py: trimmed_gumbel; lidds_ml_v2.py: gumbel, threshold'],
       ['6. Quyết định', 'token_model.py: TokenBranch.score; sentinel_pulse/pipeline/matched_worker.py; gửi cảnh báo: sentinel_pulse/ops/alert_bridge.py',
        'lidds_ml_v2.py: rows, score; lidds_ml_v5.py']], [1.2, 4.6, 3.6]),
    H2('2.5 Kiến trúc hệ thống'),
    P('Hình 1 là kiến trúc của hệ thống hiện tại. Trên mỗi worker, probe eBPF trong kernel dựng token và đếm 4-gram cho các container của namespace production; loader đọc các cửa sổ đã đóng mỗi 0,5 s; worker chấm điểm bằng mô hình của workload và ghi decision. Trên master, bridge gom các cửa sổ báo thành đợt và đẩy tới Alertmanager, rồi RCA dựng case từ cảnh báo đã nhận cùng sự kiện của Tetragon. Mô hình và ngưỡng được học offline từ normal của cụm trước mỗi lượt.', 'FirstParagraph'),
    IMG('overview', 'Hình 1. Kiến trúc hệ thống (lidds-ml-v5).'),
    T([['Thành phần', 'Code'],
       ['Probe eBPF', 'sentinel_pulse/ebpf/pulse_counter.bpf.c, pulse_tokens.bpf.h, pulse_token_ids.h; build: sentinel_pulse/ebpf/Makefile (make tokens)'],
       ['Loader', 'sentinel_pulse/ebpf/pulse_counter_loader.c'],
       ['Resolver (pod, cgroup, workload)', 'sentinel_pulse/collector/cgroup_resolver.py'],
       ['Worker chấm điểm', 'sentinel_pulse/pipeline/matched_worker.py, sentinel_pulse/detector/token_model.py, sentinel_pulse/collector/token_capture.py'],
       ['Bridge cảnh báo', 'sentinel_pulse/ops/alert_bridge.py'],
       ['RCA', 'sentinel_pulse/rca/service.py, ranking.py, tree.py, runtime_events.py'],
       ['Học mô hình trên cụm', 'scripts/analysis/token_branch_fit.py'],
       ['Dựng và khởi chạy một lượt', 'sentinel_pulse/pipeline/plan_matched_run.py, scripts/launch_run.sh'],
       ['Campaign tấn công và đối chứng', 'sentinel_pulse/attack/preview_campaign.py'],
       ['Phân tích lượt live', 'scripts/analysis/pulse_live_v4.py']], [2.6, 7.0])]))

toc_after('2.4 Sáu bước', '2.5 Kiến trúc hệ thống')

# ---------------------------------------------------------------- 3.1 select1f, probe1f
after('Mỗi quy tắc nhắm một loại thông tin', ''.join([
    P('**select1f và probe1f là gì.** Một bảng chữ là bộ quy tắc biến một lần syscall thành token. Tên bảng chữ ghép từ các lựa chọn của nó:', 'FirstParagraph'),
    B('**select:** chỉ 27 syscall được chọn giữ mã lỗi (bảng chữ "full" giữ mã lỗi của mọi syscall).'),
    B('**1:** cỡ đọc ghi theo ⌊log₂ n⌋, đủ 16 nhóm; các bảng chữ cũ gộp hai nhóm liền nhau thành một.'),
    B('**f:** thêm futex vào nhóm giữ mã lỗi (ví dụ futex!EAGAIN).'),
    B('**probe1f:** đúng quy tắc của select1f, nhưng token được sắp theo thứ tự probe phát trên cụm: 39 syscall có hook phát lúc trả về, các syscall khác phát lúc vào. Bảng chữ này chỉ dùng để kiểm trên dataset rằng thứ tự của probe không làm mất gì (mục 3.2).'),
    CODE('scripts/analysis/lidds_ml_token_alphabets.py (SELECT_ERR, ALPHABETS["select1f"], ALPHABETS["probe1f"]); token trên dataset: scripts/analysis/lidds_ml_tokens.py: token(); token trong kernel: sentinel_pulse/ebpf/pulse_tokens.bpf.h: pulse_tok_return.')]))

# ---------------------------------------------------------------- 3.3 probe table and figure
after('39 syscall cần giá trị trả về phát token qua raw_tp/sys_exit', ''.join([
    P('Ba chương trình BPF, mỗi chương trình gắn vào một điểm của đường đi một syscall:'),
    T([['Điểm gắn (hàm)', 'Chạy khi nào', 'Dùng cho', 'Code'],
       ['raw_tp/sys_enter (pulse_sys_enter, pulse_record_call)', 'mỗi syscall bắt đầu, mọi syscall của node',
        'lọc cgroup theo allow-list; giữ trạng thái và 3 token gần nhất của thread; phát token tên cho mọi syscall **không** thuộc 39 syscall có hook; với 39 syscall có hook thì chỉ đánh dấu chờ',
        'sentinel_pulse/ebpf/pulse_counter.bpf.c'],
       ['raw_tp/sys_exit (pulse_tok_sys_exit, pulse_tok_return)', 'syscall trả về',
        '39 syscall có hook: phát token có mã lỗi, cỡ đọc ghi, hoặc chế độ mở và thư mục đầu (pulse_tok_dir_of_fd)',
        'sentinel_pulse/ebpf/pulse_tokens.bpf.h'],
       ['fexit/__seccomp_filter (pulse_seccomp_skip)', 'sau khi seccomp xử lý, khi seccomp bỏ qua syscall',
        'syscall bị seccomp chặn không chạy và không tới sys_enter hay sys_exit: phát token tên ở đây, để vẫn có đúng một token',
        'sentinel_pulse/ebpf/pulse_counter.bpf.c']], [2.6, 2.0, 3.6, 2.2]),
    B('**Lưu ý:** 39 syscall có hook là nhóm **cần** giá trị trả về và phát token ở sys_exit; sys_enter phát tên cho mọi syscall còn lại. Danh sách 39 syscall: sentinel_pulse/ebpf/pulse_token_ids.h (PULSE_HOOKED_ROWS).'),
    B('**Ghi token vào map và gửi lên user space:** pulse_tokens.bpf.h: pulse_tok_emit cộng 1 vào mục (cgroup, cửa sổ, 4-gram) của map pulse_grams; loader sentinel_pulse/ebpf/pulse_counter_loader.c: drain_grams đọc các cửa sổ đã đóng mỗi 0,5 s rồi xoá.'),
    IMG('probe', 'Hình 2. Probe eBPF trong kernel: ba chương trình BPF, cách phát token và ba map.')]))

# ---------------------------------------------------------------- 3.4 events
after('Kernel đếm thẳng số lần', ''.join([
    P('**Sự kiện là gì, và vì sao mỗi sự kiện cho đúng một 4-gram.**', 'FirstParagraph', keep=True),
    B('**Sự kiện** là một lần syscall của một thread trong container được theo dõi. Mỗi sự kiện cho đúng một token: lúc trả về với 39 syscall có hook, lúc vào với các syscall khác.'),
    B('**4-gram của một sự kiện** là token của nó cùng 3 token ngay trước nó trong cùng thread. Lịch sử của thread trượt đi một ô sau mỗi sự kiện, chứ không chia thành từng khối 4. Ví dụ một thread có token a, b, c, d, e: sự kiện d cho gram (a, b, c, d), sự kiện e cho gram (b, c, d, e). Vì vậy n sự kiện cho n gram.'),
    B('**0,5 s có rất nhiều syscall:** đúng, và mỗi syscall vẫn là một sự kiện với một gram. Nhưng kernel không lưu từng sự kiện: map pulse_grams giữ một mục cho mỗi (cgroup, cửa sổ, 4-gram khác nhau) kèm bộ đếm, nên một gram lặp lại chỉ cộng 1 vào mục đã có. Worker cũng tính −ln P một lần cho mỗi gram khác nhau rồi nhân với số lần. Chỉ container của namespace production được đếm (allow-list), không phải mọi syscall của node.'),
    P('Số đo trên lượt pulse-live-v5-1110 (5 segment đã khai của mỗi worker):'),
    T([['Mỗi cửa sổ 0,5 s', 'Trung vị', 'p99', 'Lớn nhất'],
       ['Sự kiện của một container', '51', '2.179', '12.381'],
       ['4-gram khác nhau của một container', '26', '651', '1.995'],
       ['Sự kiện của một node (mọi container được theo dõi)', '6.284', '18.710', '26.552'],
       ['4-gram khác nhau của một node (số mục map cần)', '1.950', '5.450', '6.901']], [4.6, 1.6, 1.6, 1.6]),
    B('**Map:** pulse_grams có 262.144 mục, khoảng hai cửa sổ cùng nằm trong map. Cửa sổ nặng nhất dùng 2,6% sức chứa. Ở segment cuối của mỗi worker, bộ đếm của loader ghi 0 lần chèn thất bại, 0 lần đi dentry bị cắt, mỗi lần đọc map mất 3–7 ms. Lượt này chưa đẩy probe tới giới hạn; bài đo tải tới khi map đầy vẫn phải làm.'),
    CODE('đo tải: scripts/analysis/token_load.py; biên nhận validation-evidence/results-20261113/ml-final-study/token-load.json, token-drain-last-segment.json.')]))

# ---------------------------------------------------------------- code lines in sections 4-9
after('Ví dụ: kịch bản CVE-2019-5418 học từ 270 bản ghi', CODE('sentinel_pulse/detector/token_model.py: CountTokenLM.learn (cụm); scripts/analysis/lidds_ml_tokens.py: TokenLM.learn (dataset).'))
after('Ý nghĩa: một openat!EACCES', CODE('token_model.py: CountTokenLM.base.'))
after('Kết quả: một 4-gram chưa thấy', CODE('token_model.py: CountTokenLM.prob.'))
after('Kết quả: −ln P₃ = 49,94', CODE('ví dụ tính bằng scripts/analysis/lidds_token_explain.py: backoff(); biên nhận validation-evidence/results-20261112/token-explain/CVE-2019-5418.json.'))
after('Lấy 10 thay vì 1', CODE('token_model.py: CountTokenLM.window_score.'))
after('Ngưỡng ở mức α′ = 0,00018', CODE('cụm: scripts/analysis/token_branch_fit.py: fold_of, crossfit_one, fit_crossfit, trimmed_gumbel; dataset: scripts/analysis/lidds_ml_token_crossfit.py, lidds_ml_v4.py: trimmed_gumbel, lidds_ml_v2.py: gumbel, threshold.'))
after('Trên cụm, worker chấm mỗi cửa sổ', CODE('token_model.py: TokenBranch.score; sentinel_pulse/pipeline/matched_worker.py.'))
after('Biên an toàn có thể rất hẹp', CODE('scripts/analysis/lidds_token_explain.py; biên nhận validation-evidence/results-20261112/token-explain/.'))
after('Thành phầnLID-DS 2021', CODE('học trên cụm: scripts/analysis/token_branch_fit.py; nhận cửa sổ token từ loader: sentinel_pulse/collector/token_capture.py; chọn normal ngoài trial: token_branch_fit.py: trial_spans.'))
after('Chưa đo: chi phí trên request', CODE('chi phí probe: scripts/overhead_ab.sh, scripts/analysis/overhead_ab.py; CPU worker: thời gian CPU của unit worker (validation-evidence/results-20261112/pulse-live-v5-1110/worker-cpu.txt).'))
after('Thêm 13 syscall khác', CODE('scripts/analysis/lidds_token_cache.py, scripts/analysis/lidds_token_study.py (bước q1, q2, q3, q4, official).'))
after('Development và CB-DS: 530/544', CODE('scripts/analysis/lidds_ml_v5.py.'))
after('Mức chấp nhận của protocol v5', CODE('scripts/analysis/pulse_live_v4.py.'))
after('Hạng 1 có lợi thế từ thiết kế campaign', CODE('sentinel_pulse/ops/alert_bridge.py, sentinel_pulse/rca/service.py; phân tích: scripts/analysis/alert_delivery_latency.py, bridge_delivery.py, rca_coverage.py, rca_follow_up.py.'))

# ---------------------------------------------------------------- 8.5 weakness study
after('Làm được', ''.join([
    H2('8.5 Nghiên cứu các điểm yếu còn lại (12–13/11)'),
    P('Protocol ml-final-study-v1 được đăng ký trước khi viết code (12/11 21:50), mỗi phần có tiêu chí cố định. Mọi số dưới đây là phân tích trên dữ liệu đã có (development và lượt v5).', 'FirstParagraph'),
    T([['Câu hỏi', 'Cách làm', 'Kết quả', 'Quyết định'],
       ['A. Recall live có phải chỉ do burst khởi chạy qua kubectl exec?', 'Chấm lại cửa sổ tấn công sau khi bỏ mọi gram mà binary vô hại và lệnh quản trị của cùng trial đã sinh ra',
        'Tập chính vẫn bắt 314/314; báo sau 1,5 s đầu (không bỏ gram) 302/314; 0 trial chỉ bị bắt nhờ burst', 'Recall live đo đúng hành vi tấn công'],
       ['B. Học thêm lệnh quản trị như normal có hết gắn cờ?', 'Bỏ-một-lệnh: mô hình học 9 lệnh, chấm lệnh còn lại',
        'Lệnh chưa học vẫn bị gắn cờ 362/439 (82,5%, trước đó 96,1%); recall tấn công tụt còn 303/314', 'Không đạt (cần ≤ 20%): không đổi'],
       ['C. Ngưỡng theo phân vị thực nghiệm của 134.905 khối 60 s?', 'Học lại cross-fit, lấy phân vị (1 − α′) thay Gumbel',
        'Gánh giảm một nửa nhưng tập chính còn 281/314; LID-DS development 498/544 với 13 báo nhầm', 'Bị loại, giữ Gumbel'],
       ['D. Tín hiệu tần suất cho tấn công chỉ dùng chuỗi đã thấy?', 'Điểm = max log((n + 1)/(m + 1)) với m là số lần lớn nhất của gram trong một cửa sổ normal',
        'Riêng tín hiệu bắt 225/544 tấn công chỉ dùng chuỗi đã thấy (mô hình: 0); ghép với mô hình: 530/544 với 12 báo nhầm, CB-DS 4 báo nhầm', 'Trượt tiêu chí CB-DS (≤ 3) một báo nhầm: không ghép']], [2.6, 2.6, 2.8, 1.8]),
    B('**Kết luận:** không ứng viên nào đạt tiêu chí đã đăng ký, mô hình ML cuối giữ là lidds-ml-v5. Binary vô hại và lệnh quản trị không giảm được bằng cách học thêm normal: mỗi lệnh mới đều có hành vi riêng chưa thấy. Hướng tiếp theo là rule sau ML (mục 11).'),
    CODE('protocol sentinel_pulse/protocol/ml-final-study-v1.json; scripts/analysis/live_attribution.py (A, B), token_branch_fit.py --dump-maxima và cluster_threshold.py (C), lidds_token_rate.py (D); biên nhận validation-evidence/results-20261113/ml-final-study/.')]))
toc_after('8.4 Mô hình làm được gì', '8.5 Nghiên cứu các điểm yếu còn lại (12–13/11)')

# ---------------------------------------------------------------- 11 next steps
after('LID-DS 2019: chấm đúng một lần', ''.join([
    B('**Rule sau khi chốt ML** (protocol ml-final-study-v1, phần E): R1 hạ cảnh báo xuống mức thông tin khi trong cửa sổ chỉ có runtime exec của tool có sẵn trong image; R2 gắn nhãn drift cho binary không có trong image. So sánh có và không có rule trên dữ liệu v5, rồi trên lượt live mới có thêm tấn công dùng chính tool của image.')]))


def add_row(first_cell, cells, table_head):
    """Copy the row whose first cell is first_cell, in the table whose header starts with table_head, right after it."""
    global d
    tbl = next(t for t in re.finditer(r'<w:tbl>.*?</w:tbl>', d, flags=re.S) if text_of(t.group(0)).startswith(table_head))
    for m in re.finditer(r'<w:tr>.*?</w:tr>', tbl.group(0), flags=re.S):
        row = m.group(0)
        tcs = re.findall(r'<w:tc>.*?</w:tc>', row, flags=re.S)
        if tcs and text_of(tcs[0]) == first_cell:
            new = row
            for tc, text in zip(tcs, cells):
                ts = re.findall(r'<w:t[^>]*>[^<]*</w:t>', tc)
                tc2 = tc.replace(ts[0], f'<w:t xml:space="preserve">{escape(text)}</w:t>', 1)
                for t in ts[1:]:
                    tc2 = tc2.replace(t, '<w:t></w:t>', 1)
                new = new.replace(tc, tc2, 1)
            pos = tbl.start() + m.end()
            d = d[:pos] + new + d[pos:]
            return
    raise SystemExit(f'row not found: {first_cell}')


add_row('token-explain', ['ml-final-study-v1', '12–13/11', 'A–D xong; không ứng viên nào đạt tiêu chí, ML giữ lidds-ml-v5 (mục 8.5)'], 'Lượt / job')
add_row('Token', ['Sự kiện', 'Một lần syscall của một thread trong container được theo dõi; cho đúng một token và một 4-gram'], 'Thuật ngữ')
add_row('Sự kiện', ['Bảng chữ', 'Bộ quy tắc biến một lần syscall thành token'], 'Thuật ngữ')
add_row('Bảng chữ', ['select1f / probe1f', 'Bảng chữ đang dùng: 27 syscall giữ mã lỗi, cỡ log₂ đủ 16 nhóm, thêm futex / cùng quy tắc nhưng theo thứ tự probe phát'], 'Thuật ngữ')

open(DOC, 'w', encoding='utf-8').write(d)

# relationships and media
rels = open('x/word/_rels/document.xml.rels', encoding='utf-8').read()
import shutil, os
os.makedirs('x/word/media', exist_ok=True)
for rid, name in IMAGES:
    shutil.copy(f'{FIG}/{name}.png', f'x/word/media/{name}.png')
    if rid not in rels:
        rels = rels.replace('</Relationships>', f'<Relationship Id="{rid}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="media/{name}.png"/></Relationships>')
open('x/word/_rels/document.xml.rels', 'w', encoding='utf-8').write(rels)
print('images', IMAGES)
