#!/usr/bin/env python3
"""Build docs/architecture/sentinel-pulse-architecture.drawio (5 pages, Vietnamese) and
sentinel-pulse-overview-en.drawio (one page, English, the paper's Figure 1) from the facts in the repository.

Sources: thesis/chapters/design.tex and implementation.tex (system, RCA, alert path, cluster), README.md (nodes),
sentinel_pulse/ebpf/* (probe, token layout), sentinel_pulse/pipeline/matched_worker.py (worker),
sentinel_pulse/protocol/lidds-ml-v5.json (+ amendments), lidds2019-development-v1 (+ amendment 1: lidds-ml-v5-t3),
improvement-round-v1 (D1-D18) and pulse-live-final-v1 (the final live run), validation-evidence/, notes/STATE.md.
State of 19/11/2026: the system of the final live run pulse-live-final-1119: lidds-ml-v5-t3 token model alone (top 3,
trim 0.5 %, alpha' 0.0003), lineage tag, gram-map overflow alert (D1), durable bridge queue (D3), alert label stream.

    python3 docs/architecture/make_architecture_drawio.py   # then export with drawio -x (see README.md here)
"""
from pathlib import Path
from xml.sax.saxutils import escape

OUT = Path(__file__).resolve().parent / 'sentinel-pulse-architecture.drawio'

C = dict(  # fill, stroke
    kernel=('#FFF2CC', '#D6B656'), user=('#DAE8FC', '#6C8EBF'), ml=('#D5E8D4', '#82B366'),
    store=('#F5F5F5', '#666666'), alert=('#F8CECC', '#B85450'), eval=('#E1D5E7', '#9673A6'),
    ext=('#FFE6CC', '#D79B00'), retired=('#FAFAFA', '#B3B3B3'), k8s=('#FFFFFF', '#326CE5'),
    note=('#FFFDE7', '#BDB76B'))


# Code of each box (owner 19/11: the architecture figures name the code). Keyed by the box title; full repo paths.
SP = 'sentinel_pulse/'
CODE = {
    # page 1
    'Probe eBPF của Pulse': SP + 'ebpf/pulse_counter.bpf.c, pulse_tokens.bpf.h, pulse_token_ids.h',
    'Allow-list cgroup': SP + 'ebpf/pulse_counter.bpf.c (map pulse_cgroups); nạp: pulse_counter_loader.c (refresh_targets)',
    'Loader C (pulse_counter_tokens_loader)': SP + 'ebpf/pulse_counter_loader.c',
    'sentinel-pulse-resolver': SP + 'collector/cgroup_resolver.py; unit: ' + SP + 'systemd/sentinel-pulse-resolver.service',
    'Worker chấm điểm (pipeline/matched_worker.py, 3 core, 3 GB)': SP + 'pipeline/matched_worker.py, ' + SP + 'detector/token_model.py, '
        + SP + 'collector/token_capture.py, ' + SP + 'pipeline/async_sink.py',
    'Luồng decision local': SP + 'pipeline/matched_worker.py (stream_root)',
    'Alert bridge (trên .234)': SP + 'ops/alert_bridge.py; scripts/alert_bridge.sh',
    'Alertmanager': 'testbed/k8s/monitoring/sentinel-pulse-alerting.yaml',
    'Prometheus / Grafana': 'testbed/k8s/monitoring/sentinel-pulse-dashboard.json',
    'Planner + launcher': SP + 'pipeline/plan_matched_run.py, scripts/launch_run.sh, scripts/k8s_events_record.py',
    'Job phân tích (.234)': 'scripts/analysis/',
    'Tải normal (đánh giá)': SP + 'pipeline/matched_traffic.py, testbed/traffic/set_aims_traffic_regime.sh',
    'Chiến dịch tấn công (đánh giá)': SP + 'attack/preview_campaign.py, testbed/attack/runtime_attack_with_benign_control.c',
    'NFS .233: /sentinel-pulse': 'ghi bởi ' + SP + 'pipeline/matched_worker.py; nén: scripts/compress_raw_frames.py',
    'Repo git (GitHub, main)': 'scripts/sync_cluster_checkouts.sh',
    'Dữ liệu công khai (offline)': SP + 'lidds/, scripts/analysis/lidds_*.py',
    # page 2
    'raw_tp/sys_enter → pulse_record_call': SP + 'ebpf/pulse_counter.bpf.c',
    'fexit/__seccomp_filter': SP + 'ebpf/pulse_counter.bpf.c (pulse_seccomp_skip)',
    'raw_tp/sys_exit → pulse_tok_sys_exit': SP + 'ebpf/pulse_tokens.bpf.h (pulse_tok_return, pulse_tok_dir_of_fd); bảng: pulse_token_ids.h',
    '.rodata.tokcfg': SP + 'ebpf/pulse_tokens.bpf.h (pulse_tok_config)',
    'raw_tp/sched_process_fork': SP + 'ebpf/pulse_tokens.bpf.h (pulse_tok_fork, pulse_tok_lineage)',
    'pulse_tok_emit (gọi từ cả ba hook)': SP + 'ebpf/pulse_tokens.bpf.h',
    'pulse_cgroups': SP + 'ebpf/pulse_counter.bpf.c',
    'pulse_last_syscall': SP + 'ebpf/pulse_counter.bpf.c',
    'pulse_grams': SP + 'ebpf/pulse_tokens.bpf.h',
    'pulse_stats, pulse_tok_stats': SP + 'ebpf/pulse_counter.bpf.c, pulse_tokens.bpf.h',
    'Khởi động': SP + 'ebpf/pulse_counter_loader.c (main)',
    'Mỗi 0,5 s (MONOTONIC + 20 ms)': SP + 'ebpf/pulse_counter_loader.c (drain_grams, print_snapshots)',
    'Dòng JSON ra stdout (một frame)': 'proof: scripts/token_probe_proof.py, scripts/lineage_probe_proof.py',
    # page 3
    'Dòng token_grams từ loader': SP + 'pipeline/matched_worker.py (run)',
    'token_window (collector/token_capture.py)': SP + 'collector/token_capture.py (token_window, check_grams)',
    'Metadata resolver': SP + 'collector/cgroup_resolver.py; workload_key: ' + SP + 'collector/capture.py',
    'CountTokenLM của workload': SP + 'detector/token_model.py (CountTokenLM); offline: scripts/analysis/lidds_ml_tokens.py',
    'Điểm cửa sổ': SP + 'detector/token_model.py (CountTokenLM.window_score)',
    'TokenBranch (cfg tokens.models)': SP + 'detector/token_model.py (TokenBranch); ' + SP + 'collector/token_capture.py (MapOverflow)',
    'Bảng chữ select1f': SP + 'ebpf/pulse_token_ids.h, pulse_tokens.bpf.h; offline: scripts/analysis/lidds_token_cache.py',
    'Decision = mô hình token của workload báo (một cửa sổ là đủ)': SP + 'pipeline/matched_worker.py (run)',
    'NFS: segment 30 phút': SP + 'pipeline/matched_worker.py (run, TERMINAL.json)',
    'Đĩa local của worker': SP + 'pipeline/matched_worker.py (stream_root)',
    'Ghi ngoài vòng chấm (async_sink)': SP + 'pipeline/async_sink.py (AsyncSink, AsyncState)',
    'Khoá trước khi chấm': SP + 'pipeline/matched_worker.py (run), ' + SP + 'detector/token_model.py (TokenBranch)',
    # page 4
    'Worker ×3': SP + 'pipeline/matched_worker.py',
    'Alert bridge (ops/alert_bridge.py)': SP + 'ops/alert_bridge.py (Streams, Bridge, push_worker, PushQueue, stream_of)',
    'Alertmanager (API v2)': 'testbed/k8s/monitoring/sentinel-pulse-alerting.yaml',
    'Route theo notify': 'testbed/k8s/monitoring/sentinel-pulse-alerting.yaml',
    # page 5
    'LID-DS 2021 development + CB-DS': 'scripts/analysis/lidds_ml_v5.py, lidds_ml_token_crossfit.py',
    'LID-DS 2021 official': 'scripts/analysis/lidds_ml_v5.py; t3: lidds2019_dev.py (official)',
    'LID-DS 2019': 'scripts/analysis/lidds2019_dev.py, scripts/lidds2019_amendment1_run.sh',
    'Thu normal + fit trên cụm': 'scripts/launch_run.sh, scripts/analysis/token_branch_fit.py',
    'Lượt live v4–v6': 'scripts/analysis/pulse_live_v4.py, native_stream.py',
    'Lượt live cuối (45 h)': 'scripts/launch_run.sh (REHEARSAL=1), ' + SP + 'protocol/pulse-live-final-v1.json',
    'Ngưỡng': 'scripts/analysis/lidds_ml_v4.py (trimmed_gumbel), lidds_ml_v2.py (gumbel, threshold)',
    'Overhead probe token (token-probe-overhead-v1)': 'scripts/overhead_ab.sh, testbed/bench/syscall_bench.c, scripts/app_overhead_ab.py',
    'Gate cho binary vô hại (đã loại)': SP + 'detector/token_model.py (TokenBranch gate), scripts/analysis/token_branch_fit.py',
    # English page (paper)
    'eBPF probe (kernel)': SP + 'ebpf/',
    'Loader': SP + 'ebpf/pulse_counter_loader.c',
    'Scoring worker': SP + 'pipeline/matched_worker.py, detector/token_model.py',
    'Decisions': SP + 'pipeline/matched_worker.py',
    'Resolver': SP + 'collector/cgroup_resolver.py',
    'Offline fit': 'scripts/analysis/token_branch_fit.py',
    'Alert bridge': SP + 'ops/alert_bridge.py',
}


def wrap_code(text, width, size):
    """Lines of 'code: a, b, c' that fit the box: paths kept whole when they fit, else broken after a '/'."""
    fit = max(12, int((width - 14) / (size * 0.56)))
    pieces = []
    for path in text.split(', '):
        while len(path) > fit:
            cut = path.rfind('/', 0, fit)
            if cut <= 0:
                break
            pieces.append(path[:cut + 1])
            path = path[cut + 1:]
        pieces.append(path)
    lines, cur = [], 'code:'
    for piece in pieces:
        glue = '' if cur.endswith('/') else (' ' if cur == 'code:' else ', ')
        if len(cur) + len(glue) + len(piece) <= fit:
            cur += glue + piece
        else:
            lines.append(cur + ('' if cur.endswith('/') or cur == 'code:' else ','))
            cur = piece
    lines.append(cur)
    return '<br>'.join(escape(l) for l in lines)


def label(title, sub=None, small=10, width=None):
    t = f'<b>{title}</b>'
    if sub:
        t += f'<br><font style="font-size:{small}px">{sub}</font>'
    if title in CODE:
        size = max(8, small - 1)
        t += (f'<br><font style="font-size:{size}px" color="#1F4E79"><i>'
              f'{wrap_code(CODE[title], width or 400, size)}</i></font>')
    return t


class Page:
    def __init__(self, name, width=1700, height=1150):
        self.name, self.width, self.height = name, width, height
        self.cells, self.n = [], 0

    def _id(self):
        self.n += 1
        return f'{self.name[:2]}-{self.n}'

    def box(self, x, y, w, h, title, sub=None, kind='user', shape='rounded=1', extra='', parent='1', small=10,
            align='center'):
        fill, stroke = C[kind]
        dashed = 'dashed=1;' if kind in ('eval', 'retired') else ''
        font = 'fontColor=#888888;' if kind == 'retired' else ''
        valign = 'verticalAlign=top;spacingTop=6;spacingLeft=6;' if align == 'left' else ''
        style = (f'{shape};whiteSpace=wrap;html=1;fillColor={fill};strokeColor={stroke};{dashed}{font}'
                 f'arcSize=8;fontSize=12;align={align};spacing=4;{valign}{extra}')
        return self._vertex(x, y, w, h, label(title, sub, small, w), style, parent)

    def store(self, x, y, w, h, title, sub=None, parent='1'):
        fill, stroke = C['store']
        style = (f'shape=cylinder3;whiteSpace=wrap;html=1;boundedLbl=1;backgroundOutline=1;size=10;fillColor={fill};'
                 f'strokeColor={stroke};fontSize=12;')
        return self._vertex(x, y, w, h, label(title, sub, 10, w), style, parent)

    def group(self, x, y, w, h, title, kind='store', extra='', parent='1', size=13):
        fill, stroke = C[kind]
        style = (f'rounded=1;whiteSpace=wrap;html=1;fillColor=none;strokeColor={stroke};strokeWidth=2;arcSize=2;'
                 f'verticalAlign=top;align=left;spacingLeft=10;spacingTop=4;fontStyle=1;fontSize={size};'
                 f'fontColor={stroke};container=0;{extra}')
        return self._vertex(x, y, w, h, title, style, parent)

    def band(self, x, y, w, h, title, kind):
        fill, stroke = C[kind]
        style = (f'rounded=0;whiteSpace=wrap;html=1;fillColor={fill};opacity=35;strokeColor={stroke};dashed=1;'
                 f'verticalAlign=top;align=right;spacingRight=8;fontStyle=3;fontSize=11;fontColor=#555555;')
        return self._vertex(x, y, w, h, title, style, '1')

    def text(self, x, y, w, h, html, size=12, align='left', extra=''):
        style = f'text;html=1;whiteSpace=wrap;align={align};verticalAlign=top;fontSize={size};{extra}'
        return self._vertex(x, y, w, h, html, style, '1')

    def icon(self, x, y, w, h, icon, caption=''):
        style = (f'aspect=fixed;sketch=0;html=1;dashed=0;whitespace=wrap;fillColor=#2875E2;strokeColor=#ffffff;'
                 f'points=[];shape=mxgraph.kubernetes.icon;prIcon={icon};verticalLabelPosition=bottom;'
                 f'verticalAlign=top;fontSize=9;')
        return self._vertex(x, y, w, h, caption, style, '1')

    def _vertex(self, x, y, w, h, value, style, parent):
        i = self._id()
        self.cells.append(f'<mxCell id="{i}" value="{escape(value, {chr(34): "&quot;"})}" style="{style}" vertex="1" '
                          f'parent="{parent}"><mxGeometry x="{x}" y="{y}" width="{w}" height="{h}" as="geometry"/></mxCell>')
        return i

    def edge(self, s, t, text='', kind='data', exit=None, entry=None, points=(), extra=''):
        styles = dict(data='strokeColor=#333333;', eval='strokeColor=#9673A6;dashed=1;',
                      alert='strokeColor=#B85450;strokeWidth=2;', ctrl='strokeColor=#6C8EBF;dashed=1;dashPattern=1 3;',
                      store='strokeColor=#888888;', kernel='strokeColor=#B58900;strokeWidth=2;')
        style = ('edgeStyle=orthogonalEdgeStyle;rounded=1;html=1;endArrow=block;endFill=1;fontSize=10;'
                 'labelBackgroundColor=#FFFFFF;' + styles[kind] + extra)
        if exit:
            style += f'exitX={exit[0]};exitY={exit[1]};exitDx=0;exitDy=0;'
        if entry:
            style += f'entryX={entry[0]};entryY={entry[1]};entryDx=0;entryDy=0;'
        i = self._id()
        pts = ''.join(f'<mxPoint x="{px}" y="{py}"/>' for px, py in points)
        geo = f'<mxGeometry relative="1" as="geometry">{"<Array as=\"points\">" + pts + "</Array>" if pts else ""}</mxGeometry>'
        self.cells.append(f'<mxCell id="{i}" value="{escape(text, {chr(34): "&quot;"})}" style="{style}" edge="1" '
                          f'parent="1" source="{s}" target="{t}">{geo}</mxCell>')
        return i

    def title(self, main, sub):
        self.text(20, 10, self.width - 40, 30, f'<b>{main}</b>', size=20)
        self.text(20, 40, self.width - 40, 22, sub, size=12, extra='fontColor=#555555;')

    def xml(self, index):
        body = ''.join(self.cells)
        return (f'<diagram id="page-{index}" name="{escape(self.name)}"><mxGraphModel dx="1400" dy="900" grid="1" '
                f'gridSize="10" guides="1" tooltips="1" connect="1" arrows="1" fold="1" page="1" pageScale="1" '
                f'pageWidth="{self.width}" pageHeight="{self.height}" background="#FFFFFF" math="0" shadow="0">'
                f'<root><mxCell id="0"/><mxCell id="1" parent="0"/>{body}</root></mxGraphModel></diagram>')


def legend(p, x, y):
    p.group(x, y, 330, 232, 'Chú giải', kind='store', size=12)
    rows = [('kernel', 'Kernel: probe eBPF của Pulse'), ('user', 'User space của Pulse (C, Python)'),
            ('ml', 'Mô hình token lidds-ml-v5-t3'), ('alert', 'Đường cảnh báo'),
            ('ext', 'Thành phần có sẵn của cụm'), ('eval', 'Chỉ dùng khi đánh giá (đứt nét)'),
            ('retired', 'Giữ lại, không dùng để báo (xám)')]
    for k, (kind, t) in enumerate(rows):
        p.box(x + 12, y + 32 + 28 * k, 26, 18, '', kind=kind)
        p.text(x + 46, y + 30 + 28 * k, 280, 22, t, size=11)


EDGE_VI = [('kernel', 'Dữ liệu trong kernel (syscall, map)'), ('data', 'Dữ liệu sự kiện (cửa sổ token, decision)'),
           ('alert', 'Đường cảnh báo'), ('store', 'Ghi lưu trữ (NFS)'),
           ('ctrl', 'Điều khiển, cấu hình (đổi chậm, không mang sự kiện)'),
           ('eval', 'Chỉ khi đánh giá (lịch trial)')]
EDGE_EN = [('kernel', 'kernel data'), ('data', 'event data'), ('alert', 'alert path'),
           ('ctrl', 'control and configuration (slow-changing, no events)')]


def edge_legend(p, x, y, rows, columns=1, width=330, title='Kiểu mũi tên'):
    """Line samples for the edge kinds used on a page (an invisible pair of points per sample)."""
    per = -(-len(rows) // columns)
    col_w = (width - 24) // columns
    p.group(x, y, width, 34 + 26 * per, title, kind='store', size=12)
    dot = 'text;html=1;strokeColor=none;fillColor=none;'
    for k, (kind, label) in enumerate(rows):
        cx, cy = x + 12 + col_w * (k // per), y + 38 + 26 * (k % per)
        a = p._vertex(cx, cy + 8, 1, 1, '', dot, '1')
        b = p._vertex(cx + 44, cy + 8, 1, 1, '', dot, '1')
        p.edge(a, b, '', kind=kind)
        p.text(cx + 52, cy - 2, col_w - 56, 22, label, size=11)


# ---------------------------------------------------------------- page 1: overview
def overview():
    p = Page('1. Tổng quan hệ thống', 1720, 1260)
    p.title('Sentinel Pulse: kiến trúc tổng thể (19/11/2026, lượt live cuối)',
            'Phát hiện runtime trên Kubernetes bằng mô hình ngôn ngữ trên token syscall do eBPF dựng trong kernel (lidds-ml-v5-t3), '
            'cảnh báo qua Alertmanager. Khung tím đứt nét chỉ dùng khi đánh giá.')
    p.group(20, 75, 1235, 945, 'Cụm Kubernetes của lab: 6 VM trên ESXi · Ubuntu 24.04 · kernel 6.8.0 · '
                               'Kubernetes v1.34 · Cilium · Istio ambient', kind='k8s', size=13)
    p.group(40, 110, 800, 700, 'Mỗi worker (×3): k8s-worker1 .237 · k8s-worker4 .238 · k8s-worker3 .239',
            kind='user', size=12)
    p.icon(785, 116, 40, 39, 'node')
    p.band(55, 150, 770, 115, 'namespace production: ứng dụng AIMS (21 workload, khoảng 80 pod)', 'ext')
    apps = ['frontend', 'API gateway', 'service Python', 'PostgreSQL (CNPG)', 'Kafka', 'RabbitMQ', 'Redis', 'MinIO']
    pods = [p.box(68 + 93 * k, 175, 86, 40, a, kind='ext', small=9) for k, a in enumerate(apps)]
    p.text(68, 222, 740, 36, 'Mỗi container là một cgroup: Pulse dựng token theo cgroup và thread, không sửa ứng dụng hay pod.',
           size=10, extra='fontColor=#555555;')
    p.band(55, 280, 770, 160, 'Kernel Linux 6.8 (eBPF, BTF)', 'kernel')
    probe = p.box(70, 305, 300, 120, 'Probe eBPF của Pulse',
                  'raw_tp/sys_enter: allow-list, trạng thái thread, token lúc vào<br>raw_tp/sys_exit: token lúc trả về (39 syscall)<br>'
                  'fexit/__seccomp_filter: syscall bị seccomp bỏ qua<br>raw_tp/sched_process_fork: thẻ dòng dõi native/session<br>'
                  'map: trạng thái thread, 4-gram theo (cgroup, cửa sổ, dòng dõi)',
                  kind='kernel', small=9)
    allow = p.box(400, 305, 410, 120, 'Allow-list cgroup', 'map pulse_cgroups: chỉ cgroup production được theo dõi; cgroup '
                  'khác thoát sau một lần tra map', kind='kernel', small=9)
    p.band(55, 455, 770, 340, 'User space của worker (unit systemd)', 'user')
    loader = p.box(70, 480, 300, 100, 'Loader C (pulse_counter_tokens_loader)', 'khoá SHA-256 + proof theo kernel; mỗi '
                   '0,5 s: dòng token_grams cho mỗi (cgroup, cửa sổ đã đóng)', kind='user', small=9)
    resolver = p.box(400, 480, 410, 100, 'sentinel-pulse-resolver', 'pod UID → container → cgroup → phiên bản workload',
                     kind='user', small=9)
    worker = p.box(70, 605, 530, 175, 'Worker chấm điểm (pipeline/matched_worker.py, 3 core, 3 GB)',
                   '• kiểm hợp đồng của cửa sổ token; gắn workload, Pod, container<br>'
                   '• mô hình ngôn ngữ 4-gram Witten-Bell của workload (khoá SHA-256)<br>'
                   '• điểm = trung bình 3 giá trị −ln p lớn nhất (top của MODELS.json)<br>'
                   '• ngưỡng Gumbel trên điểm giữ ra (khối 60 s, cross-fit 5 fold); một cửa sổ vượt ngưỡng là báo<br>'
                   '• map gram đầy (insert_fail tăng) → báo cửa sổ nặng nhất của frame (D1)<br>'
                   '• ghi NFS bằng thread nền (AsyncSink), ngoài vòng chấm', kind='ml', align='left', small=10)
    local = p.store(630, 615, 180, 160, 'Luồng decision local', '/var/lib/sentinel-pulse-live (đĩa của worker)')
    p.group(875, 110, 360, 700, 'Master (×3): .234 k8s-master · .235 · .236', kind='alert', size=12)
    p.icon(1190, 116, 40, 39, 'master')
    bridge = p.box(890, 150, 330, 105, 'Alert bridge (trên .234)', 'đọc decision local của 3 worker qua SSH; gom đợt '
                   'theo container; push API v2; đợt chưa giao giữ trong hàng đợi bền, thử lại tới 1 giờ (D3); nhãn stream '
                   'native/session', kind='alert', small=9)
    am = p.box(890, 285, 330, 70, 'Alertmanager', 'kube-prometheus-stack; gửi thông báo cho người vận hành', kind='alert', small=9)
    graf = p.box(890, 385, 330, 90, 'Prometheus / Grafana', 'scrape gauge /metrics của bridge (đường pull, để so độ trễ); '
                 'dashboard; NodePort 32090 / 32300', kind='ext', small=9)
    planner = p.box(890, 645, 160, 150, 'Planner + launcher', 'CONFIG.json bất biến: hash mô hình, probe, fixture, '
                    'lịch tải, lịch trial; diễn tập trước lượt; ghi sự kiện K8s', kind='eval', small=9)
    p.box(1060, 645, 160, 150, 'Job phân tích (.234)', 'systemd-run có MemoryMax; học mô hình (token_branch_fit.py), chấm LID-DS; '
          'đọc NFS, repo, dữ liệu công khai; không chạy cùng lượt live', kind='eval', small=9)
    p.box(40, 845, 400, 110, 'Tải normal (đánh giá)', '4 generator trong namespace production gửi HTTP tới AIMS; chế độ '
          'steady, toolmix, peak, burst, recovery theo lịch đăng ký', kind='eval')
    campaign = p.box(460, 845, 380, 110, 'Chiến dịch tấn công (đánh giá)', 'lượt cuối 945 trial: 21 workload × 5 kịch '
                     'bản × tốc độ 0,1–24/s, pha loãng PAD 300, bật-tắt 10 s; mỗi trial: control 15 s rồi theo thứ tự có '
                     'seed: lệnh admin, binary vô hại, tấn công, lotl, event-generator', kind='eval', small=9)
    nfs = p.store(1280, 110, 410, 160, 'NFS .233: /sentinel-pulse', '/mnt/sentinel-pulse-archive; segment 30 phút mỗi '
                  'worker: decisions, tokens, issues, TERMINAL.json (seal SHA-256); CONFIG.json, mô hình token')
    people = p.box(1280, 290, 410, 80, 'Người vận hành', 'nhận thông báo từ Alertmanager hoặc xem dashboard', kind='alert',
                   small=10)
    p.box(1280, 400, 410, 130, 'Repo git (GitHub, main)', 'code Pulse · protocol đăng ký trước · biên nhận JSON '
          '(validation-evidence/) · audit số liệu · đồ án LaTeX (thesis/) · notes/<br>checkout trên .234/.237/.238/.239 '
          'đồng bộ bằng git pull --ff-only', kind='store', small=10)
    p.box(1280, 560, 410, 110, 'Dữ liệu công khai (offline)', 'LID-DS 2021 (15 kịch bản, development → official), '
          'CB-DS, LID-DS 2019 (development 30% / holdout 70%)', kind='eval', small=10)
    legend(p, 1280, 700)
    edge_legend(p, 1280, 945, EDGE_VI[:5], width=410)
    p.edge(pods[0], probe, 'syscall', kind='kernel', exit=(0.5, 1), entry=(0.137, 0))
    p.edge(probe, loader, 'đọc map theo lô', kind='kernel', exit=(0.5, 1), entry=(0.5, 0))
    p.edge(resolver, allow, 'allowed-cgroups (loader nạp vào map)', kind='ctrl', exit=(0.5, 0), entry=(0.5, 1))
    p.edge(loader, worker, 'cửa sổ token', kind='data', exit=(0.5, 1), entry=(0.283, 0))
    p.edge(resolver, worker, 'cgroups.json', kind='ctrl', exit=(0.5, 1), entry=(0.811, 0))
    p.edge(worker, local, 'decision', kind='data', exit=(1, 0.5), entry=(0, 0.47))
    p.edge(local, bridge, 'SSH, chỉ dòng báo', kind='alert', exit=(1, 0.25), entry=(0, 0.5), points=[(850, 655), (850, 202)])
    p.edge(bridge, am, 'POST /api/v2/alerts', kind='alert', exit=(0.5, 1), entry=(0.5, 0))
    p.edge(am, people, '', kind='alert', exit=(1, 0.5), entry=(0, 0.375))
    p.edge(worker, nfs, 'decisions / tokens (NFS)', kind='store', exit=(0.5, 1), entry=(0, 0.47),
           points=[(335, 822), (1266, 822), (1266, 185)])
    p.edge(planner, campaign, 'lịch trial', kind='eval', exit=(0.5, 1), entry=(1, 0.5), points=[(970, 900)])
    p.text(20, 1035, 1235, 100,
           '<b>Đường dữ liệu chính:</b> syscall của container → probe eBPF dựng token, đếm 4-gram theo thread → loader đọc map '
           'mỗi 0,5 s → worker chấm mô hình token của workload → decision ghi local và NFS → bridge gom đợt, đẩy vào '
           'Alertmanager → người vận hành.<br><b>Mục tiêu:</b> recall ≥ 95%, '
           'precision ≥ 95%, p95 kernel → cảnh báo ≤ 3 s; gánh cảnh báo và binary vô hại bị gắn cờ càng thấp càng tốt. '
           'Kết quả (lidds-ml-v5-t3): LID-DS 2021 official 97,25% / 0,19% báo nhầm, p95 1,54 s; LID-DS 2019 holdout 97,15% (dung sai '
           'nhãn 1 s), p95 10,95 s. Live v6 (lidds-ml-v5): tốc độ chính 315/315, precision 99,68%, p95 0,45 s. Lượt cuối '
           'pulse-live-final-1119 chạy 19/11–21/11.', size=12)
    return p


# ---------------------------------------------------------------- page 2: kernel probe
def kernel():
    p = Page('2. Probe eBPF trong kernel', 1720, 1010)
    p.title('Probe eBPF: pulse_counter_tokens (make tokens)',
            'Token select1f cho mô hình lidds-ml-v5-t3; build pulse-tokens-final-f8ccbb2. Không có ftrace_ops nào ngoài '
            'fexit/__seccomp_filter: ba raw tracepoint (sys_enter, sys_exit, sched_process_fork). Bộ đếm syscall theo cgroup '
            'còn trong build, không dùng để báo.')
    p.band(20, 75, 1680, 85, 'Một syscall của process trong container được giám sát', 'ext')
    sysc = p.box(40, 95, 280, 50, 'syscall(nr, args)', 'x86_64; mọi thread', kind='ext')
    sk = p.box(370, 95, 280, 50, 'seccomp của container', 'SECCOMP_RET_ERRNO → syscall không chạy', kind='ext')
    body = p.box(700, 95, 300, 50, 'thân syscall (__x64_sys_*)', 'ret ≥ 0 hoặc −errno', kind='ext')
    ret = p.box(1050, 95, 300, 50, 'trở về user space', 'syscall_exit_work', kind='ext')
    p.edge(sysc, sk, '', kind='data')
    p.edge(sk, body, 'cho phép', kind='data')
    p.edge(body, ret, '', kind='data')
    p.band(20, 175, 1680, 485, 'Chương trình BPF (kernel 6.8, CO-RE, BTF)', 'kernel')
    enter = p.box(40, 200, 300, 190, 'raw_tp/sys_enter → pulse_record_call',
                  '1. cgroup_id → tra pulse_cgroups (miss: thoát ngay)<br>2. full_counts[nr]++ (giữ lại, không dùng để báo)<br>'
                  '3. bin cặp syscall++ (giữ lại, không dùng để báo)<br>4. tra hoặc tạo trạng thái thread (pulse_last_syscall, '
                  'khoá pid_tgid)<br>5. syscall không trong bảng hook: phát token tên ngay<br>'
                  '&nbsp;&nbsp;&nbsp;&nbsp;syscall có hook: tok_pending = 1', kind='kernel', align='left', small=10)
    skip = p.box(370, 200, 280, 190, 'fexit/__seccomp_filter', 'syscall bị seccomp bỏ qua (result −1, không phải '
                 'recheck) không tới sys_enter: đếm như sys_enter (seccomp_skipped_or_emulated++), token tên lúc vào, '
                 'tok_pending = 0 nên sys_exit không phát lần hai', kind='kernel', align='left', small=10)
    exitp = p.box(700, 200, 650, 190, 'raw_tp/sys_exit → pulse_tok_sys_exit',
                  'chỉ khi tok_pending (cùng thread, cùng cgroup); nr = syscall_id đã ghi ở sys_enter. Token theo bảng '
                  '39 syscall (pulse_token_ids.h):<br>'
                  '• lỗi, syscall thuộc nhóm ERR (26 + futex): tên + errno<br>'
                  '• đọc/ghi thành công, ret &gt; 0: tên + min(15, ⌊log2 ret⌋)<br>'
                  '• open, openat, openat2, creat thành công: tên + chế độ (w nếu O_WRONLY | O_RDWR | O_CREAT | O_TRUNC | '
                  'O_APPEND) + thư mục đầu<br>• còn lại: tên<br>'
                  '<b>Thư mục đầu:</b> fd trả về → struct file → đi ngược d_parent, vượt mount (bpf_loop ≤ 64 bước) tới '
                  'gốc của task (gốc container) → FNV-1a của thành phần đầu, giữ 20 bit', kind='kernel', align='left',
                  small=10)
    cfg = p.box(1380, 200, 300, 150, '.rodata.tokcfg', 'loader đặt trước khi nạp; verifier cắt nhánh tắt:<br>'
                '• futex_at_exit · • count_grams<br>B = exit-nofutex, C = exit, D = grams (lượt live dùng D)<br>'
                'Biến thể 39 trampoline fexit đã bỏ (va chạm kprobe Tetragon)', kind='kernel', align='left',
                small=10)
    fork = p.box(1380, 365, 300, 140, 'raw_tp/sched_process_fork', 'chạy trong process cha: con nhận thẻ dòng dõi của cha '
                 '(native = cây process của workload, session = vào qua runtime exec) và lịch sử token rỗng, trước khi chạy; '
                 'thẻ là telemetry, không dùng để báo', kind='kernel', align='left', small=10)
    emit = p.box(40, 420, 1310, 85, 'pulse_tok_emit (gọi từ cả ba hook)',
                 'gram = (tok[0], tok[1], tok[2], token mới); khoá = (cgroup, cửa sổ = ktime / 0,5 s, gram); có trong map '
                 'thì cộng nguyên tử, chưa có thì chèn BPF_NOEXIST (thua tranh chấp: tra lại); rồi dịch lịch sử của thread',
                 kind='kernel', small=10)
    p.edge(sysc, enter, '', kind='kernel', exit=(0.5, 1), entry=(0.467, 0))
    p.edge(sk, skip, 'bỏ qua', kind='kernel', exit=(0.5, 1), entry=(0.5, 0))
    p.edge(ret, exitp, '', kind='kernel', exit=(0.5, 1), entry=(0.769, 0))
    p.edge(enter, emit, 'token lúc vào', kind='kernel', exit=(0.5, 1), entry=(0.111, 0))
    p.edge(skip, emit, 'token lúc vào', kind='kernel', exit=(0.5, 1), entry=(0.37, 0))
    p.edge(exitp, emit, 'token lúc ra', kind='kernel', exit=(0.5, 1), entry=(0.787, 0))
    p.edge(cfg, emit, '', kind='ctrl', exit=(0, 0.9), entry=(1, 0.2), points=[(1365, 335), (1365, 437)])
    p.edge(fork, emit, '', kind='kernel', exit=(0, 0.75), entry=(1, 0.6))
    m1 = p.store(40, 540, 300, 100, 'pulse_cgroups', 'PERCPU_HASH, 1024 cgroup: allow-list; full_counts, 64 bin cặp, '
                 'seccomp_skipped (giữ lại, không dùng để báo)')
    m2 = p.store(370, 540, 330, 100, 'pulse_last_syscall', 'LRU_HASH 131.072 thread: cgroup, seen_ns, syscall_id, '
                 'tok[3], tok_pending, thẻ dòng dõi')
    m3 = p.store(730, 540, 330, 100, 'pulse_grams', 'HASH 262.144 entry; khoá 32 byte (cgroup, cửa sổ, 4 token, dòng dõi); '
                 'giá trị: số lần')
    p.store(1090, 540, 260, 100, 'pulse_stats, pulse_tok_stats', 'lỗi chèn trạng thái/gram (insert_fail tăng → cảnh báo map đầy, D1), walk quá sâu, tổng gram')
    p.edge(emit, m2, 'lịch sử', kind='store', exit=(0.4, 1), entry=(0.5, 0))
    p.edge(emit, m3, 'đếm gram', kind='store', exit=(0.682, 1), entry=(0.5, 0))
    p.text(1380, 540, 300, 110, 'pulse_cgroups do loader nạp từ allow-list của resolver; process ngoài allow-list thoát '
           'ở bước 1, nên chỉ trả chi phí một lần tra map.', size=10, extra='fontColor=#555555;')
    # token layout
    p.group(20, 680, 820, 150, 'Bố cục token 32 bit (pulse_token_ids.h)', kind='kernel', size=12)
    for start, width, t in [(0, 9, 'nr syscall (bit 23–31)'), (9, 3, 'loại (21–22)'), (12, 20, 'chi tiết (bit 0–20)')]:
        p.box(40 + start * 24, 712, width * 24, 40, t, kind='kernel', small=9)
    p.text(40, 760, 790, 70, 'loại 0: chỉ tên · 1: errno (bit 0–11) · 2: bucket kích thước 0–15 · 3: open (bit 20 = ghi, '
           'bit 0–19 = FNV thư mục; mã riêng cho "/", "rel", không rõ)<br>0xFFFFFFFF = ô lịch sử trống (đầu thread → gram '
           'ngắn hơn, như TokenLM offline)', size=11)
    # loader
    p.group(860, 680, 840, 310, 'Loader (pulse_counter_loader.c, -DPULSE_TOKENS) và đầu ra', kind='user', size=12)
    l1 = p.box(880, 712, 380, 116, 'Khởi động', 'kiểm layout map; đặt .rodata.tokcfg; nạp object; gắn sys_enter, '
               'fexit seccomp, sys_exit, sched_process_fork; nạp allow-list từ resolver; lỗi thì dừng (fail closed)', kind='user',
               align='left', small=10)
    l2 = p.box(1300, 712, 380, 116, 'Mỗi 0,5 s (MONOTONIC + 20 ms)', 'cộng bộ đếm per-CPU mọi cgroup → '
               'cgroup_snapshot_extended; đọc pulse_grams theo lô, lấy cửa sổ đã đóng, xoá theo lô → token_grams; window_end = '
               '(W + 1) × 0,5 s + lệch đồng hồ (D2)',
               kind='user', align='left', small=10)
    p.box(880, 840, 800, 140, 'Dòng JSON ra stdout (một frame)',
          '{"type":"cgroup_snapshot_extended","cgroup_id":…,"total":…,"counts":{29 syscall},"syscall_bins":[64],'
          '"transition_bins":[64],"full_counts":{…},"seccomp_skipped_or_emulated":…}<br>'
          '{"type":"token_grams","contract":"pulse-token-select1f-v1","cgroup_id":…,"window":W,"window_end":t,'
          '"events":n,"grams":[[t0,t1,t2,t3,count],…],"session_events":m,"session":[…]}<br>'
          '{"type":"token_drain",…,"insert_fail_cumulative":0} · {"type":"stat",…} · '
          '{"type":"snapshot_end","targets":…,"snapshots":…}<br><b>Proof</b> (scripts/token_probe_proof.py): tổng sự '
          'kiện token = tổng full_counts trong cgroup cô lập (bản final: 361.900 / 442.796 / 393.644 trên 3 worker), token mẫu '
          'đúng, seccomp như proof matched.',
          kind='store', align='left', small=10)
    p.edge(l1, l2, '', kind='data')
    edge_legend(p, 20, 845, [EDGE_VI[0], EDGE_VI[1], EDGE_VI[3], EDGE_VI[4]], columns=2, width=820)
    return p


# ---------------------------------------------------------------- page 3: worker and the token model
def worker():
    p = Page('3. Worker và mô hình token', 1720, 1210)
    p.title('Worker chấm điểm và mô hình token lidds-ml-v5-t3 trên cụm',
            'pipeline/matched_worker.py, một unit systemd mỗi worker (3 core, 3 GB). Một mô hình ngôn ngữ mỗi workload; '
            'một cửa sổ vượt ngưỡng của workload là báo động.')
    fr = p.box(20, 90, 300, 120, 'Dòng token_grams từ loader', 'mỗi 0,5 s, mỗi (cgroup, cửa sổ đã đóng): số sự kiện, '
               'danh sách (4 token, số lần)', kind='user', small=10)
    chk = p.box(360, 90, 380, 120, 'token_window (collector/token_capture.py)', 'kiểm contract, tổng số lần = số sự kiện, '
                'ô trống chỉ ở đầu gram; bỏ cgroup ngoài production; dòng sai → issues', kind='user', small=10)
    meta = p.box(780, 90, 300, 120, 'Metadata resolver', '/run/sentinel-pulse/cgroups.json: workload_key = '
                 'namespace/workload:container, pod_uid, revision', kind='user', small=10)
    p.edge(fr, chk, '', kind='data')
    p.edge(meta, chk, '', kind='ctrl', exit=(0, 0.5), entry=(1, 0.5))
    p.group(20, 240, 1680, 420, 'Mô hình token (detector/token_model.py)', kind='ml', size=12)
    lm = p.box(40, 280, 520, 220, 'CountTokenLM của workload', 'đếm từ normal: c(h, w), c(h), T(h) cho ngữ cảnh 0–3 token<br>'
               'mức nền: P(tên) × P(token | tên), cộng ½ (token lạ của tên quen vẫn có xác suất)<br>'
               'Witten-Bell nội suy: P_k = (c(h_k, w) + T(h_k) P_{k−1}) / (c(h_k) + T(h_k)), k = 1, 2, 3<br>'
               '= TokenLM offline trên dataset tới sai số 1e-12 (có test)', kind='ml', align='left', small=11)
    sc = p.box(600, 280, 520, 220, 'Điểm cửa sổ', 'mỗi sự kiện: độ bất ngờ −ln P_3<br>s(W) = trung bình top giá trị lớn nhất '
               '(gram tính theo số lần); top = 3 (lidds-ml-v5-t3, MODELS.json), v5: 10; ít sự kiện hơn: trung bình tất cả; '
               'cửa sổ rỗng: 0<br>ví dụ lượt cuối: tấn công child_ptrace_handshake trong catalog-service, s(W) = 40,50 '
               '&gt; τ = 19,30', kind='ml', align='left', small=11)
    tb = p.box(1160, 280, 520, 220, 'TokenBranch (cfg tokens.models)', 'mỗi workload: đường dẫn mô hình, SHA-256, ngưỡng τ; '
               'hash lệch → không nạp<br>s(W) &gt; τ → báo (candidate_alert_preview), một cửa sổ là đủ<br>ghi decision '
               'branch=token: token_score, token_threshold, session_events<br>map gram đầy → token_alert_reason = gram_map_overflow '
               'trên cửa sổ nặng nhất, cả frame token_incomplete (D1)<br>chấm p50 0,17 s, p95 0,23 s sau khi cửa sổ đóng '
               '(12,1 triệu cửa sổ, lượt v6)', kind='ml', align='left', small=11)
    p.box(40, 530, 1080, 110, 'Bảng chữ select1f', 'errno của 27 syscall (stat, lstat, fstat, newfstatat, access, faccessat, '
          'open, openat, creat, read, write, writev, ioctl, connect, execve, fcntl, close, rename, renameat, sendfile, unlink, '
          'unlinkat, mkdir, kill, recvfrom, shutdown, futex) · mở thành công: chế độ r|w + thư mục đầu · đọc/ghi thành công: '
          'min(15, ⌊log2 n⌋) · còn lại: tên. LID-DS 2021 official (t3): recall 97,25%, báo nhầm 0,19%, p95 1,54 s',
          kind='note', align='left', small=11)
    p.edge(chk, lm, 'cửa sổ token', kind='data', exit=(0.5, 1), entry=(0.5, 0), points=[(550, 250), (300, 250)])
    p.edge(lm, sc, '', kind='data')
    p.edge(sc, tb, '', kind='data')
    dec = p.box(20, 690, 1680, 80, 'Decision = mô hình token của workload báo (một cửa sổ là đủ)',
                'mỗi decision mang workload_key, pod_uid, container, window_start/end, token_score, token_threshold, run_id, '
                'capture_segment, session_events (nhãn stream của cảnh báo); độ trễ kernel → cảnh báo = cuối cửa sổ + thời gian chấm',
                kind='alert')
    p.edge(tb, dec, '', kind='alert', exit=(0.5, 1), entry=(0.83, 0))
    s1 = p.store(20, 800, 400, 110, 'NFS: segment 30 phút', 'decisions.jsonl · tokens.jsonl · issues.jsonl · loader.log · '
                 'TERMINAL.json (seal)')
    s2 = p.store(450, 800, 300, 110, 'Đĩa local của worker', 'decisions.jsonl cho bridge, campaign')
    p.box(780, 800, 450, 110, 'Ghi ngoài vòng chấm (async_sink)', 'thread nền, fdatasync + FADV_DONTNEED mỗi 30 s; '
          'STATUS.json bất đồng bộ; dừng khi hết chỗ trống', kind='user', small=10)
    p.box(1260, 800, 440, 110, 'Khoá trước khi chấm', 'kernel = proof; SHA-256 của loader và object; SHA-256 từng mô hình token '
          'và ngưỡng trong CONFIG.json', kind='user', small=10)
    p.edge(dec, s1, '', kind='store', exit=(0.12, 1), entry=(0.5, 0))
    p.edge(dec, s2, '', kind='store', exit=(0.35, 1), entry=(0.5, 0))
    p.text(20, 940, 1680, 120, '<b>Học mô hình (token_branch_fit.py, trước mỗi lượt; lượt cuối: pulse-live-v7-fit-1118):</b> normal của lượt thu '
           'pulse-token-capture-v6-1116 (+ normal của lượt live v5, bỏ −5 s … +25 s quanh mỗi trial) → tách theo workload → đoạn '
           '30 phút chia vào 5 fold → chấm phần giữ ra (top 3) → điểm lớn nhất mỗi khối 60 s mỗi container → bỏ 0,5% cao nhất → '
           'Gumbel theo moment → τ ở α′ = 0,0003 → mô hình cuối học trên toàn bộ → MODELS.json (SHA-256, có top). Không đổi '
           'trong lượt chạy. Cụm đổi thì thu normal và fit lại (D9).', size=12)
    edge_legend(p, 20, 1075, [EDGE_VI[1], EDGE_VI[2], EDGE_VI[3], EDGE_VI[4]], columns=2, width=1100)
    return p


# ---------------------------------------------------------------- page 4: alert path (RCA left out for now, owner 19/11)
def alerting():
    p = Page('4. Đường cảnh báo', 1720, 520)
    p.title('Đường cảnh báo: từ decision của worker tới người vận hành',
            'Bridge chạy trên .234 và chỉ đọc decision.')
    w = p.box(20, 90, 250, 120, 'Worker ×3', 'decisions.jsonl local; chỉ dòng token có "candidate_alert_preview":true '
              'rời worker', kind='ml', small=9)
    br = p.box(310, 70, 520, 230, 'Alert bridge (ops/alert_bridge.py)', '• bám log decision của từng worker qua SSH<br>'
               '• gom đợt theo (pod_uid, container); hết đợt khi im lặng quá resolve_after<br>'
               '• push POST /api/v2/alerts lúc mở đợt, làm mới khi còn kéo dài; lỗi → hàng đợi bền push-queue.jsonl, '
               'backoff tới 30 s, giữ tới 1 giờ, tiếp tục sau khi khởi động lại (D3)<br>'
               '• nhãn stream: session nếu ≥ 50% sự kiện của cửa sổ chạy trên thread session, ngược lại native<br>'
               '• đo độ trễ từ preview_emitted_at và window_end (webhook của Alertmanager → deliveries.jsonl)<br>'
               '• đường pull (gauge /metrics, scrape 5 s / 30 s) chỉ để so độ trễ: chậm hơn nhiều', kind='alert',
               align='left', small=10)
    am = p.box(880, 90, 330, 120, 'Alertmanager (API v2)', 'alert SentinelPulseAnomaly với nhãn node, workload, pod_uid, '
               'container, episode, stream', kind='alert', small=10)
    ppl = p.box(1260, 90, 300, 120, 'Người vận hành', 'nhận thông báo hoặc xem dashboard', kind='alert')
    graf = p.box(880, 250, 330, 90, 'Prometheus / Grafana', 'scrape gauge /metrics của bridge; dashboard '
                 'sentinel-pulse-alerts', kind='ext', small=10)
    p.edge(w, br, 'SSH tail', kind='alert', exit=(1, 0.4), entry=(0, 0.25))
    p.edge(br, am, 'push', kind='alert', exit=(1, 0.25), entry=(0, 0.5))
    p.edge(am, ppl, '', kind='alert')
    p.edge(br, graf, 'pull (so sánh)', kind='data', exit=(1, 0.8), entry=(0, 0.5))
    p.text(20, 330, 840, 60, 'Lượt v6: bridge giao 3.233/3.233 đợt, decision → Alertmanager p95 1,21 s; kernel → Alertmanager '
           '(push) p95 1,53 s. Lượt cuối, ví dụ trial tấn công 5: Alertmanager nhận 0,14 s sau cuối cửa sổ báo.', size=11)
    edge_legend(p, 20, 400, [EDGE_VI[1], EDGE_VI[2]], columns=2, width=820)
    return p


# ---------------------------------------------------------------- page 5: learning and evaluation
def evaluation():
    p = Page('5. Học và đánh giá', 1720, 1100)
    p.title('Quy trình chọn, xác nhận và đánh giá',
            'Chọn trên dữ liệu development, xác nhận trên dữ liệu khoá; mỗi bước có protocol đăng ký trước (sửa đổi là amendment '
            'có giờ và lý do) và biên nhận JSON trong repo.')
    steps = [
        ('LID-DS 2021 development + CB-DS', 'chọn bảng chữ token, độ dài gram, top-k, ngưỡng; lidds-ml-v5: development '
         '530/544, 6 báo nhầm; CB-DS 891/891, 3/1.410', 'eval'),
        ('LID-DS 2021 official', 'lidds-ml-v5: 1.238/1.271, 26/7.938 báo nhầm, p95 1,47 s; lidds-ml-v5-t3: 1.236/1.271 '
         '(97,25%), 15/7.938 (0,19%), p95 1,54 s', 'ml'),
        ('LID-DS 2019', 'v5 theo protocol 723/1.162; dung sai nhãn 1 s (amendment, sau lượt chấm) 1.056/1.162; chia '
         '30/70: chọn t3 trên development, holdout 817/841 (97,15%), p95 10,95 s', 'eval'),
        ('Thu normal + fit trên cụm', 'pulse-token-capture-v6-1116 (chỉ normal, tải theo lịch) + normal lượt v5 → '
         'pulse-live-v7-fit-1118 (t3, 21 mô hình)', 'eval'),
        ('Lượt live v4–v6', 'v6: tập chính 315/315, precision 99,68%, control 1/315, p95 0,45 s; PAD 300: 105/105; lotl '
         '524/525; vòng cải thiện D1–D18 sau đó', 'eval'),
        ('Lượt live cuối (45 h)', 'pulse-live-final-1119: diễn tập trước; 945 trial gồm tốc độ chậm 0,1–0,5/s, PAD 300, '
         'bật-tắt, lotl, event-generator; 6 h normal cuối đo gánh', 'eval'),
    ]
    ids = []
    for k, (t, s, kind) in enumerate(steps):
        ids.append(p.box(20 + 280 * k, 100, 255, 150, t, s, kind=kind, small=10))
        if k:
            p.edge(ids[k - 1], ids[k], '', kind='eval' if kind != 'ml' else 'data')
    p.group(20, 290, 830, 420, 'Offline (máy phân tích .234, systemd-run có giới hạn bộ nhớ)', kind='eval', size=12)
    p.box(40, 330, 380, 170, 'Chuyển đổi và chấm', 'sentinel_pulse/lidds: convert.py<br>'
          'lidds_ml_token_alphabets.py (token), lidds_ml_token_crossfit.py (cross-fit)<br>'
          'lidds_ml_v5.py (chọn trên development + CB-DS, chấm official một ứng viên)<br>lidds2019_dev.py (2019: split, '
          'development, holdout)', kind='user',
          align='left', small=10)
    p.box(440, 330, 390, 170, 'Ngưỡng', 'Gumbel theo moment trên điểm lớn nhất giữ ra của cross-fit 5 fold, bỏ 1% cao nhất; '
          'v5: α′ = 0,00018, bỏ 1%; t3: α′ = 0,0003, bỏ 0,5%, top 3; moment được chọn trên development sau khi so với Gumbel '
          'MLE, GEV, chuẩn, đuôi mũ<br>'
          'trên cụm: khối 60 s mỗi container thay cho bản ghi, fold theo đoạn 30 phút', kind='ml', align='left', small=10)
    p.box(40, 520, 380, 170, 'Kiểm thêm (development)', 'chỉ tên syscall 487/544, bỏ cỡ đọc ghi 490/544<br>'
          'LSTM lớn không hơn 4-gram<br>thứ tự phát token như probe (probe1f): 530/544<br>luật đếm 4-gram chưa thấy có ngưỡng: ngang mô hình',
          kind='eval', align='left', small=10)
    p.box(440, 520, 390, 170, 'Overhead probe token (token-probe-overhead-v1)', 'benchmark syscall tĩnh, 5 vòng, 3 '
          'worker, xoay điều kiện: off / A / B / C / D / D không giám sát<br>lần 1 fexit → va chạm kprobe Tetragon; '
          'lần 2 sys_exit; lần 3 đi ngược dentry; báo cáo, không đạt/trượt', kind='eval', align='left', small=10)
    p.group(870, 290, 830, 420, 'Trên cụm (lượt live)', kind='eval', size=12)
    p.box(890, 330, 380, 170, 'Planner', 'plan_matched_run.py --token-build --token-models --admin-control --on-off --eventgen [--rehearsal] → '
          'CONFIG.json bất biến; launch_run.sh cài worker, bridge, traffic, campaign, bộ ghi sự kiện K8s (system unit)', kind='eval', align='left', small=10)
    p.box(1290, 330, 390, 170, 'Fit trước lượt live', 'token_branch_fit.py → MODELS.json (mô hình token + ngưỡng mỗi workload)<br>'
          '--extra-run: thêm normal của lượt trước, bỏ −5 s … +25 s quanh mỗi trial<br>khoá sha256 trước lượt live', kind='ml', align='left', small=10)
    p.box(890, 520, 380, 170, 'Chấm lượt live', 'trial phát hiện khi có báo động trong [start, start + 15 s]; đợt = '
          'báo động cùng container cách nhau < 15 s; gánh = đợt / replica-giờ ngoài khoảng campaign; Wilson, bootstrap '
          'theo workload; pulse_live_v4.py, native_stream.py, live_attribution.py', kind='eval', align='left', small=10)
    p.box(1290, 520, 390, 170, 'Gate cho binary vô hại (đã loại)', 'mô hình gộp mọi workload, giữ 1–2 s sau execve, '
          'ngưỡng theo pha: không giữ được kết quả LID-DS (development 315–509/544) → hệ thống không có gate',
          kind='retired', align='left', small=10)
    p.group(20, 740, 1680, 230, 'Bằng chứng và tài liệu', kind='store', size=12)
    docs = [('Protocol', 'sentinel_pulse/protocol/*.json, đăng ký trước khi có dữ liệu; amendment ghi rõ lý do'),
            ('Biên nhận', 'validation-evidence/results-YYYYMMDD/*: JSON, bảng, log; seal SHA-256 của segment'),
            ('Audit số liệu', 'scripts/audit/headline_numbers.py: mọi số trong bản LaTeX khớp biên nhận'),
            ('Đồ án', 'thesis/ (LaTeX, tectonic); báo cáo và slide họp trong docs/'),
            ('Ghi chép', 'notes/STATE.md (trạng thái), notes/WORKLOG.md (nhật ký từng bước), docs/LUONG_CODE.md (luồng code, lệnh)')]
    for k, (t, s) in enumerate(docs):
        p.box(40 + 330 * k, 775, 310, 100, t, s, kind='store', small=10)
    p.text(40, 890, 1640, 60, 'Nguyên tắc: chọn trên development, official và lượt live chỉ để xác nhận; mỗi lần chấm '
           'lại official phải khai báo; holdout LID-DS 2019 đã được v5 chấm trước khi chia (công bố trong mọi tài liệu); '
           'không job nặng nào chạy cùng lượt live; số liệu chỉ lấy từ biên nhận.', size=12)
    edge_legend(p, 20, 990, [('data', 'Bước tiếp theo, chấm trên dữ liệu khoá'), ('eval', 'Bước tiếp theo, development hoặc cụm')],
                columns=2, width=1100, title='Kiểu mũi tên')
    return p


# ---------------------------------------------------------------- English overview for the paper (Figure 1)
def paper_overview():
    p = Page('Overview (paper)', 1500, 620)
    p.group(20, 30, 1460, 330, 'Each worker node (×3)', kind='user', size=15)
    app = p.box(40, 70, 200, 170, 'Application containers', 'namespace production; one cgroup each; unmodified',
                kind='ext', small=13)
    probe = p.box(275, 70, 330, 170, 'eBPF probe (kernel)', 'sys_enter, sys_exit, __seccomp_filter, sched_process_fork<br>'
                  '32-bit token per call; per-thread 4-grams counted per (cgroup, 0.5 s window); lineage tag',
                  kind='kernel', small=13)
    loader = p.box(640, 70, 220, 170, 'Loader', 'every 0.5 s drains the closed windows; SHA-256 and kernel proof checked '
                   'at start', kind='user', small=13)
    worker = p.box(895, 70, 330, 170, 'Scoring worker', 'per-workload 4-gram count LM (Witten-Bell); s(W) = mean of the top '
                   'surprisals; alarm if s(W) > τ of the workload; one window fires', kind='ml', small=13)
    dec = p.store(1260, 70, 200, 170, 'Decisions', 'local disk; segments on NFS')
    res = p.box(40, 260, 200, 95, 'Resolver', 'pod UID → cgroup → workload', kind='user', small=13)
    p.group(830, 395, 650, 150, 'Master node', kind='alert', size=15)
    fit = p.box(40, 425, 200, 105, 'Offline fit', 'normal capture → counts → 5-fold cross-fit → Gumbel τ', kind='ml',
                small=13)
    am = p.box(850, 425, 200, 105, 'Alertmanager', 'of the cluster; to the operators', kind='alert', small=13)
    bridge = p.box(1085, 425, 375, 105, 'Alert bridge', 'follows alarm rows over SSH; one episode per container (gaps < 15 s); '
                   'push to Alertmanager', kind='alert', small=13)
    p.edge(app, probe, 'syscalls', kind='kernel')
    p.edge(probe, loader, 'map', kind='kernel')
    p.edge(loader, worker, 'windows', kind='data')
    p.edge(worker, dec, '', kind='data')
    p.edge(res, loader, 'allow-list, identity', kind='ctrl', exit=(1, 0.5), entry=(0.5, 1), points=[(750, 305)])
    p.edge(dec, bridge, 'alarms', kind='alert', exit=(0.5, 1), entry=(1, 0.5), points=[(1360, 380), (1475, 380), (1475, 477)])
    p.edge(bridge, am, '', kind='alert')
    p.edge(fit, worker, 'MODELS.json (SHA-256)', kind='ctrl', exit=(0.5, 0), entry=(0.3, 1), points=[(140, 375), (994, 375)])
    edge_legend(p, 20, 555, EDGE_EN, columns=4, width=1460, title='Arrows')
    return p


def write(path, pages):
    xml = ('<mxfile host="drawio" agent="make_architecture_drawio.py" version="32.6.10">'
           + ''.join(pg.xml(k + 1) for k, pg in enumerate(pages)) + '</mxfile>\n')
    path.write_text(xml, encoding='utf-8')
    print(path, len(pages), 'pages')


def main():
    write(OUT, [overview(), kernel(), worker(), alerting(), evaluation()])
    write(OUT.with_name('sentinel-pulse-overview-en.drawio'), [paper_overview()])


if __name__ == '__main__':
    main()
