#!/usr/bin/env python3
"""Build docs/architecture/sentinel-pulse-architecture.drawio (5 pages) from the facts in the repository.

Sources: thesis/chapters/design.tex and implementation.tex (system, RCA, alert path, cluster), README.md (nodes),
sentinel_pulse/ebpf/* (probe, token layout), sentinel_pulse/pipeline/matched_worker.py (worker),
sentinel_pulse/protocol/lidds-ml-v5.json (+ amendments 1, 2) and pulse-live-v3-v1.json (the ML and its live runs), notes/STATE.md.
State of 11/11/2026: the system is lidds-ml-v5, the token model alone (no tree, support, tripwire, replica discount).

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


def label(title, sub=None, small=10):
    t = f'<b>{title}</b>'
    if sub:
        t += f'<br><font style="font-size:{small}px">{sub}</font>'
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
        return self._vertex(x, y, w, h, label(title, sub, small), style, parent)

    def store(self, x, y, w, h, title, sub=None, parent='1'):
        fill, stroke = C['store']
        style = (f'shape=cylinder3;whiteSpace=wrap;html=1;boundedLbl=1;backgroundOutline=1;size=10;fillColor={fill};'
                 f'strokeColor={stroke};fontSize=12;')
        return self._vertex(x, y, w, h, label(title, sub), style, parent)

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
            ('ml', 'Mô hình token lidds-ml-v5'), ('alert', 'Đường cảnh báo và RCA'),
            ('ext', 'Thành phần có sẵn của cụm (Tetragon, K8s)'), ('eval', 'Chỉ dùng khi đánh giá (đứt nét)'),
            ('retired', 'Giữ lại, không dùng để báo (xám)')]
    for k, (kind, t) in enumerate(rows):
        p.box(x + 12, y + 32 + 28 * k, 26, 18, '', kind=kind)
        p.text(x + 46, y + 30 + 28 * k, 280, 22, t, size=11)


# ---------------------------------------------------------------- page 1: overview
def overview():
    p = Page('1. Tổng quan hệ thống', 1720, 1150)
    p.title('Sentinel Pulse: kiến trúc tổng thể (11/11/2026)',
            'Phát hiện runtime trên Kubernetes bằng mô hình ngôn ngữ trên token syscall do eBPF dựng trong kernel (lidds-ml-v5), '
            'cảnh báo qua Alertmanager, RCA từ sự kiện Tetragon. Khung tím đứt nét chỉ dùng khi đánh giá.')
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
                  'fexit/__seccomp_filter: syscall bị seccomp bỏ qua<br>map: trạng thái thread, 4-gram theo (cgroup, cửa sổ)',
                  kind='kernel', small=9)
    allow = p.box(400, 305, 200, 120, 'Allow-list cgroup', 'map pulse_cgroups: chỉ cgroup production được theo dõi; cgroup '
                  'khác thoát sau một lần tra map', kind='kernel', small=9)
    tetra_k = p.box(630, 305, 180, 120, 'Tetragon (kprobe)', 'exec, fork, file nhạy cảm, credential, namespace, kết nối, '
                    'ptrace; 3 policy, chỉ production', kind='ext', small=9)
    p.band(55, 455, 770, 340, 'User space của worker (unit systemd)', 'user')
    loader = p.box(70, 480, 300, 100, 'Loader C (pulse_counter_tokens_loader)', 'khoá SHA-256 + proof theo kernel; mỗi '
                   '0,5 s: dòng token_grams cho mỗi (cgroup, cửa sổ đã đóng)', kind='user', small=9)
    resolver = p.box(400, 480, 200, 100, 'sentinel-pulse-resolver', 'pod UID → container → cgroup → phiên bản workload',
                     kind='user', small=9)
    tetra_u = p.box(630, 480, 180, 100, 'Agent Tetragon', 'DaemonSet, shareProcessNamespace; tetra getevents',
                    kind='ext', small=9)
    worker = p.box(70, 605, 530, 175, 'Worker chấm điểm (pipeline/matched_worker.py, 3 core, 3 GB)',
                   '• kiểm hợp đồng của cửa sổ token; gắn workload, Pod, container<br>'
                   '• mô hình ngôn ngữ 4-gram Witten-Bell của workload (khoá SHA-256)<br>'
                   '• điểm = trung bình 10 giá trị −ln p lớn nhất<br>'
                   '• ngưỡng Gumbel trên điểm giữ ra (khối 60 s, cross-fit 5 fold); một cửa sổ vượt ngưỡng là báo<br>'
                   '• ghi NFS bằng thread nền (AsyncSink), ngoài vòng chấm', kind='ml', align='left', small=10)
    local = p.store(630, 615, 180, 160, 'Luồng decision local', '/var/lib/sentinel-pulse-live (đĩa của worker)')
    p.group(875, 110, 360, 700, 'Master (×3): .234 k8s-master · .235 · .236', kind='alert', size=12)
    p.icon(1190, 116, 40, 39, 'master')
    bridge = p.box(890, 150, 330, 105, 'Alert bridge (trên .234)', 'đọc decision local của 3 worker qua SSH; gom đợt '
                   'theo container; push API v2, thử lại 3 lần; phục vụ trang case', kind='alert', small=9)
    am = p.box(890, 285, 330, 70, 'Alertmanager', 'kube-prometheus-stack; route theo nhãn notify', kind='alert', small=9)
    rca = p.box(890, 385, 330, 125, 'RCA (trên .234)', 'sự kiện Tetragon → ring SQLite 180 s; case cho mỗi cảnh báo '
                'Alertmanager đã nhận (30 s trước); xếp hạng nghi phạm; triage: thao tác bảo mật / chỉ probe / '
                'binary mới / khác', kind='alert', small=9)
    viewer = p.box(890, 540, 160, 75, 'RCA viewer', '/cases, bảng Grafana Infinity', kind='alert', small=9)
    graf = p.box(1060, 540, 160, 75, 'Prometheus / Grafana', 'NodePort 32090 / 32300', kind='ext', small=9)
    planner = p.box(890, 645, 160, 150, 'Planner + launcher', 'CONFIG.json bất biến: hash mô hình, probe, fixture, '
                    'lịch tải, lịch trial', kind='eval', small=9)
    p.box(1060, 645, 160, 150, 'Job phân tích (.234)', 'systemd-run có MemoryMax; học mô hình (token_branch_fit.py), chấm LID-DS; '
          'đọc NFS, repo, dữ liệu công khai; không chạy cùng lượt live', kind='eval', small=9)
    p.box(40, 845, 400, 110, 'Tải normal (đánh giá)', '4 generator trong namespace production gửi HTTP tới AIMS; chế độ '
          'steady, toolmix, peak, burst, recovery theo lịch đăng ký', kind='eval')
    campaign = p.box(460, 845, 380, 110, 'Chiến dịch tấn công (đánh giá)', 'kubectl exec fixture vào container: 21 '
                     'workload × 5 kịch bản × tốc độ 1–24/s, 525 trial; mỗi trial: control 15 s → binary vô hại 15 s → '
                     'tấn công 15 s; từ lượt v5 thêm một lệnh admin thật', kind='eval')
    nfs = p.store(1280, 110, 410, 160, 'NFS .233: /sentinel-pulse', '/mnt/sentinel-pulse-archive; segment 30 phút mỗi '
                  'worker: decisions, tokens, issues, TERMINAL.json (seal SHA-256); CONFIG.json, mô hình token')
    people = p.box(1280, 290, 410, 80, 'Người vận hành', 'nhận cảnh báo (notify=immediate) hoặc xem dashboard; mở case '
                   'RCA: nghi phạm, lý do, cây bằng chứng', kind='alert', small=10)
    p.box(1280, 400, 410, 130, 'Repo git (GitHub, main)', 'code Pulse · protocol đăng ký trước · biên nhận JSON '
          '(validation-evidence/) · audit số liệu · đồ án LaTeX (thesis/) · notes/<br>checkout trên .234/.237/.238/.239 '
          'đồng bộ bằng git pull --ff-only', kind='store', small=10)
    p.box(1280, 560, 410, 110, 'Dữ liệu công khai (offline)', 'LID-DS 2021 (15 kịch bản, development → official), '
          'CB-DS, LID-DS 2019 (cuối cùng)', kind='eval', small=10)
    legend(p, 1280, 700)
    p.edge(pods[0], probe, 'syscall', kind='kernel', exit=(0.5, 1), entry=(0.137, 0))
    p.edge(probe, loader, 'đọc map theo lô', kind='kernel', exit=(0.5, 1), entry=(0.5, 0))
    p.edge(resolver, allow, 'allowed-cgroups', kind='ctrl', exit=(0.5, 0), entry=(0.5, 1))
    p.edge(tetra_k, tetra_u, 'sự kiện', kind='data', exit=(0.5, 1), entry=(0.5, 0))
    p.edge(loader, worker, 'cửa sổ token', kind='data', exit=(0.5, 1), entry=(0.283, 0))
    p.edge(resolver, worker, 'cgroups.json', kind='ctrl', exit=(0.5, 1), entry=(0.811, 0))
    p.edge(worker, local, 'decision', kind='data', exit=(1, 0.5), entry=(0, 0.47))
    p.edge(local, bridge, 'SSH, chỉ dòng báo', kind='alert', exit=(1, 0.25), entry=(0, 0.5), points=[(850, 655), (850, 202)])
    p.edge(tetra_u, rca, 'tetra getevents', kind='data', exit=(1, 0.5), entry=(0, 0.5), points=[(865, 530), (865, 447)])
    p.edge(bridge, am, 'POST /api/v2/alerts', kind='alert', exit=(0.5, 1), entry=(0.5, 0))
    p.edge(am, rca, 'cảnh báo đã nhận → case', kind='alert', exit=(0.5, 1), entry=(0.5, 0))
    p.edge(am, people, '', kind='alert', exit=(1, 0.5), entry=(0, 0.375))
    p.edge(rca, viewer, '', kind='alert', exit=(0.242, 1), entry=(0.5, 0))
    p.edge(viewer, graf, '', kind='alert', exit=(1, 0.5), entry=(0, 0.5))
    p.edge(worker, nfs, 'decisions / tokens (NFS)', kind='store', exit=(0.5, 1), entry=(0, 0.47),
           points=[(335, 822), (1266, 822), (1266, 185)])
    p.edge(planner, campaign, 'lịch trial', kind='eval', exit=(0.5, 1), entry=(1, 0.5), points=[(970, 900)])
    p.text(20, 1035, 1235, 100,
           '<b>Đường dữ liệu chính:</b> syscall của container → probe eBPF dựng token, đếm 4-gram theo thread → loader đọc map '
           'mỗi 0,5 s → worker chấm mô hình token của workload → decision ghi local và NFS → bridge gom đợt, đẩy vào '
           'Alertmanager → RCA dựng case cho đúng cảnh báo đó từ sự kiện Tetragon.<br><b>Mục tiêu:</b> recall ≥ 95%, '
           'precision ≥ 95%, p95 kernel → cảnh báo ≤ 3 s; gánh cảnh báo và binary vô hại bị gắn cờ càng thấp càng tốt. '
           'Kết quả: LID-DS 2021 official 97,40% / 0,33% báo nhầm, p95 1,47 s; live 1109 tốc độ chính 315/315, p95 0,49 s.', size=12)
    return p


# ---------------------------------------------------------------- page 2: kernel probe
def kernel():
    p = Page('2. Probe eBPF trong kernel', 1720, 1010)
    p.title('Probe eBPF: pulse_counter_tokens (make tokens)',
            'Token select1f cho mô hình lidds-ml-v5. Không có ftrace_ops nào (amendment 1–2 của token-probe-overhead-v1): '
            'chỉ raw tracepoint và fexit/__seccomp_filter. Bộ đếm syscall theo cgroup còn trong build, không dùng để báo.')
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
    cfg = p.box(1380, 200, 300, 190, '.rodata.tokcfg', 'loader đặt trước khi nạp; verifier cắt nhánh tắt:<br>'
                '• futex_at_exit: futex là syscall có hook<br>• count_grams: cập nhật map 4-gram<br>'
                'B = exit-nofutex, C = exit, D = grams (điều kiện đo overhead; lượt live dùng D)<br><br>'
                'Biến thể 39 trampoline fexit đã bỏ (va chạm kprobe Tetragon, open + close chậm thêm 2,3–2,7 µs)', kind='kernel', align='left',
                small=10)
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
    p.edge(cfg, emit, '', kind='ctrl', exit=(0.5, 1), entry=(1, 0.5), points=[(1530, 462)])
    m1 = p.store(40, 540, 300, 100, 'pulse_cgroups', 'PERCPU_HASH, 1024 cgroup: allow-list; full_counts, 64 bin cặp, '
                 'seccomp_skipped (giữ lại, không dùng để báo)')
    m2 = p.store(370, 540, 330, 100, 'pulse_last_syscall', 'LRU_HASH 131.072 thread: cgroup, seen_ns, syscall_id, '
                 'tok[3], tok_pending')
    m3 = p.store(730, 540, 330, 100, 'pulse_grams', 'HASH 262.144 entry; khoá 32 byte (cgroup, cửa sổ, 4 token); '
                 'giá trị: số lần')
    p.store(1090, 540, 260, 100, 'pulse_stats, pulse_tok_stats', 'lỗi chèn trạng thái/gram, walk quá sâu, tổng gram')
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
    l1 = p.box(880, 712, 380, 100, 'Khởi động', 'kiểm layout map; đặt .rodata.tokcfg; nạp object; gắn sys_enter, '
               'fexit seccomp, sys_exit; nạp allow-list từ resolver; lỗi thì dừng (fail closed)', kind='user',
               align='left', small=10)
    l2 = p.box(1300, 712, 380, 100, 'Mỗi 0,5 s (MONOTONIC + 20 ms)', 'cộng bộ đếm per-CPU mọi cgroup → '
               'cgroup_snapshot_extended; đọc pulse_grams theo lô, lấy cửa sổ đã đóng, xoá theo lô → token_grams',
               kind='user', align='left', small=10)
    p.box(880, 828, 800, 150, 'Dòng JSON ra stdout (một frame)',
          '{"type":"cgroup_snapshot_extended","cgroup_id":…,"total":…,"counts":{29 syscall},"syscall_bins":[64],'
          '"transition_bins":[64],"full_counts":{…},"seccomp_skipped_or_emulated":…}<br>'
          '{"type":"token_grams","contract":"pulse-token-select1f-v1","cgroup_id":…,"window":W,"window_end":t,'
          '"events":n,"grams":[[t0,t1,t2,t3,count],…]}<br>{"type":"token_drain",…} · {"type":"stat",…} · '
          '{"type":"snapshot_end","targets":…,"snapshots":…}<br><b>Proof</b> (scripts/token_probe_proof.py): tổng sự '
          'kiện token = tổng full_counts trong cgroup cô lập (422.316 = 422.316), token mẫu đúng, seccomp như proof matched.',
          kind='store', align='left', small=10)
    p.edge(l1, l2, '', kind='data')
    return p


# ---------------------------------------------------------------- page 3: worker and the token model
def worker():
    p = Page('3. Worker và mô hình token', 1720, 1090)
    p.title('Worker chấm điểm và mô hình token lidds-ml-v5 trên cụm',
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
    sc = p.box(600, 280, 520, 220, 'Điểm cửa sổ', 'mỗi sự kiện: độ bất ngờ −ln P_3<br>s(W) = trung bình 10 giá trị lớn nhất '
               '(gram tính theo số lần); ít hơn 10 sự kiện: trung bình tất cả; cửa sổ rỗng: 0<br>ví dụ: binary đối chứng '
               'trong RabbitMQ (6 × 34,0 + 4 × 7,0) / 10 = 23,2 &gt; 13,4', kind='ml', align='left', small=11)
    tb = p.box(1160, 280, 520, 220, 'TokenBranch (cfg tokens.models)', 'mỗi workload: đường dẫn mô hình, SHA-256, ngưỡng τ; '
               'hash lệch → không nạp<br>s(W) &gt; τ → báo (candidate_alert_preview), một cửa sổ là đủ<br>ghi decision '
               'branch=token: token_score, token_threshold, token_scored_at<br>chấm p50 0,15 s, p95 0,18 s sau khi cửa sổ đóng '
               '(10,9 triệu cửa sổ, lượt 1109)', kind='ml', align='left', small=11)
    p.box(40, 530, 1080, 110, 'Bảng chữ select1f', 'errno của 27 syscall (stat, lstat, fstat, newfstatat, access, faccessat, '
          'open, openat, creat, read, write, writev, ioctl, connect, execve, fcntl, close, rename, renameat, sendfile, unlink, '
          'unlinkat, mkdir, kill, recvfrom, shutdown, futex) · mở thành công: chế độ r|w + thư mục đầu · đọc/ghi thành công: '
          'min(15, ⌊log2 n⌋) · còn lại: tên. LID-DS 2021 official: recall 97,40%, báo nhầm 0,33%, p95 1,47 s',
          kind='note', align='left', small=11)
    p.edge(chk, lm, 'cửa sổ token', kind='data', exit=(0.5, 1), entry=(0.5, 0), points=[(550, 250), (300, 250)])
    p.edge(lm, sc, '', kind='data')
    p.edge(sc, tb, '', kind='data')
    dec = p.box(20, 690, 1680, 80, 'Decision = mô hình token của workload báo (một cửa sổ là đủ)',
                'mỗi decision mang workload_key, pod_uid, container, window_start/end, token_score, token_threshold, run_id, '
                'capture_segment; độ trễ kernel → cảnh báo = cuối cửa sổ + thời gian chấm', kind='alert')
    p.edge(tb, dec, '', kind='alert', exit=(0.5, 1), entry=(0.83, 0))
    s1 = p.store(20, 800, 400, 110, 'NFS: segment 30 phút', 'decisions.jsonl · tokens.jsonl · issues.jsonl · loader.log · '
                 'TERMINAL.json (seal)')
    s2 = p.store(450, 800, 300, 110, 'Đĩa local của worker', 'decisions.jsonl cho bridge, RCA, campaign')
    p.box(780, 800, 450, 110, 'Ghi ngoài vòng chấm (async_sink)', 'thread nền, fdatasync + FADV_DONTNEED mỗi 30 s; '
          'STATUS.json bất đồng bộ; dừng khi hết chỗ trống', kind='user', small=10)
    p.box(1260, 800, 440, 110, 'Khoá trước khi chấm', 'kernel = proof; SHA-256 của loader và object; SHA-256 từng mô hình token '
          'và ngưỡng trong CONFIG.json', kind='user', small=10)
    p.edge(dec, s1, '', kind='store', exit=(0.12, 1), entry=(0.5, 0))
    p.edge(dec, s2, '', kind='store', exit=(0.35, 1), entry=(0.5, 0))
    p.text(20, 940, 1680, 120, '<b>Học mô hình (token_branch_fit.py, trước mỗi lượt):</b> normal của lượt thu 12 h (+ normal của lượt '
           'live trước, bỏ −5 s … +25 s quanh mỗi trial) → tách theo workload → đoạn 30 phút chia vào 5 fold → chấm phần giữ ra → '
           'điểm lớn nhất mỗi khối 60 s mỗi container → bỏ 1% cao nhất → Gumbel theo moment → τ ở α′ = 0,00018 → mô hình cuối học '
           'trên toàn bộ → MODELS.json (SHA-256). Không đổi trong lượt chạy.', size=12)
    return p


# ---------------------------------------------------------------- page 4: alerting and RCA
def alerting():
    p = Page('4. Cảnh báo và RCA', 1720, 790)
    p.title('Đường cảnh báo và truy nguyên nguyên nhân (RCA)',
            'Bridge và RCA chạy trên .234 và chỉ đọc decision. Mã đợt cảnh báo = mã case RCA.')
    w = p.box(20, 90, 250, 110, 'Worker ×3', 'decisions.jsonl local; chỉ dòng token có "candidate_alert_preview":true '
              'rời worker', kind='ml', small=9)
    br = p.box(310, 80, 430, 165, 'Alert bridge (ops/alert_bridge.py)', '• bám log decision của từng worker qua SSH<br>'
               '• gom đợt theo (pod_uid, container); hết đợt khi im lặng quá resolve_after<br>'
               '• push POST /api/v2/alerts lúc mở đợt, làm mới khi còn kéo dài; lỗi → thử lại 3 lần, cách 0,5 s<br>'
               '• đo độ trễ từ preview_emitted_at và window_end<br>• đường pull (gauge /metrics, scrape 5 s / 30 s) chỉ để '
               'so độ trễ: chậm hơn nhiều<br>• triggers.jsonl: dòng đầu của mỗi đợt đã giao', kind='alert', align='left',
               small=10)
    am = p.box(800, 80, 300, 110, 'Alertmanager (API v2)', 'SentinelPulseAnomaly (kèm chú thích RCA khi case xong, cùng '
               'nhãn); SentinelPulseTriage với nhãn rca_class, notify', kind='alert', small=9)
    route = p.box(800, 220, 300, 90, 'Route theo notify', 'immediate: thao tác bảo mật → /alertmanager/notify'
                  '<br>dashboard: chỉ probe, binary mới, khác', kind='alert', small=9)
    ppl = p.box(1160, 80, 260, 110, 'Người vận hành', 'thông báo ngay, hoặc xem dashboard', kind='alert')
    graf = p.box(1160, 220, 260, 90, 'Grafana', 'dashboard sentinel-pulse-alerts; bảng case qua Infinity (/cases.json)',
                 kind='ext', small=9)
    p.edge(w, br, 'SSH tail', kind='alert', exit=(1, 0.4), entry=(0, 0.23))
    p.edge(br, am, 'push', kind='alert', exit=(1, 0.29), entry=(0, 0.5))
    p.edge(am, route, '', kind='alert')
    p.edge(route, ppl, 'immediate', kind='alert', exit=(1, 0.3), entry=(0, 0.75), points=[(1130, 247), (1130, 162)])
    p.edge(route, graf, 'dashboard', kind='alert', exit=(1, 0.7), entry=(0, 0.7))
    p.group(20, 340, 1680, 370, 'RCA (sentinel_pulse/rca)', kind='alert', size=12)
    tp = p.box(40, 380, 300, 135, '3 policy Tetragon (chỉ production)', '<b>runtime:</b> file nhạy cảm, credential, '
               'kết nối, namespace, ptrace<br><b>fork</b><br><b>flow:</b> lần gửi trên socket đã mở, lấy mẫu 1 lần mỗi '
               'process mỗi 10 s<br>+ exec provenance', kind='ext', align='left', small=10)
    sub = p.box(380, 380, 320, 135, 'Subscriber', 'tetra getevents của 3 worker, xoay vòng có giới hạn<br>ghép theo node, '
                'Pod UID, container, thời gian; process = exec_id (PID bị tái dùng)<br>ring SQLite 180 s; nhật ký exec 15 '
                'phút', kind='alert', align='left', small=10)
    case = p.box(740, 380, 330, 135, 'Dựng case (nhịp 0,25 s)', 'từ cảnh báo Alertmanager đã nhận (triggers.jsonl); '
                 'lấy 30 s trước cảnh báo<br>cùng container trong 300 s → cùng case; binary mới trong khoảng đó → case tiếp '
                 'nối; giữ tối đa 20.000 case', kind='alert', align='left', small=10)
    rank = p.box(1110, 380, 570, 135, 'Xếp hạng nghi phạm (heuristic có lý do)', 'binary mới trong workload sau mốc '
                 'baseline +4 · thao tác credential / namespace / mount / ptrace +3 mỗi lần (tối đa 9) · binary chưa từng '
                 'ghi nhận +2 · exec trong cửa sổ cảnh báo +2 · syscall thất bại +1 (tối đa 3) · cha của nghi phạm khác +1'
                 '<br>ngoại lệ: hạ quyền setuid/setgid lúc khởi động; containerd-shim, runc không xếp hạng<br>phá hoà theo '
                 'thời điểm khởi chạy: top-1 100% trên các trial blind', kind='alert', align='left', small=10)
    tri = p.box(40, 560, 660, 120, 'Triage (ops/rca_view.py)', 'security_operation → notify ngay '
                '· probe_only (mọi exec là probe Kubernetes của pod spec) → dashboard · new_binary → dashboard · other → '
                'dashboard<br>chỉ là quyết định giao tin: decision và mọi chỉ số đánh giá không đổi', kind='alert',
                align='left', small=10)
    out = p.box(740, 560, 940, 120, 'Đầu ra của case', '&lt;case_id&gt;.json (cây bằng chứng) · .md · .svg; trang /cases, '
                '/cases/&lt;id&gt; (nghi phạm, lý do, binary, đích mạng, cây)<br>bridge push lại SentinelPulseAnomaly kèm chú '
                'thích RCA (khoảng 2,7 s sau cảnh báo)<br>cây cho thấy liên quan theo định danh và thời gian, không chứng minh '
                'nhân quả; RCA không tự xử lý pod', kind='alert', align='left', small=10)
    p.edge(tp, sub, 'sự kiện', kind='data')
    p.edge(sub, case, '', kind='data')
    p.edge(case, rank, '', kind='data')
    p.edge(am, case, 'cảnh báo đã nhận', kind='alert', exit=(0, 0.8), entry=(0.106, 0), points=[(775, 168)])
    p.edge(case, tri, '', kind='alert', exit=(0.2, 1), entry=(0.9, 0), points=[(806, 540), (634, 540)])
    p.edge(rank, out, '', kind='alert', exit=(0.5, 1), entry=(0.75, 0))
    p.text(20, 725, 1680, 40, 'Độ trễ tới Alertmanager và RCA của mô hình token đo ở lượt pulse-live-v5-1110 (lượt 1109: bridge '
           'bỏ dòng token, lỗi đã sửa).', size=11)
    return p


# ---------------------------------------------------------------- page 5: learning and evaluation
def evaluation():
    p = Page('5. Học và đánh giá', 1720, 1000)
    p.title('Quy trình chọn, xác nhận và đánh giá',
            'Chọn trên dữ liệu development, xác nhận một lần trên dữ liệu khoá; mỗi bước có protocol đăng ký trước và '
            'biên nhận JSON trong repo.')
    steps = [
        ('LID-DS 2021 development + CB-DS', 'chọn bảng chữ token, độ dài gram, top-k, ngưỡng; lidds-ml-v5: development '
         '530/544, 6 báo nhầm; CB-DS 891/891, 3/1.410', 'eval'),
        ('LID-DS 2021 official', 'lidds-ml-v5: 97,40% recall (1.238/1.271), 0,33% báo nhầm (26/7.938), precision 97,9%, '
         'p95 1,47 s; trong 3 s 1.234', 'ml'),
        ('Thu normal trên cụm (12 h)', 'pulse-token-capture-1107: chỉ normal, tải theo lịch; dữ liệu học mô hình token', 'eval'),
        ('Lượt live blind (24 h)', 'pulse-live-v4-1109: 525 trial; tập chính 315/315, precision 99,06%, control 3/315, '
         'p95 0,49 s, binary vô hại 313/315, gánh 0,41', 'eval'),
        ('Học lại + live v5', 'normal 1109 ngoài trial (amendment 2); pulse-live-v5-1110: thêm lệnh admin, đo Alertmanager '
         'và RCA', 'eval'),
        ('LID-DS 2019 (cuối cùng)', 'chấm một lần, không chỉnh gì', 'eval'),
    ]
    ids = []
    for k, (t, s, kind) in enumerate(steps):
        ids.append(p.box(20 + 280 * k, 100, 255, 150, t, s, kind=kind, small=10))
        if k:
            p.edge(ids[k - 1], ids[k], '', kind='eval' if kind != 'ml' else 'data')
    p.group(20, 290, 830, 420, 'Offline (máy phân tích .234, systemd-run có giới hạn bộ nhớ)', kind='eval', size=12)
    p.box(40, 330, 380, 170, 'Chuyển đổi và chấm', 'sentinel_pulse/lidds: convert.py<br>'
          'lidds_ml_token_alphabets.py (token), lidds_ml_token_crossfit.py (cross-fit)<br>'
          'lidds_ml_v5.py (chọn trên development + CB-DS, chấm official một ứng viên)', kind='user',
          align='left', small=10)
    p.box(440, 330, 390, 170, 'Ngưỡng', 'Gumbel theo moment trên điểm lớn nhất giữ ra của cross-fit 5 fold, bỏ 1% cao nhất; '
          'α′ = 0,0002 × 0,9 = 0,00018; moment được chọn trên development sau khi so với Gumbel MLE, GEV, chuẩn, đuôi mũ<br>'
          'trên cụm: khối 60 s mỗi container thay cho bản ghi, fold theo đoạn 30 phút', kind='ml', align='left', small=10)
    p.box(40, 520, 380, 170, 'Kiểm thêm (development)', 'chỉ tên syscall 487/544, bỏ cỡ đọc ghi 490/544<br>'
          'LSTM lớn không hơn 4-gram<br>thứ tự phát token như probe (probe1f): 530/544<br>luật đếm 4-gram chưa thấy có ngưỡng: ngang mô hình',
          kind='eval', align='left', small=10)
    p.box(440, 520, 390, 170, 'Overhead probe token (token-probe-overhead-v1)', 'benchmark syscall tĩnh, 5 vòng, 3 '
          'worker, xoay điều kiện: off / A / B / C / D / D không giám sát<br>lần 1 fexit → va chạm kprobe Tetragon; '
          'lần 2 sys_exit; lần 3 đi ngược dentry; báo cáo, không đạt/trượt', kind='eval', align='left', small=10)
    p.group(870, 290, 830, 420, 'Trên cụm (lượt live)', kind='eval', size=12)
    p.box(890, 330, 380, 170, 'Planner', 'plan_matched_run.py --token-build --token-models --admin-control → CONFIG.json '
          'bất biến; launcher cài worker, RCA, bridge, traffic, campaign', kind='eval', align='left', small=10)
    p.box(1290, 330, 390, 170, 'Fit trước lượt live', 'token_branch_fit.py → MODELS.json (mô hình token + ngưỡng mỗi workload)<br>'
          '--extra-run: thêm normal của lượt trước, bỏ −5 s … +25 s quanh mỗi trial<br>khoá sha256 trước lượt live', kind='ml', align='left', small=10)
    p.box(890, 520, 380, 170, 'Chấm lượt live', 'trial phát hiện khi có báo động trong [start, start + 15 s]; đợt = '
          'báo động cùng container cách nhau < 15 s; gánh = đợt / replica-giờ ngoài khoảng campaign; Wilson, bootstrap '
          'theo workload', kind='eval', align='left', small=10)
    p.box(1290, 520, 390, 170, 'Gate cho binary vô hại (đã loại)', 'mô hình gộp mọi workload, giữ 1–2 s sau execve, '
          'ngưỡng theo pha: không giữ được kết quả LID-DS (development 315–509/544) → hệ thống không có gate',
          kind='retired', align='left', small=10)
    p.group(20, 740, 1680, 230, 'Bằng chứng và tài liệu', kind='store', size=12)
    docs = [('Protocol', 'sentinel_pulse/protocol/*.json, đăng ký trước khi có dữ liệu; amendment ghi rõ lý do'),
            ('Biên nhận', 'validation-evidence/results-YYYYMMDD/*: JSON, bảng, log; seal SHA-256 của segment'),
            ('Audit số liệu', 'scripts/audit/headline_numbers.py: mọi số trong bản LaTeX khớp biên nhận (53/53)'),
            ('Đồ án', 'thesis/ (LaTeX, tectonic); báo cáo và slide họp trong docs/'),
            ('Ghi chép', 'notes/STATE.md (trạng thái), notes/WORKLOG.md (nhật ký từng bước)')]
    for k, (t, s) in enumerate(docs):
        p.box(40 + 330 * k, 775, 310, 100, t, s, kind='store', small=10)
    p.text(40, 890, 1640, 60, 'Nguyên tắc: chọn trên development, official và lượt live chỉ để xác nhận; mỗi lần chấm '
           'lại official phải khai báo; không job nặng nào chạy cùng lượt live; số liệu chỉ lấy từ biên nhận.', size=12)
    return p


def main():
    pages = [overview(), kernel(), worker(), alerting(), evaluation()]
    xml = ('<mxfile host="drawio" agent="make_architecture_drawio.py" version="32.6.10">'
           + ''.join(pg.xml(k + 1) for k, pg in enumerate(pages)) + '</mxfile>\n')
    OUT.write_text(xml, encoding='utf-8')
    print(OUT, len(pages), 'pages')


if __name__ == '__main__':
    main()
