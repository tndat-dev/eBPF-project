"""Token branch of lidds-ml-v3 on the probe's integer tokens (sentinel_pulse/ebpf/pulse_token_ids.h).

The same model as scripts/analysis/lidds_ml_tokens.py TokenLM: per-thread 4-grams, Witten-Bell backoff over shorter
contexts down to the base P(name) x P(token | name), both add-half, an unseen call graded by the mean unseen-token
probability of the known calls. Two differences, neither in the arithmetic:

- tokens are the probe's 32-bit integers and a token's call (the "name") is its syscall number, ``tok >> 23``;
- it learns from gram counts (the probe sends one count per distinct (cgroup, window, gram)), so a gram seen c times
  adds c, exactly what c separate ``TokenLM.learn`` calls add (tests/test_token_model.py checks the equality).

A window's score is the mean of its TOP highest per-event -log p, events counted with their multiplicity. Grams whose
leading slots are TOK_NONE (thread start) are the shorter grams of the offline model.
"""
# ==============================================================================================================
# token_model.py — MÔ HÌNH ML CỦA ĐỒ ÁN (đường cảnh báo hiện tại) và lớp TokenBranch mà worker dùng để chấm.
# ------------------------------------------------------------------------------------------------------------
# Mô hình ngôn ngữ ĐẾM: học = đếm số lần mỗi token theo sau mỗi ngữ cảnh 1, 2, 3
# token trước nó trong CÙNG thread, trên dữ liệu normal. Chấm = tính xác suất của mỗi sự kiện, lấy "độ bất ngờ"
# -ln p, điểm cửa sổ = trung bình `top` độ bất ngờ lớn nhất (top lấy từ MODELS.json: 10 ở v5, 3 ở v5-t3). Ngưỡng (đặt ở token_branch_fit.py) so với điểm này.
# Ký hiệu dùng trong code: gram g = (t0, t1, t2, w) — w là token đang xét, (t0,t1,t2) là lịch sử; h = ngữ cảnh;
# "name" = số syscall của token (tok >> 23).
# Cùng số học với bản offline scripts/analysis/lidds_ml_tokens.py (TokenLM) — test kiểm sai lệch < 1e-12, nên
# mô hình chấm LID-DS và mô hình chạy trên cụm là MỘT.
# ==============================================================================================================
from __future__ import annotations

from collections import Counter, defaultdict
import gzip
import json
import math
from pathlib import Path

# N = độ dài gram (4); TOP = số độ bất ngờ lớn nhất lấy trung bình (10). TOK_NONE = ô lịch sử trống (đầu thread).
N, TOP = 4, 10
TOK_NONE = 0xFFFFFFFF
NR_SHIFT = 23
KIND_SHIFT = 21


# Số syscall của một token: 9 bit cao (bit 23..31), xem bố cục trong sentinel_pulse/ebpf/pulse_token_ids.h.
def call_of(tok: int) -> int:
    return tok >> NR_SHIFT


# Bỏ các ô TOK_NONE ở đầu gram: gram ở đầu thread chỉ có 1–3 token thật (gram "ngắn" của mô hình offline).
def strip(gram) -> tuple:
    """Drop the empty history slots in front: (NONE, NONE, a, b) -> (a, b)."""
    g = tuple(int(t) for t in gram)
    start = 0
    while start < len(g) - 1 and g[start] == TOK_NONE:
        start += 1
    if TOK_NONE in g[start:]:
        raise ValueError('empty slot inside a gram')
    return g[start:]


# ---------------------------------------------------------------------------------------------------------------
# CountTokenLM — bảng đếm và cách tính xác suất.
#   count[k][h][w] : số lần token w theo sau ngữ cảnh h gồm k token (k = 1, 2, 3; count[0] không dùng)
#   names[name]    : số sự kiện của mỗi syscall (bất kể biến thể)          → c(ν) trong công thức
#   given[name][w] : số lần biến thể w (vd. read#12) trong syscall đó       → c(ν, w)
#   total          : tổng số sự kiện đã học                                → N
# ---------------------------------------------------------------------------------------------------------------
class CountTokenLM:
    def __init__(self, n: int = N):
        self.n = n
        self.count = [defaultdict(Counter) for _ in range(n)]
        self.names = Counter()
        self.given = defaultdict(Counter)
        self.total = 0
        self.finalized = False
        self.default_top = TOP      # window score: mean of this many highest -log p (lidds-ml-v5: 10, lidds-ml-v5-t3: 3)

    # Học MỘT gram với trọng số `weight` (= số lần probe thấy gram đó). Với mỗi k, ngữ cảnh là k token ngay trước w.
    # Học "gram thấy c lần" bằng weight = c cho kết quả y hệt gọi learn c lần (test_token_model.py kiểm).
    def learn(self, gram, weight: int = 1):
        if weight <= 0:
            raise ValueError('gram count must be positive')
        g = tuple(gram[-self.n:])
        w = g[-1]
        for k in range(1, min(self.n, len(g))): 
            self.count[k][g[-1 - k:-1]][w] += weight
        name = call_of(w)
        self.names[name] += weight
        self.given[name][w] += weight
        self.total += weight

    # Học cả một cửa sổ đúng định dạng loader in ra: [[t0,t1,t2,t3,count], ...].
    def learn_window(self, grams):
        """grams: [[t0, t1, t2, t3, count], ...] as the probe sends them."""
        for *gram, c in grams:  # extended iterable unpacking (*gram, c) để tách phần tử cuối cùng thành c
            self.learn(strip(gram), int(c))

    # Gọi một lần sau khi học xong: tính sẵn (tổng c(h), số loại T(h)) cho mọi ngữ cảnh — hai đại lượng của
    # Witten–Bell — và xác suất "biến thể chưa thấy" trung bình (dùng khi chính tên syscall chưa từng thấy).
    # memo: bộ nhớ đệm xác suất theo gram (tối đa 2 triệu mục) vì cùng gram lặp lại rất nhiều giữa các cửa sổ.
    def finalize(self):
        self.stats = [{h: (sum(c.values()), len(c)) for h, c in level.items()} for level in self.count]
        self.memo = {}
        unseen = [0.5 / (sum(c.values()) + 0.5 * (len(c) + 1)) for c in self.given.values()]
        self.unseen_given = sum(unseen) / len(unseen) if unseen else 1.0
        self.given_total = {name: sum(c.values()) for name, c in self.given.items()}
        self.finalized = True
        return self

    # MỨC NỀN P0(w) = P(tên) × P(biến thể | tên), cả hai làm mượt "cộng nửa" (add-½):
    #   P(tên)            = (c(ν) + ½) / (N + ½(V + 1))           — V = số tên đã thấy, +1 chừa chỗ cho tên mới
    #   P(biến thể | tên) = (c(ν,w) + ½) / (c(ν) + ½(V_ν + 1))   — V_ν = số biến thể đã thấy của tên ν
    # Tên chưa thấy → thừa số thứ hai = xác suất biến-thể-chưa-thấy trung bình. Nhờ cấu trúc này, openat!13 chưa
    # thấy vẫn có xác suất cao hơn nhiều so với ptrace chưa từng gọi.
    def base(self, w: int) -> float: 
        name = call_of(w)
        p_name = (self.names.get(name, 0) + 0.5) / (self.total + 0.5 * (len(self.names) + 1))
        given = self.given.get(name)
        if not given:
            return p_name * self.unseen_given
        return p_name * (given.get(w, 0) + 0.5) / (self.given_total[name] + 0.5 * (len(given) + 1))

    # XÁC SUẤT P3(w | 3 token trước) theo WITTEN–BELL NỘI SUY, đi từ ngữ cảnh ngắn tới dài:
    #   p ← P0(w);  với k = 1, 2, 3:  p ← (c(h_k, w) + T(h_k)·p) / (c(h_k) + T(h_k))   (bỏ qua nếu h_k chưa thấy)
    # T(h) = số token KHÁC NHAU từng theo sau h. Ngữ cảnh "đoán được" (T nhỏ so với c) tin số đếm của nó; ngữ cảnh
    # có nhiều khả năng tiếp theo nhường nhiều xác suất cho mức ngắn hơn.
    def prob(self, g) -> float:
        g = tuple(g[-self.n:])
        hit = self.memo.get(g)
        if hit is not None:
            return hit
        w = g[-1]
        p = self.base(w)
        for k in range(1, min(self.n, len(g))):
            h = g[-1 - k:-1]
            st = self.stats[k].get(h)
            if not st:
                continue
            tot, types = st
            p = (self.count[k][h].get(w, 0) + types * p) / (tot + types)
        if len(self.memo) < 2_000_000:
            self.memo[g] = p
        return p

    # ĐIỂM CỬA SỔ: mỗi gram cho độ bất ngờ -ln p, lặp lại `c` lần (bội số). Sắp giảm dần, lấy 10 sự kiện bất ngờ
    # nhất (một gram có thể chiếm nhiều chỗ nếu c > 1), trả trung bình. Ví dụ RabbitMQ trong đồ án:
    # 6 lần 34,0 + 4 lần 7,0 → (204 + 28)/10 = 23,2 > ngưỡng 13,4 → cửa sổ bị báo.
    def window_score(self, grams, top: int | None = None) -> float:
        """Mean of the top highest -log p of a window's events; 0 for an empty window (as the offline scorer).
        top None = the model's default_top (TOP unless the fit set another, MODELS.json "top")."""
        top = self.default_top if top is None else int(top)
        values = sorted(((-math.log(self.prob(strip(gram))), int(c)) for *gram, c in grams), reverse=True)
        taken, total = 0, 0.0
        for nll, c in values:
            use = min(c, top - taken)
            total += nll * use
            taken += use
            if taken == top:
                break
        return total / taken if taken else 0.0

    # Lưu/nạp: chỉ lưu bảng đếm (JSON nén gzip, ~1,5 MB cho 21 workload); finalize() dựng lại phần còn lại.
    # persistence: counts only; finalize() rebuilds the rest
    # Chuyển mô hình thành dict sẵn sàng serialize JSON
    def to_json(self) -> dict:
        return dict(schema='sentinel-pulse-token-lm-v1', n=self.n, total=self.total,
                    names=[[k, v] for k, v in self.names.items()],
                    given=[[name, [[w, c] for w, c in ws.items()]] for name, ws in self.given.items()],
                    count=[[[list(h), [[w, c] for w, c in ws.items()]] for h, ws in level.items()] for level in self.count])

    @classmethod
    # Dựng lại đối tượng CountTokenLM từ dict
    def from_json(cls, doc: dict) -> 'CountTokenLM':
        if doc.get('schema') != 'sentinel-pulse-token-lm-v1':
            raise ValueError('not a token LM document')
        lm = cls(doc['n'])
        lm.total = doc['total']
        lm.names = Counter({k: v for k, v in doc['names']})
        for name, ws in doc['given']:
            lm.given[name] = Counter({w: c for w, c in ws})
        for k, level in enumerate(doc['count']):
            for h, ws in level:
                lm.count[k][tuple(h)] = Counter({w: c for w, c in ws})
        return lm.finalize()

    def save(self, path: Path):
        with gzip.open(path, 'wt') as handle:
            json.dump(self.to_json(), handle, separators=(',', ':'))

    @classmethod
    def load(cls, path: Path) -> 'CountTokenLM':
        with gzip.open(path, 'rt') as handle:
            return cls.from_json(json.load(handle))


# ---------------------------------------------------------------------------------------------------------------
# Phần dưới dùng cho GATE của protocol lidds-ml-v5 (đã thử và BỊ LOẠI: làm mất phát hiện trên LID-DS). Mã vẫn giữ để
# tái lập; trong các lượt chạy hiện tại không truyền `gate` nên nhánh này không chạy.
# ---------------------------------------------------------------------------------------------------------------
NR_EXECVE = 59


def has_execve(grams) -> bool:
    """A process image changed in this window: some event of the window is an execve (its last token slot)."""
    return any(call_of(int(gram[3])) == NR_EXECVE for gram in grams if int(gram[3]) != TOK_NONE)


# TokenBranch — thứ matched_worker.py khởi tạo một lần và gọi score(window) cho MỖI cửa sổ token vừa đóng.
#   spec = MODELS.json do token_branch_fit.py sinh: {workload_key: {lm, lm_sha256, threshold}}.
#   Lúc nạp, SHA-256 của từng file mô hình phải khớp spec → mô hình bị đổi giữa chừng thì worker từ chối chạy.
#   score(): workload không có mô hình → None (không chấm); có → token_score, token_threshold, token_alert
#   (= điểm > ngưỡng; MỘT cửa sổ vượt là đủ để báo).
class TokenBranch:
    """Online token branch for the worker. spec (worker cfg tokens.models): {workload_key: {"lm": path,
    "lm_sha256": hex, "threshold": float}}; a workload without a model gets no token score. One window above its
    workload's threshold is a token alert (the lidds-ml-v3 rule: one window fires).

    gate (worker cfg tokens.gate, protocol lidds-ml-v5), optional: {"pool": {"lm": path, "lm_sha256": hex},
    "exec_hold_seconds": float}, with "pool_threshold" per workload in spec. The alert then also needs the window to be
    surprising to the model of all workloads together (score above pool_threshold) and to lie more than
    exec_hold_seconds after the container's last execve. With "phase_threshold" (amendment 1) a window within those
    seconds is not held but compared with that threshold instead."""

    def __init__(self, spec: dict, sha256_file, gate: dict | None = None, session: dict | None = None):
        self.models, self.thresholds = {}, {}
        # session-stream-v1 (optional, worker cfg tokens.session): the native part of each window against
        # "native_thresholds" (the workload model at the branch level) OR the session part against a session model:
        # the workload's own ("per", when the fit gave one) or the pooled one ("pooled"). Absent = the whole window.
        self.session = None
        if session:
            def load(item):
                path = Path(item['lm'])
                if sha256_file(path) != item['lm_sha256']:
                    raise ValueError(f'token session model {path} changed')
                lm = CountTokenLM.load(path)
                lm.default_top = int(item.get('top', TOP))
                thr = float(item['threshold'])
                if not math.isfinite(thr):
                    raise ValueError('token session threshold is not finite')
                return lm, thr
            native = {k: float(v) for k, v in session['native_thresholds'].items()}
            if not all(math.isfinite(v) for v in native.values()):
                raise ValueError('token native threshold is not finite')
            self.session = dict(native=native, pooled=load(session['pooled']),
                                per={k: load(v) for k, v in session.get('per', {}).items()})
        self.pool, self.pool_thresholds, self.hold, self.last_exec = None, {}, 0.0, {}
        self.phase_threshold = None
        if gate:
            path = Path(gate['pool']['lm'])
            if sha256_file(path) != gate['pool']['lm_sha256']:
                raise ValueError('token pool model changed')
            self.pool = CountTokenLM.load(path)
            self.hold = float(gate['exec_hold_seconds'])
            if gate.get('phase_threshold') is not None:
                self.phase_threshold = float(gate['phase_threshold'])
                if not math.isfinite(self.phase_threshold):
                    raise ValueError('token phase threshold is not finite')
            self.pool_thresholds = {key: float(item['pool_threshold']) for key, item in spec.items()}
            if not all(math.isfinite(t) for t in self.pool_thresholds.values()):
                raise ValueError('token pool threshold is not finite')
        for key, item in spec.items():
            path = Path(item['lm'])
            if sha256_file(path) != item['lm_sha256']:
                raise ValueError(f'token model of {key} changed')
            self.models[key] = CountTokenLM.load(path)
            self.models[key].default_top = int(item.get('top', TOP))      # lidds-ml-v5-t3: 3; absent = 10
            if self.models[key].default_top < 1:
                raise ValueError(f'token top of {key} must be >= 1')
            self.thresholds[key] = float(item['threshold'])
            if not math.isfinite(self.thresholds[key]):
                raise ValueError(f'token threshold of {key} is not finite')

    def score(self, window: dict):
        lm = self.models.get(window['workload_key'])
        if lm is None:
            return None
        s = lm.window_score(window['grams'])
        raw = bool(s > self.thresholds[window['workload_key']])
        out = dict(token_score=s, token_threshold=self.thresholds[window['workload_key']], token_alert=raw)
        if self.session is not None:
            return self._session_score(window, lm, out)
        if self.pool is None:
            return out
        key = (window['pod_uid'], window['container_name'])
        if has_execve(window['grams']):
            self.last_exec[key] = window['window_end']
        held = self.hold > 0 and window['window_end'] - self.last_exec.get(key, -math.inf) <= self.hold
        pool_score = self.pool.window_score(window['grams'])
        threshold = self.pool_thresholds[window['workload_key']]
        passes = (pool_score > self.phase_threshold) if held and self.phase_threshold is not None else (
            pool_score > threshold and not held)
        out.update(token_alert=bool(raw and passes), token_alert_raw=raw,
                   token_pool_score=pool_score, token_pool_threshold=threshold, token_exec_held=held)
        return out

    def _session_score(self, window, lm, out):
        """session-stream-v1: native part by the workload model at its branch threshold, session part by its model."""
        key = window['workload_key']
        session = window.get('session')
        if session is None:
            raise ValueError('the session branch needs windows of the lineage build')
        native = native_part(window['grams'], session)
        native_score = lm.window_score(native) if native else 0.0
        native_thr = self.session['native'][key]
        slm, sthr = self.session['per'].get(key, self.session['pooled'])
        session_score = slm.window_score(session) if session else 0.0
        alert = bool(native_score > native_thr or session_score > sthr)
        out.update(token_alert=alert, token_alert_whole=out['token_alert'], token_native_score=native_score,
                   token_native_threshold=native_thr, token_session_score=session_score, token_session_threshold=sthr,
                   token_alert_stream=('native' if native_score > native_thr else 'session') if alert else None)
        return out


def native_part(grams, session):
    """The window minus its session part, count by count (session-stream-v1); rows with nothing left are dropped."""
    left = {tuple(int(v) for v in g[:4]): int(g[4]) for g in grams}
    for g in session:
        k = tuple(int(v) for v in g[:4])
        left[k] = left.get(k, 0) - int(g[4])
        if left[k] < 0:
            raise ValueError('session part exceeds the window')
    return [[*k, c] for k, c in left.items() if c > 0]
