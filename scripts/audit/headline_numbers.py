#!/usr/bin/env python3
"""Audit of the headline numbers: every number the summaries state is recomputed from the receipts committed under
validation-evidence/ and compared at the precision the report prints it.

A claim is a sentence (exact substring) of a report plus the values it must contain; each value is computed here
from a receipt and formatted the way the reports write numbers (Vietnamese decimal comma). A claim fails when its
sentence is missing from the report (it was edited without updating this audit) or when a value computed from the
receipt does not appear in it (the report and the receipt disagree). No cluster access: receipts only.

    python3 scripts/audit/headline_numbers.py [--markdown docs/AUDIT.md]

Exit status 1 on any failure. tests/test_headline_numbers.py runs it in the test suite.
"""
from __future__ import annotations

import argparse
import gzip
import importlib.util
import json
import math
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
EV = ROOT/'validation-evidence'
FINAL = 'results-20261025/pulse-peer-discount-confirm'
CONFIRM = 'results-20261023/pulse-stable-confirm'


def receipt(path):
    p = EV/path
    with (gzip.open(p, 'rt') if p.suffix == '.gz' else open(p)) as f:
        return json.load(f)


def jsonl(path):
    with gzip.open(EV/path, 'rt') as f:
        return [json.loads(line) for line in f]


def num(x, digits):
    return f'{x:.{digits}f}'.replace('.', ',')


def pct(x, digits=1):
    return num(100 * x, digits) + '%'


def wilson(k, n, z=1.96):
    p = k / n
    den = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / den
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / den
    return centre - half, centre + half


def ci(lo_hi, digits):
    return f'[{num(100 * lo_hi[0], digits)}; {num(100 * lo_hi[1], digits)}]'


def thousands(n):
    return f'{n:,}'.replace(',', '.')


def signed(x, digits=1):
    """+5,8 / −1,4 (the reports write the minus sign U+2212)."""
    return ('+' if x >= 0 else '−') + num(abs(x), digits)


# ------------------------------------------------------------------ derived values

def final_push():
    """Kernel -> recipient on the push path, registered subset (6, 12, 24/s) and all rates (RCA 5.14 join)."""
    spec = importlib.util.spec_from_file_location('adl', ROOT/'scripts'/'analysis'/'alert_delivery_latency.py')
    m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
    res = receipt(f'{FINAL}/campaign-RESULTS.json')
    since = receipt(f'{FINAL}/delivery-latency-campaign.json')['since']
    rows = m.join(res['outcomes'], jsonl('results-20261025/alert-bridge/episodes.jsonl.gz'),
                  jsonl('results-20261025/alert-bridge/deliveries.jsonl.gz'), since)
    prim = [r for r in rows if r['rate_per_second'] in (6, 12, 24)]
    v = [r['push_kernel_to_recipient_seconds'] for r in prim if r.get('push_kernel_to_recipient_seconds') is not None]
    return dict(prim_n=len(prim), prim_alerted=len(v), prim_p50=m.quantile(v, .5), prim_p95=m.quantile(v, .95),
                summary=m.summarize(rows))


def overhead_per_syscall():
    syscalls = dict(getpid=1, read4k=1, mmapunmap=2, openclose=2)
    o = receipt('results-20261021/overhead/OVERHEAD-AB.json')['nodes']['k8s-worker4.local']
    mon = [o[k]['monitored_overhead']['added_ns_per_op'] / n for k, n in syscalls.items()]
    filt = [o[k]['filtered_overhead']['added_ns_per_op'] / n for k, n in syscalls.items()]
    r10 = lambda x: f'{int(round(x, -1))}'
    return f'{r10(min(mon))}–{r10(max(mon))} ns', f'{r10(min(filt))}–{r10(max(filt))} ns'


def live_runs_benign_range():
    """Benign-launch flag rate over the five live runs, from the table the figure script derives from receipts."""
    rows = [l for l in (ROOT/'docs/figures/vi/live-runs-table.md').read_text().splitlines() if l.startswith('| pulse-')]
    shares = [float(r.split('|')[6].split('%')[0].strip().replace(',', '.')) for r in rows]
    return f"{num(min(shares), 1)}–{num(max(shares), 1)}%"


# ------------------------------------------------------------------ claims

def claims():
    out = []

    def add(cid, doc, snippet, values, source):
        out.append(dict(id=cid, doc=doc, snippet=snippet, values=values, source=source))

    pulse, rule, rca, todo = 'SENTINEL_PULSE_STATUS.md', 'RULE_INTEGRATION_STATUS.md', 'RCA_RUNTIME_STATUS.md', 'TODO.md'
    c = receipt(f'{FINAL}/confirm-campaign.json')['primary']
    n_att, n_ctl, n_ben = c['TP'] + c['FN'], c['control_FP'] + c['control_TN'], c['benign_FP'] + c['benign_TN']
    add('final-recall', pulse, f"| Recall | ≥ 95% | **{pct(c['recall'])}** ({c['TP']}/{n_att}) {ci(wilson(c['TP'], n_att), 1)} |",
        [pct(c['recall']), f"{c['TP']}/{n_att}", ci(wilson(c['TP'], n_att), 1)], f'{FINAL}/confirm-campaign.json')
    add('final-precision', pulse, f"| Precision | ≥ 95% | **{pct(c['precision'])}** ({c['TP']}/{c['TP'] + c['control_FP']})",
        [pct(c['precision'])], f'{FINAL}/confirm-campaign.json')
    add('final-control', pulse, f"| Control idle dương | ≤ 5% | **{pct(c['control'])}** ({c['control_FP']}/{n_ctl}) {ci(wilson(c['control_FP'], n_ctl), 1)} |",
        [pct(c['control']), ci(wilson(c['control_FP'], n_ctl), 1)], f'{FINAL}/confirm-campaign.json')
    add('final-p95', pulse, f"**{num(c['p95'], 2)} s** (mức chấp nhận)", [num(c['p95'], 2)], f'{FINAL}/confirm-campaign.json')
    add('final-benign', pulse, f"| Binary vô hại bị gắn cờ | (báo kèm) | {pct(c['benign'])} ({c['benign_FP']}/{n_ben}) |",
        [pct(c['benign'])], f'{FINAL}/confirm-campaign.json')
    r = receipt(f'{FINAL}/confirm-campaign.json')['by_rate']
    add('final-slow', pulse, f"Recall {pct(r['1']['recall'])} ({r['1']['TP']}/{r['1']['TP'] + r['1']['FN']}) ở 1/s và "
        f"{pct(r['3']['recall'])} ({r['3']['TP']}/{r['3']['TP'] + r['3']['FN']}) ở 3/s", [pct(r['1']['recall']), pct(r['3']['recall'])],
        f'{FINAL}/confirm-campaign.json')
    b = receipt(f'{FINAL}/burden-blind-test.json')
    live = b['live']
    add('final-burden', pulse, f"**{num(live['burden_live_previews'], 2)} đợt/replica-giờ** [{num(live['burden_live_ci']['ci95'][0], 2)}; "
        f"{num(live['burden_live_ci']['ci95'][1], 2)}]", [num(live['burden_live_previews'], 2)], f'{FINAL}/burden-blind-test.json')
    keep = live['burden_live_previews'] / b['metrics']['reference']['burden']
    cap = live['burden_live_previews'] / b['metrics']['stable']['burden']
    add('final-burden-ratio', pulse, f"bằng {num(keep, 2)} lần CUSUM `keep` và {num(cap, 2)} lần stable trước",
        [num(keep, 2), num(cap, 2)], f'{FINAL}/burden-blind-test.json')
    add('final-agreement', pulse, f"{pct(live['window_agreement'], 4)} cửa sổ ({live['live_only_windows']} cửa sổ chỉ live có, "
        f"{live['recomputed_only_windows']} theo chiều ngược lại)", [pct(live['window_agreement'], 4)], f'{FINAL}/burden-blind-test.json')
    push = final_push()
    s = push['summary']
    add('final-push', pulse, f"tập chính {push['prim_alerted']}/{push['prim_n']} trial, p50 {num(push['prim_p50'], 2)} s, "
        f"p95 {num(push['prim_p95'], 2)} s; mọi tốc độ {s['push']['trials_alerted']}/{s['attack_trials']}, p95 {num(s['push']['p95'], 2)} s",
        [num(push['prim_p95'], 2)], 'results-20261025/alert-bridge/*.jsonl.gz + campaign-RESULTS.json (join of alert_delivery_latency.py)')
    add('final-pull', pulse, f"pull nhanh p50 {num(s['pull-fast']['p50'], 1)} s; pull mặc định chỉ tới người nhận ở "
        f"{s['pull-default']['trials_alerted']}/{s['attack_trials']} trial (p50 {round(s['pull-default']['p50'])} s)",
        [num(s['pull-fast']['p50'], 1)], f'{FINAL}/delivery-latency-campaign.json')
    rc = receipt('results-20261025/rule-integration/rule-comparison.json')
    A, B2 = rc['arms']['A'], rc['arms']['B2']
    add('r6-b2-summary', pulse, f"tripwire thêm {num(100 * (B2['all_rates']['attack'] - A['all_rates']['attack']), 1)} điểm recall ở mọi tốc độ "
        f"({pct(A['all_rates']['attack'])} → {pct(B2['all_rates']['attack'])}), p95 nhanh hơn "
        f"{num(A['primary']['p95'] - B2['primary']['p95'], 2)} s, gánh chỉ +{num(B2['burden'] - A['burden'], 3)} đợt/replica-giờ",
        [], 'results-20261025/rule-integration/rule-comparison.json')
    for arm, label in (('A', 'A — ML'), ('B1', 'B1 — ML + Falco'), ('B2', 'B2 — ML + tripwire'), ('B3', 'B3 — ML rồi triage probe'),
                       ('B_all', 'B_all')):
        v, m = rc['arms'][arm], rc['arms'][arm]['primary']
        add(f'r6-row-{arm}', rule, f"| {label} | {pct(m['attack'])} ({pct(v['all_rates']['attack'])}) | {pct(m['control'])} "
            f"({m['control_FP']}) | {pct(m['benign'])} | {pct(m['precision'])} | {num(m['p50'], 2)} s | {num(m['p95'], 2)} s "
            f"({num(v['all_rates']['p95'], 2)} s) | {num(v['burden'], 2)} |", [], 'results-20261025/rule-integration/rule-comparison.json')
    d = rc['comparison_primary']['B2']['burden_diff']
    add('r6-b2-burden-ci', rule, f"**+{num(d['point'], 3)} [+{num(d['ci95'][0], 3)}; +{num(d['ci95'][1], 3)}]**", [],
        'results-20261025/rule-integration/rule-comparison.json')
    tw = rc['standalone']['tripwire']
    add('r6-tripwire-alone', rule, f"| Tripwire A1 | {pct(tw['primary']['attack'])} ({pct(tw['all_rates']['attack'])}) |", [],
        'results-20261025/rule-integration/rule-comparison.json')
    add('r6-tripwire-burden', rule, f"| {pct(tw['primary']['control'])} | {pct(tw['primary']['benign'])} | {pct(tw['primary']['precision'])} | "
        f"**{num(tw['burden'], 3)}** |", [], 'results-20261025/rule-integration/rule-comparison.json')
    fb = receipt('results-20261025/rule-integration/falco-baseline.json')
    top = dict(fb['normal']['episodes_by_rule'])['Unexpected connection to K8s API Server from container']
    add('r6-falco-rule', rule, f"**Falco:** {top}/{fb['normal']['episodes']} đợt normal", [], 'results-20261025/rule-integration/falco-baseline.json')
    s2 = receipt('results-20261025/rule-integration-secondary/rule-comparison.json')['comparison_primary']['B2']['burden_diff']
    add('r6-secondary-b2', rule, f"**+{num(s2['point'], 3)} [+{num(s2['ci95'][0], 3)}; +{num(s2['ci95'][1], 3)}]**", [],
        'results-20261025/rule-integration-secondary/rule-comparison.json')
    sc = receipt(f'{CONFIRM}/confirm-campaign.json')['primary']
    add('confirm-fail', pulse, f"**không đạt** (precision {pct(sc['precision'])}, control {pct(sc['control'])}, "
        f"{sc['control_FP']}/{sc['control_FP'] + sc['control_TN']})", [], f'{CONFIRM}/confirm-campaign.json')
    bt = receipt(f'{CONFIRM}/burden-blind-test.json')['metrics']['le3s']
    add('blind-522', todo, f"gánh {num(bt['burden'], 2)}, control {pct(bt['control'])}, precision {pct(bt['precision'])}, "
        f"p95 {num(bt['p95'], 2)} s", [], f'{CONFIRM}/burden-blind-test.json')
    add('benign-range', pulse, f"bị gắn cờ {live_runs_benign_range()} qua 5 lượt live ({pct(c['benign'])} ở lượt cuối)", [],
        'docs/figures/vi/live-runs-table.md (generated from the campaign receipts) + confirm-campaign.json')
    fa = receipt('results-20261021/baselines/fresh/FRESH-ADOPTION.json')['candidates']
    sep = [-v['separation_diff']['point'] for v in fa.values()]
    assert all(v['separation_diff']['ci95'][1] < 0 for v in fa.values())
    add('baselines-fresh', pulse, f"AE và `tree_ae` tăng recall {num(100 * fa['autoencoder']['recall_diff']['point'], 1)} điểm nhưng "
        f"tách binary vô hại kém khoảng {round(100 * sum(sep) / len(sep))} điểm (CI dưới 0)", [],
        'results-20261021/baselines/fresh/FRESH-ADOPTION.json')
    mon, filt = overhead_per_syscall()
    add('overhead', pulse, f"thêm khoảng {mon.replace(' ns', '')} ns mỗi syscall khi container được theo dõi, {filt} khi không", [],
        'results-20261021/overhead/OVERHEAD-AB.json (added ns per op / syscalls per op)')
    lr = receipt('results-20261021/pulse-stable-candidate/label-review.json')
    add('label-review', pulse, f"**Review nhãn (5.20):** {thousands(lr['cases'])} cảnh báo normal, không case nào có dấu hiệu độc hại", [],
        'results-20261021/pulse-stable-candidate/label-review.json')
    add('label-review-shares', pulse, f"| benign_probe | {thousands(lr['counts']['benign_probe'])} | {pct(lr['share']['benign_probe'])} "
        f"({num(100 * lr['share_ci95']['benign_probe'][0], 1)}–{num(100 * lr['share_ci95']['benign_probe'][1], 1)})", [],
        'results-20261021/pulse-stable-candidate/label-review.json')
    cov = receipt(f'{FINAL}/rca-coverage.json'); rk = receipt(f'{FINAL}/rca-ranking-reranked.json')['ranking']
    tax = receipt(f'{FINAL}/alarm-taxonomy.json')
    add('rca-final', rca, f"Attack có case riêng {cov['attack_cases']}/{cov['trials']} ({pct(cov['attack_cases'] / cov['trials'])}); "
        f"top-1 {pct(rk['top1'])}, top-3 {pct(rk['top3'], 0)}; preview → case p95 {num(cov['preview_to_case_seconds']['p95'], 2)} s "
        f"(case attack); {tax['cases']} case normal", [], f'{FINAL}/rca-coverage.json, rca-ranking-reranked.json, alarm-taxonomy.json')
    cc = receipt(f'{CONFIRM}/rca-coverage.json'); ck = receipt(f'{CONFIRM}/rca-ranking-reranked.json')['ranking']
    add('rca-confirm', rca, f"`pulse-stable-confirm` {pct(cc['attack_cases'] / cc['trials'])} / {pct(ck['top1'])} / "
        f"{num(cc['preview_to_case_seconds']['p95'], 2)} s (5.15)", [], f'{CONFIRM}/rca-coverage.json, rca-ranking-reranked.json')
    FS = 'results-20261026/pulse-final-system-confirm'
    fs = receipt(f'{FS}/final-system.json')
    S, A2 = fs['arms']['B2']['primary'], fs['arms']['A']['primary']
    n_ctl = round(S['control_FP'] / S['control'])
    add('final-system-summary', pulse, f"tập chính recall {pct(S['attack'])} ({S['TP']}/{S['TP'] + S['FN']}), precision {pct(S['precision'])}, "
        f"control {pct(S['control'])} ({S['control_FP']}/{n_ctl}), **p95 {num(S['p95'], 2)} s**", [], f'{FS}/final-system.json')
    d = fs['comparison_primary']['B2']['burden_diff']
    add('final-system-burden', pulse, f"S − A = +{num(d['point'], 3)} [+{num(d['ci95'][0], 3)}; +{num(d['ci95'][1], 3)}]", [], f'{FS}/final-system.json')
    ag = receipt(f'{FS}/live-tripwire.json.gz')['agreement']
    add('final-system-agreement', pulse, f"{thousands(ag['judged_windows'])} cửa sổ đã xét, {thousands(ag['live_alert_windows'])} cửa sổ cảnh báo "
        f"ở cả hai, **{ag['live_only'] + ag['offline_only']} cửa sổ khác nhau**", [], f'{FS}/live-tripwire.json.gz')
    cc = receipt(f'{FS}/confirm-campaign.json')['primary']
    add('final-system-ml', pulse, f"recall {pct(cc['recall'])} ({cc['TP']}/{cc['TP'] + cc['FN']}), precision {pct(cc['precision'])}, "
        f"control {pct(cc['control'])} ({cc['control_FP']}/{cc['control_FP'] + cc['control_TN']}), p95 {num(cc['p95'], 2)} s", [], f'{FS}/confirm-campaign.json')
    rc5 = receipt(f'{FS}/rca-coverage.json'); rk5 = receipt(f'{FS}/rca-ranking-reranked.json.gz')['ranking']
    add('rca-final-system', rca, f"| Attack có case riêng | **{rc5['attack_cases']}/{rc5['trials']} ({pct(rc5['attack_cases'] / rc5['trials'])})** |", [],
        f'{FS}/rca-coverage.json')
    add('rca-final-system-rank', rca, f"| Top-1 / top-3 (binary attack là nghi phạm hạng 1 / trong 3 hạng đầu) | **{pct(rk5['top1'])} / {pct(rk5['top3'], 0)}** |", [],
        f'{FS}/rca-ranking-reranked.json.gz')
    rr = receipt(f'{FS}/rca-ranking-reranked-recency.json.gz')['ranking']
    add('rca-recency-dev', rca, f"top-1 **{pct(rk5['top1'])} → {pct(rr['top1'], 0)}** ({round(rr['top1'] * rr['cases'])}/{rr['cases']}), "
        f"top-3 vẫn {pct(rr['top3'], 0)}", [], f'{FS}/rca-ranking-reranked.json.gz, rca-ranking-reranked-recency.json.gz')
    thesis = 'thesis/chapters/evaluation.tex'
    tex = lambda t: t.replace('%', r'\%')
    br = lambda lo, hi, d=2: f"{{[}}{num(100 * lo, d)}; {num(100 * hi, d)}{{]}}"
    # LID-DS 2021 official, development and CB-DS (lidds-ml-v5, token model)
    MLV5 = 'results-20261110/lidds-ml-v5/lidds-ml-v5-official.json'
    mlv5 = receipt(MLV5)
    o = mlv5['official']['pooled']
    add('v5-official-recall', thesis, tex(f"Recall & ≥ 95% & {pct(o['recall'], 2)} ({thousands(o['detected'])}/{thousands(o['attack_recordings'])}) "
        f"{br(*o['recall_ci95'])} \\\\"), [], MLV5)
    add('v5-official-fa', thesis, tex(f"Bản ghi normal bị báo nhầm & báo kèm & {pct(o['false_alarm_rate'], 2)} ({o['false_alarm_recordings']}/"
        f"{thousands(o['normal_recordings'])}) {br(*o['false_alarm_ci95'])} \\\\"), [], MLV5)
    add('v5-official-precision', thesis, tex(f"Precision theo tỉ lệ của dataset & ≥ 95% & {pct(o['precision_base_rate'])} \\\\"), [], MLV5)
    add('v5-official-latency', thesis, f"Độ trễ p50 / p95 & p95 ≤ 3 s & {num(o['latency_p50'], 2)} s / {num(o['latency_p95'], 2)} s \\\\", [], MLV5)
    add('v5-official-3s', thesis, tex(f"Phát hiện trong 3 s & báo kèm & {thousands(o['detected_within_3s'])}/{thousands(o['attack_recordings'])} "
        f"({pct(o['detected_within_3s'] / o['attack_recordings'])}) \\\\"), [], MLV5)
    rb = lambda r: o['recall'] * r / (o['recall'] * r + o['false_alarm_rate'] * (1 - r))
    add('v5-base-rate', thesis, tex(f"precision còn {pct(rb(0.01))} khi bản ghi tấn công chiếm 1% và {pct(rb(0.001))} khi chiếm 0,1%"), [], MLV5)
    sc = mlv5['official']['scenarios']
    macro = sum(v['recall'] for v in sc.values()) / len(sc)
    add('v5-macro', thesis, f"Tính cùng cách, mô hình token đạt {num(macro, 2)}.", [], f'{MLV5} (mean over scenarios)')
    for s_, m in sc.items():
        t = s_.replace('_', r'\_').replace('-', r'-\allowbreak{}')
        add(f'ml-v5-thesis-{s_}', thesis, f"\\texttt{{{t}}} & {m['detected']}/{m['attack_recordings']} & {pct(m['recall'])} & "
            f"{m['false_alarm_recordings']}/{m['normal_recordings']} & {pct(m['false_alarm_rate'], 2)} \\\\".replace('%', r'\%'), [], MLV5)
    DEV5 = 'results-20261110/lidds-ml-v5/lidds-ml-v5-development.json'
    c5 = receipt(DEV5)['candidates']['token-hold0-poolnone']
    d, cb = c5['development'], c5['cbds']
    add('v5-development', thesis, tex(f"{d['detected']}/{d['attack_recordings']} ({pct(d['recall'], 2)}), {d['false_alarm_recordings']}/"
        f"{thousands(d['normal_recordings'])} bản ghi normal bị báo nhầm ({pct(d['false_alarm_rate'], 2)}), p95 {num(d['latency_p95'], 2)} s"), [], DEV5)
    add('v5-cbds', thesis, tex(f"{cb['detected']}/{cb['attack_recordings']}, {cb['false_alarm_recordings']}/{thousands(cb['normal_recordings'])} "
        f"bản ghi normal bị báo nhầm ({pct(cb['false_alarm_rate'], 2)})"), [], DEV5)
    # token alphabets on development (token model alone, alpha 0.002)
    AL = 'results-20261105/ml-exploration/alphabets.txt'
    PO = 'results-20261105/ml-exploration/probe-order.txt'
    rows = {}
    for f in (AL, PO):
        for line in (EV/f).read_text().splitlines():
            parts = line.split('|')
            if len(parts) == 4 and parts[0].strip() and not parts[0].startswith('alphabet'):
                det, rec, fa, p95 = parts[1].split()
                rows[parts[0].strip()] = (int(det.split('/')[0]), float(rec[:-1]), float(fa[:-1]), float(p95[:-1]))
    for key, label in (('probe1f', r'\texttt{probe1f}: \texttt{select1f} theo thứ tự probe phát'), ('full', 'Đầy đủ'),
                       ('noerr', 'Bỏ mã lỗi'), ('noopen', 'Bỏ chế độ mở và thư mục'), ('req', 'Cỡ yêu cầu lúc vào thay cỡ trả về'),
                       ('nosize', 'Bỏ cỡ đọc ghi'), ('open_only', 'Chỉ thông tin open'), ('name', 'Chỉ tên syscall')):
        k, r, f_, q = rows[key]
        add(f'alphabet-{key}', thesis, tex(f"{label} & {k} ({num(r, 2)}%) & {num(f_, 2)}% & {num(q, 2)} s \\\\"), [], f'{AL}, {PO}')
    k, r, f_, q = rows['select1f']
    add('alphabet-select1f', thesis, tex(f"\\textbf{{\\texttt{{select1f}}}} (đang dùng) & \\textbf{{{k} ({num(r, 2)}%)}} & \\textbf{{{num(f_, 2)}%}} & "
        f"\\textbf{{{num(q, 2)} s}} \\\\"), [], PO)
    # live run pulse-live-v4-1109, token model (arm T)
    LIVE = 'results-20261110/pulse-live-v4-1109/arms.json'
    live = receipt(LIVE)
    T = live['arms']['T']
    p_, b_ = T['primary'], T['burden']
    add('live-recall', thesis, f"Recall & ≥ 95\\% & {p_['attack']['hits']}/{p_['attack']['n']} {br(*p_['attack']['ci95'], 1)} \\\\", [], LIVE)
    add('live-precision', thesis, tex(f"Precision & ≥ 95% & {pct(p_['precision']['rate'], 2)} {br(*p_['precision']['ci95'])} \\\\"), [], LIVE)
    add('live-control', thesis, tex(f"Control dương & ≤ 5% & {p_['control']['hits']}/{p_['control']['n']} ({pct(p_['control']['rate'], 2)}) "
        f"{br(*p_['control']['ci95'])} \\\\"), [], LIVE)
    add('live-p95', thesis, f"{num(p_['latency_p95'], 2)} s (p50 {num(p_['latency_p50'], 2)} s) \\\\", [], LIVE)
    add('live-benign', thesis, f"Binary vô hại bị gắn cờ & báo kèm & {p_['benign']['hits']}/{p_['benign']['n']} \\\\", [], LIVE)
    add('live-burden', thesis, f"Gánh cảnh báo (đợt/replica-giờ) & thấp nhất có thể & {num(b_['value'], 2)} {br(*b_['ci95'])}".replace(
        f"{{[}}{num(100 * b_['ci95'][0], 2)}; {num(100 * b_['ci95'][1], 2)}{{]}}", f"{{[}}{num(b_['ci95'][0], 2)}; {num(b_['ci95'][1], 2)}{{]}}"), [], LIVE)
    add('live-burden-episodes', thesis, f"{b_['episodes']} đợt trên {num(b_['replica_hours'], 1)} replica-giờ normal", [], LIVE)
    al = T['all_rates']
    assert all(v['hits'] == v['n'] == 105 for v in T['recall_by_rate'].values())
    add('live-all-rates', thesis, f"mô hình bắt {al['attack']['hits']}/{al['attack']['n']} trial (105/105 ở từng tốc độ", [], LIVE)
    add('live-all-control', thesis, f"control dương là {al['control']['hits']}/{al['control']['n']}", [], LIVE)
    add('live-all-benign', thesis, f"{p_['benign']['hits']}/{p_['benign']['n']} trial tập chính và {al['benign']['hits']}/{al['benign']['n']} trial mọi tốc độ", [], LIVE)
    hard = p_['attack']['hits'] / (p_['attack']['hits'] + p_['control']['hits'] + p_['benign']['hits'])
    add('token-live-hard-precision', thesis, tex(f"{pct(hard)} ({p_['attack']['hits']}/({p_['attack']['hits']} + "
        f"{p_['control']['hits']} + {p_['benign']['hits']}))"), [], LIVE)
    sl = live['scoring_latency']['token']
    add('live-scoring', thesis, f"Worker chấm cửa sổ thêm p50 {num(sl['p50'], 2)} s, p95 {num(sl['p95'], 2)} s", [], LIVE)
    # held-out block exceedance of the fits
    F4, F5 = 'results-20261109/pulse-live-v4-fit/token-FIT.json', 'results-20261111/pulse-live-v5-fit/token-FIT.json'
    def exceed(f):
        w = receipt(f)['workloads']
        return sum(int(v['validation_blocks_above']) for v in w.values()), sum(int(v['validation_blocks']) for v in w.values())
    k4, n4 = exceed(F4); k5, n5 = exceed(F5)
    design = 0.0002 * 0.9
    add('fit-exceed-v4', thesis, tex(f"{k4}/{thousands(n4)} khối 60 s ({pct(k4 / n4, 3)}) vượt ngưỡng, gấp {num(k4 / n4 / design, 1)} lần mức thiết kế "
        f"{pct(design, 3)}"), [], F4)
    add('fit-exceed-v5', thesis, tex(f"{k5}/{thousands(n5)} ({pct(k5 / n5, 3)})"), [], F5)
    # probe overhead (token-probe-overhead-v1 amendment 2, condition tokD against off)
    OV = 'results-20261107/token-probe-overhead/overhead-run3.json'
    nodes = receipt(OV)['nodes']
    rng = lambda xs, d=0: f"{thousands(round(min(xs))) if d == 0 else num(min(xs), d)}--{thousands(round(max(xs))) if d == 0 else num(max(xs), d)}"
    for op, label in (('getpid', r'\texttt{getpid}'), ('read4k', r'\texttt{read} 4 KB'), ('futex', r'\texttt{futex}'),
                      ('openclose', r'\texttt{open} + \texttt{close}'), ('mmapunmap', r'\texttt{mmap} + \texttt{munmap}')):
        v = [nodes[n][op] for n in nodes]
        off = [x['median_ns_per_op']['off'] for x in v]
        add_ = [x['tokD_overhead']['added_ns_per_op'] for x in v]
        rel = [100 * x['tokD_overhead']['relative'] for x in v]
        unm = [x['tokD_filtered_overhead']['added_ns_per_op'] for x in v]
        relr = f"{round(min(rel))}--{round(max(rel))}"
        add(f'overhead-{op}', thesis, f"{label} & {rng(off)} & {rng(add_)} & {relr} & {rng(unm)} \\\\", [], OV)
    # the four status reports were removed on 07/11 (owner); their claims are retired, the LaTeX and TODO claims stay
    return [c for c in out if c['doc'] not in RETIRED]


RETIRED = {'SENTINEL_PULSE_STATUS.md', 'RULE_INTEGRATION_STATUS.md', 'RCA_RUNTIME_STATUS.md'}


def run(read=lambda doc: (ROOT/doc).read_text()):
    rows, failures = [], 0
    for c in claims():
        text = read(c['doc'])
        present = c['snippet'] in text
        missing = [v for v in c['values'] if v not in c['snippet']]
        ok = present and not missing
        failures += not ok
        rows.append(dict(c, ok=ok, present=present, missing=missing))
    return rows, failures


def markdown(rows):
    out = ['| Mã | Báo cáo | Câu được kiểm (tính lại từ biên nhận) | Biên nhận | Khớp |', '|---|---|---|---|---|']
    for r in rows:
        out.append(f"| `{r['id']}` | {r['doc']} | {r['snippet'].replace('|', '¦')} | `{r['source']}` | {'có' if r['ok'] else '**KHÔNG**'} |")
    return '\n'.join(out) + '\n'


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--markdown', type=Path, help='write the audit table here')
    a = ap.parse_args()
    rows, failures = run()
    for r in rows:
        if not r['ok']:
            print(f"FAIL {r['id']} ({r['doc']}): {'sentence not found' if not r['present'] else 'values ' + str(r['missing'])}\n"
                  f"     expected: {r['snippet']}")
    print(f'{len(rows) - failures}/{len(rows)} claims match their receipts')
    if a.markdown:
        a.markdown.write_text(markdown(rows))
    raise SystemExit(1 if failures else 0)


if __name__ == '__main__':
    main()
