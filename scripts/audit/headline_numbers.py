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
    # the two live runs, token model (arm T): pulse-live-v4-1109 and pulse-live-v5-1110 (registered analysis, all pairs)
    LIVE = 'results-20261110/pulse-live-v4-1109/arms.json'
    LIVE5 = 'results-20261112/pulse-live-v5-1110/arms.json'
    T4, T5 = receipt(LIVE)['arms']['T'], receipt(LIVE5)['arms']['T']
    p4, p5 = T4['primary'], T5['primary']
    frac = lambda x: f"{x['hits']}/{x['n']}"
    add('live-recall', thesis, f"Recall & ≥ 95\\% & {frac(p4['attack'])} {br(*p4['attack']['ci95'], 1)} & {frac(p5['attack'])} {br(*p5['attack']['ci95'], 1)} \\\\",
        [], f'{LIVE}, {LIVE5}')
    prec = lambda p: f"{pct(p['precision']['rate'], 2) if p['precision']['rate'] < 1 else '100%'} {br(*p['precision']['ci95'])}"
    add('live-precision', thesis, tex(f"Precision & ≥ 95% & {prec(p4)} & {prec(p5)} \\\\"), [], f'{LIVE}, {LIVE5}')
    ctl = lambda p: f"{frac(p['control'])}" + (f" ({pct(p['control']['rate'], 2)})" if p['control']['hits'] else '') + f" {br(*p['control']['ci95'])}"
    add('live-control', thesis, tex(f"Control dương & ≤ 5% & {ctl(p4)} & {ctl(p5)} \\\\"), [], f'{LIVE}, {LIVE5}')
    add('live-p95', thesis, f"{num(p4['latency_p95'], 2)} s (p50 {num(p4['latency_p50'], 2)} s) & {num(p5['latency_p95'], 2)} s (p50 {num(p5['latency_p50'], 2)} s) \\\\",
        [], f'{LIVE}, {LIVE5}')
    add('live-benign', thesis, f"Binary vô hại bị gắn cờ & báo kèm & {frac(p4['benign'])} & {frac(p5['benign'])} \\\\", [], f'{LIVE}, {LIVE5}')
    add('live-admin', thesis, f"Lệnh quản trị bị gắn cờ & báo kèm & không có & {frac(p5['admin'])} \\\\", [], LIVE5)
    b4, b5 = T4['burden'], T5['burden']
    bb = lambda b: f"{num(b['value'], 2)} {{[}}{num(b['ci95'][0], 2)}; {num(b['ci95'][1], 2)}{{]}}"
    add('live-burden', thesis, f"Gánh cảnh báo (đợt/replica-giờ) & thấp nhất có thể & {bb(b4)} & {bb(b5)} \\\\", [], f'{LIVE}, {LIVE5}')
    add('live-burden-episodes', thesis, f"từ {b4['episodes']} đợt trên {num(b4['replica_hours'], 1)} replica-giờ ({num(b4['value'], 2)}) xuống "
        f"{b5['episodes']} đợt trên {num(b5['replica_hours'], 1)} replica-giờ ({num(b5['value'], 2)})", [], f'{LIVE}, {LIVE5}')
    a4, a5 = T4['all_rates'], T5['all_rates']
    add('live-all-rates', thesis, f"lượt 1109 bắt {frac(a4['attack'])} trial và lượt v5 bắt {frac(a5['attack'])}", [], f'{LIVE}, {LIVE5}')
    add('live-all-control', thesis, f"control dương là {frac(a4['control'])} và {frac(a5['control'])}", [], f'{LIVE}, {LIVE5}')
    add('live-all-benign', thesis, f"{frac(p4['benign'])} trial tập chính ở lượt 1109 và {frac(p5['benign'])} ở lượt v5; mọi tốc độ "
        f"{frac(a4['benign'])} và {frac(a5['benign'])}", [], f'{LIVE}, {LIVE5}')
    add('live-admin-all', thesis, tex(f"{frac(p5['admin'])} ở tập chính, {frac(a5['admin'])} ở mọi tốc độ ({pct(a5['admin']['rate'])})"), [], LIVE5)
    hard = p5['attack']['hits'] / (p5['attack']['hits'] + p5['control']['hits'] + p5['benign']['hits'])
    add('token-live-hard-precision', thesis, tex(f"{pct(hard)} ({p5['attack']['hits']}/({p5['attack']['hits']} + "
        f"{p5['control']['hits']} + {p5['benign']['hits']}))"), [], LIVE5)
    sl = receipt(LIVE)['scoring_latency']['token']
    add('live-scoring', thesis, f"Worker chấm cửa sổ thêm p50 {num(sl['p50'], 2)} s, p95 {num(sl['p95'], 2)} s", [], LIVE)
    W = 'results-20261112/pulse-live-v5-1110/worker-cpu.txt'
    import re
    hours = [int(h) + int(mi) / 60 + float(se) / 3600 for h, mi, se in re.findall(r'Consumed (\d+)h (\d+)min ([\d.]+)s', (EV/W).read_text())]
    add('worker-cpu', thesis, f"tức trung bình {num(min(hours) / 24, 2)}--{num(max(hours) / 24, 2)} core trên node 24 core", [], W)
    # alert path and RCA of pulse-live-v5-1110
    DL = 'results-20261112/pulse-live-v5-1110/delivery-latency.json'
    dl = receipt(DL)['summary']
    pr = [v['p95'] for v in dl['push_by_rate'].values()]
    add('delivery-push', thesis, f"cảnh báo tới nơi ở {dl['push']['trials_alerted']}/{dl['attack_trials']} trial, p50 {num(dl['push']['p50'], 2)} s, "
        f"p95 {num(dl['push']['p95'], 2)} s; theo từng tốc độ p95 từ {num(min(pr), 2)} tới {num(max(pr), 2)} s", [], DL)
    add('delivery-pull', thesis, f"chu kỳ nhanh p50 {num(dl['pull-fast']['p50'], 2)} s; chu kỳ mặc định p50 {num(dl['pull-default']['p50'], 1)} s và chỉ kịp ở "
        f"{dl['pull-default']['trials_alerted']}/{dl['attack_trials']} trial", [], DL)
    BD = 'results-20261112/pulse-live-v5-1110/bridge-delivery.json'
    bd = receipt(BD)
    o, i = bd['outside_stall'], bd['inside_stall']
    add('bridge-delivered', thesis, f"cả {thousands(o['delivered'])}/{thousands(o['episodes'])} đợt cảnh báo của lượt đều tới Alertmanager, với thời gian từ decision "
        f"tới lúc nhận p50 {num(o['decision_to_receipt_seconds']['p50'], 3)} s, p95 {num(o['decision_to_receipt_seconds']['p95'], 3)} s. Trong 3,5 phút nghẽn, "
        f"{i['not_delivered']}/{i['episodes']} đợt không tới", [], BD)
    RC = 'results-20261112/pulse-live-v5-1110/rca-coverage.json'
    rc = receipt(RC)
    top1 = round(rc['stored_rank_top1'] * rc['attack_cases'])
    add('rca-own-case', thesis, tex(f"Tấn công có case riêng & {rc['attack_cases']}/{rc['trials']} ({pct(rc['attack_cases'] / rc['trials'])}) \\\\"), [], RC)
    add('rca-top1', thesis, tex(f"Binary tấn công đứng hạng 1 trong case & {top1}/{rc['attack_cases']} ({pct(rc['stored_rank_top1'])}) \\\\"), [], RC)
    add('rca-latency', thesis, f"Cảnh báo → case, p50 / p95 & {num(rc['preview_to_case_seconds']['p50'], 2)} s / {num(rc['preview_to_case_seconds']['p95'], 2)} s \\\\", [], RC)
    RF = 'results-20261112/pulse-live-v5-1110/rca-follow-up.json'
    rf = receipt(RF)
    al = rf['exec_lag_seconds']['attack_binary']
    add('rca-exec-lag', thesis, f"Độ trễ sự kiện exec của binary tấn công, p95 / lớn nhất & {num(al['p95'], 2)} s / {num(al['max'], 2)} s \\\\", [], RF)
    miss = rf['attack_trials'] - rf['classes']['own_case']
    add('rca-missing', thesis, f"\\textbf{{{miss} tấn công không có case riêng}}", [], RF)
    add('rca-known', thesis, f"ở {rf['classes']['exec_known_refused']}/{miss} trường hợp, exec của binary tấn công đã có trong nhật ký", [], RF)
    # token design study (development) and the declared official scoring
    DS = 'results-20261112/token-design-study/'
    q1 = receipt(DS + 'q1.json'); base = q1['base']
    for unit, label in (('write', r'\texttt{write}'), ('open', r'\texttt{open}')):
        r = q1['leave_one_out'][unit]
        add(f'loo-{unit}', thesis, f"{label} & {r['detected']} ($-${base['detected'] - r['detected']})", [], DS + 'q1.json')
    add('loo-counts', thesis, f"{len(q1['absent_from_data'])} trong 39 syscall không xuất hiện trong dữ liệu", [], DS + 'q1.json')
    changed = sum(1 for r in q1['leave_one_out'].values() if (r['detected'], r['false_alarm_recordings']) != (base['detected'], base['false_alarm_recordings']))
    add('loo-changed', thesis, f"Trong {len(q1['leave_one_out'])} syscall còn lại, chỉ {changed} làm đổi kết quả", [], DS + 'q1.json')
    add('subset-size', thesis, f"Sau {len(q1['elimination'])} lần chấm, {len(q1['removed'])} syscall bị loại và còn lại \\textbf{{{len(q1['smallest_subset'])}}}", [], DS + 'q1.json')
    add('add-one', thesis, f"{len(q1['add_one'])} ứng viên có dữ liệu được thêm lần lượt", [], DS + 'q1.json')
    OF = DS + 'official-smallest-subset.json'
    of = receipt(OF)
    add('subset-official', thesis, f"phát hiện {thousands(of['subset']['detected'])}/{thousands(of['subset']['attack_recordings'])} với "
        f"{of['subset']['false_alarm_recordings']}/{thousands(of['subset']['normal_recordings'])} báo nhầm", [], OF)
    q2 = receipt(DS + 'q2.json')['grid']
    cell = lambda v, r, bold: (r'\textbf{' if bold else '') + f"{v}: {r['detected']} / {r['false_alarm_recordings']}" + ('}' if bold else '')
    add('grid-n', thesis, 'Độ dài gram & ' + r' \quad '.join(cell(k, r, k == '4') for k, r in q2['n'].items()) + r' \\', [], DS + 'q2.json')
    add('grid-top', thesis, 'Số giá trị lấy trung bình & ' + r' \quad '.join(cell(k, r, k == '10') for k, r in q2['top'].items()) + r' \\', [], DS + 'q2.json')
    q3 = receipt(DS + 'q3.json')
    reg = q3['alternatives_at_false_alarm_budgets']['gumbel moments, trimmed (registered)']
    add('threshold-registered', thesis, r'\textbf{Gumbel theo moment, bỏ 1\% (đang dùng)} & ' + ' & '.join(rf'\textbf{{{reg[b][1]}}}' for b in ('6', '12', '20')) + r' \\',
        [], DS + 'q3.json')
    c18 = next(c for c in q3['calibration'] if abs(c['alpha'] - 0.00018) < 1e-9)
    add('calibration', thesis, f"ở $\\alpha' = 0{{,}}00018$ kỳ vọng {num(c18['expected'], 1)} và thấy {c18['observed']} ({num(c18['ratio'], 1)} lần)", [], DS + 'q3.json')
    add('ad-rejected', thesis, f"bác giả thiết Gumbel cho cực đại giữ ra ở {q3['rejected_after_holm']}/{len(q3['scenarios'])} kịch bản", [], DS + 'q3.json')
    q4 = receipt(DS + 'q4.json')
    bm, br_ = q4['at_false_alarm_budgets']['model'], q4['at_false_alarm_budgets']['unseen_grams']
    add('rule-6', thesis, f"$\\leq$ 6 & {bm['6'][1]} & {br_['6'][1]} \\\\", [], DS + 'q4.json')
    pd = q4['paired']['unseen_grams']
    add('rule-paired', thesis, f"mô hình phát hiện nhiều hơn {pd['difference']} bản ghi, khoảng tin cậy 95\\% [{round(pd['ci95'][0])}; {round(pd['ci95'][1])}]", [], DS + 'q4.json')
    so = q4['seen_only_simulation']['pooled']
    add('seen-only', thesis, f"Mô hình phát hiện {so['detected_seen_only']}/{so['attack_recordings']} bản ghi (trước khi bỏ: {so['detected']})", [], DS + 'q4.json')
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
