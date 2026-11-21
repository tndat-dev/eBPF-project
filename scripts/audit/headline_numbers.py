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
# KIỂM TOÁN SỐ LIỆU: mỗi "câu khẳng định" = một câu nguyên văn trong đồ án + các số tính lại từ biên nhận; câu bị sửa mà
# không cập nhật kiểm toán, hoặc số lệch biên nhận, đều làm test thất bại.
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
    pc2 = lambda x: num(100 * x, 2)
    T3 = 'results-20261118/lidds2019-development/official2021.json'
    t3 = receipt(T3)['chosen']
    t3r, t3f = t3['detected'] / t3['attack_recordings'], t3['false_alarm_recordings'] / t3['normal_recordings']
    both = f'{MLV5}, {T3}'
    add('v5-official-recall', thesis, tex(f"Recall & ≥ 95% & {pct(o['recall'], 2)} ({thousands(o['detected'])}/{thousands(o['attack_recordings'])}) "
        f"{br(*o['recall_ci95'])} & {pct(t3r, 2)} ({thousands(t3['detected'])}/{thousands(t3['attack_recordings'])}) {br(*t3['recall_ci95'])} \\\\"), [], both)
    add('v5-official-fa', thesis, tex(f"Bản ghi normal bị báo nhầm & báo kèm & {pct(o['false_alarm_rate'], 2)} ({o['false_alarm_recordings']}/"
        f"{thousands(o['normal_recordings'])}) {br(*o['false_alarm_ci95'])} & {pct(t3f, 2)} ({t3['false_alarm_recordings']}/"
        f"{thousands(t3['normal_recordings'])}) {br(*t3['false_alarm_ci95'])} \\\\"), [], both)
    t3p = t3['detected'] / (t3['detected'] + t3['false_alarm_recordings'])
    add('v5-official-precision', thesis, tex(f"Precision theo tỉ lệ của dataset & ≥ 95% & {pct(o['precision_base_rate'])} & {pct(t3p)} \\\\"), [], both)
    add('v5-official-latency', thesis, f"Độ trễ p50 / p95 & p95 ≤ 3 s & {num(o['latency_p50'], 2)} s / {num(o['latency_p95'], 2)} s & "
        f"{num(t3['latency_p50'], 2)} s / {num(t3['latency_p95'], 2)} s \\\\", [], both)
    add('v5-official-3s', thesis, tex(f"Phát hiện trong 3 s & báo kèm & {thousands(o['detected_within_3s'])}/{thousands(o['attack_recordings'])} "
        f"({pct(o['detected_within_3s'] / o['attack_recordings'])}) & {thousands(t3['detected_within_3s'])}/{thousands(t3['attack_recordings'])} "
        f"({pct(t3['detected_within_3s'] / t3['attack_recordings'])}) \\\\"), [], both)
    rb = lambda r: o['recall'] * r / (o['recall'] * r + o['false_alarm_rate'] * (1 - r))
    rb3 = lambda r: t3r * r / (t3r * r + t3f * (1 - r))
    add('v5-base-rate', thesis, tex(f"precision còn {pct(rb3(0.01))} khi bản ghi tấn công chiếm 1% và {pct(rb3(0.001))} khi chiếm 0,1% "
        f"(v5: {pct(rb(0.01))} và {pct(rb(0.001))})"), [], both)
    sc = mlv5['official']['scenarios']
    macro = sum(v['recall'] for v in sc.values()) / len(sc)
    macro3 = sum(t3['scenarios'][k][0] / v['attack_recordings'] for k, v in sc.items()) / len(sc)
    assert num(macro, 2) == num(macro3, 2)
    add('v5-macro', thesis, f"Tính cùng cách, mô hình token đạt {num(macro, 2)} ở cả hai cấu hình.", [], f'{both} (mean over scenarios)')
    for s_, m in sc.items():
        t = s_.replace('_', r'\_').replace('-', r'-\allowbreak{}')
        d3, f3 = t3['scenarios'][s_]
        add(f'ml-v5-thesis-{s_}', thesis, f"\\texttt{{{t}}} & {m['detected']}/{m['attack_recordings']} & {d3}/{m['attack_recordings']} & "
            f"{m['false_alarm_recordings']}/{m['normal_recordings']} & {f3}/{m['normal_recordings']} \\\\", [], both)
    HO = 'results-20261118/lidds2019-development/holdout.json'
    ho = receipt(HO)
    hc, hv = ho['chosen']['tolerance'], ho['lidds_ml_v5']['tolerance']
    add('t3-holdout', thesis, f"t3 phát hiện \\textbf{{{hc['detected']}/{hc['attack_recordings']} ({pc2(hc['recall'])}\\%, CI {{[}}"
        f"{pc2(hc['recall_ci95'][0])}; {pc2(hc['recall_ci95'][1])}{{]}})}} với dung sai 1 s, {hc['false_alarm_recordings']}/"
        f"{thousands(hc['normal_recordings'])} bản ghi normal bị báo nhầm ({pc2(hc['false_alarm_rate'])}\\%), p95 {num(hc['latency_p95'], 2)} s; "
        f"v5 trên cùng bản ghi là {hv['detected']}/{hv['attack_recordings']} ({pc2(hv['recall'])}\\%), {hv['false_alarm_recordings']} báo nhầm, "
        f"p95 {num(hv['latency_p95'], 2)} s", [], HO)
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
    FIN = 'results-20261121/pulse-live-final-1119'
    TF = receipt(f'{FIN}/pulse-live-final.json')['arms']['T']
    pf, af = TF['primary'], TF['all_rates']
    add('live-all-benign', thesis, f"{frac(p4['benign'])} trial tập chính ở lượt 1109, {frac(p5['benign'])} ở lượt v5 và {frac(pf['benign'])} ở lượt cuối (t3); "
        f"mọi tốc độ {frac(a4['benign'])}, {frac(a5['benign'])} và {frac(af['benign'])}", [], f'{LIVE}, {LIVE5}, {FIN}/pulse-live-final.json')
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
    # ml-final-study-v1 parts B, B2, B3 (thesis RQ4, lineage subsection)
    MF = 'results-20261113/ml-final-study'
    lb = receipt(f'{MF}/live-attribution.json')['B']
    ho, iv = lb['held_out_admin_all'], lb['intervals']
    kn = lambda x: f"{x['k']}/{x['n']}"
    add('b-held-out-admin', thesis, tex(f"lệnh bị giữ ra vẫn bị gắn cờ {kn(ho['operator'])} lần ({pct(ho['operator']['rate'])}), so với "
        f"{kn(ho['v5'])} ({pct(ho['v5']['rate'])}) của mô hình v5"), [], f'{MF}/live-attribution.json')
    add('b-learnt-cost', thesis, f"recall tập chính giảm từ {kn(iv['attack-primary']['v5'])} xuống {kn(iv['attack-primary']['operator'])} "
        f"và tấn công theo đúng hành vi riêng của nó (bỏ các gram đã có trong khoảng vô hại cùng trial) còn "
        f"{kn(iv['attack-specific-primary']['operator'])}", [], f'{MF}/live-attribution.json')
    sm = receipt(f'{MF}/session-model.json')
    b2, b3 = sm['B2']['held_out_admin']['known'], sm['B3']
    add('b2-held-out-admin', thesis, tex(f"cũng chỉ hạ còn {kn(b2)} ({pct(b2['rate'])})"), [], f'{MF}/session-model.json')
    na = b3['native_arm']
    add('b3-native', thesis, f"control bị gắn cờ {kn(na['control'])}, lệnh quản trị {kn(na['admin'])} và binary vô hại {kn(na['benign'])}",
        [], f'{MF}/session-model.json')
    add('b3-session-threshold', thesis, f"cho ngưỡng {num(b3['known_tools']['threshold'], 1)} (và {num(b3['learnt_program']['threshold'], 1)} "
        f"khi học cả binary vô hại)", [], f'{MF}/session-model.json')
    assert b3['attack_tools_only']['all'] == b3['attack_program_learnt']['all']
    add('b3-session-attack', thesis, f"nó bắt {kn(b3['attack_tools_only']['all'])} tấn công", [], f'{MF}/session-model.json')
    # lineage tag cost (token-probe-overhead-v1 amendment 3)
    LO = 'results-20261116/lineage-overhead/overhead-lineage.json'
    ln = receipt(LO)['nodes']
    cells = [(n, op, ln[n][op]['tokD_vs_tokD_base']) for n in ln for op in ln[n]]
    away = [(n, op, r) for n, op, r in cells if not r['ci95'][0] <= 0 <= r['ci95'][1]]
    assert len(cells) == 12 and len(away) == 1 and away[0][2]['ci95'][1] < 0
    n1, op1, r1 = away[0]
    fork = [ln[n]['forkwait']['median_ns_per_op'][c] / 1000 for n in ln for c in ('off', 'tokD_base', 'tokD')]
    add('lineage-cost', thesis, f"trừ một ô âm (\\texttt{{{op1}}} trên {n1.split('.')[0].replace('k8s-', '')}, $-${num(-100 * r1['relative'], 1)}\\%). "
        f"Một lần fork + exit + wait tốn {round(min(fork))}--{round(max(fork))} µs", [], LO)
    # gram map capacity (map-capacity-v1) and the v5 load (ml-final-study token_load)
    MC = 'results-20261116/map-capacity/RESULTS.json'
    lv = {r['offered_calls_per_second']: r for r in receipt(MC)['levels']}
    first = min(k for k, r in lv.items() if r['failed_inserts'])
    assert all(not r['failed_inserts'] for k, r in lv.items() if k < first)
    for k, r in sorted(lv.items()):
        add(f'map-capacity-{k}', thesis, f"{thousands(k)} & {thousands(round(r['distinct_grams_per_window']['p50']))} & "
            f"{thousands(r['failed_inserts'])} & {num(r['drain_seconds']['p50'], 2)} s \\\\", [], MC)
    below = lv[max(k for k in lv if k < first)]
    add('map-capacity-first-loss', thesis, f"Map bắt đầu bỏ gram ở {thousands(first)} syscall/s trên một cgroup; tới {thousands(max(k for k in lv if k < first))} "
        f"syscall/s, khoảng {thousands(round(below['distinct_grams_per_window']['p50']))} gram mỗi cửa sổ, chưa mất gram nào", [], MC)
    add('map-capacity-drain', thesis, f"{num(below['drain_seconds']['p50'], 2)} s (lâu nhất {num(below['drain_seconds']['max'], 2)} s) ở "
        f"{thousands(max(k for k in lv if k < first))} syscall/s, còn ở {thousands(first)} syscall/s lần đọc lâu nhất là "
        f"{num(lv[first]['drain_seconds']['max'], 2)} s, vượt nhịp 0,5 s", [], MC)
    tl = receipt(f'{MF}/token-load.json')['node_window']['distinct_grams']['max']
    add('map-capacity-v5-load', thesis, f"Cửa sổ nặng nhất của cả node ở lượt v5 chỉ có {thousands(round(tl))} gram", [], f'{MF}/token-load.json')
    # model aging (pulse-live-v6-v1 amendment 1)
    MA = 'results-20261117/model-aging/model-aging.json'
    ag = receipt(MA)
    p, h = ag['pooled'], ag['pooled']['v5_heldout']
    w1, w2 = wilson(p['above'], p['blocks']), wilson(h['above'], h['blocks'])
    pc = lambda x: num(100 * x, 2)
    add('aging-pooled', 'thesis/chapters/discussion.tex',
        f"{p['above']}/{thousands(p['blocks'])} khối 60 s của container ({pc(p['rate'])}\\%, khoảng tin cậy 95\\% {pc(w1[0])}--{pc(w1[1])}\\%) "
        f"vượt ngưỡng, so với {h['above']}/{thousands(h['blocks'])} ({pc(h['rate'])}\\%, {pc(w2[0])}--{pc(w2[1])}\\%) trên dữ liệu giữ ra "
        f"của chính v5: gấp khoảng {num(p['rate'] / h['rate'], 1)} lần", [], MA)
    rd = ag['workloads']['production/aims-redis:aims-redis']
    add('aging-redis', 'thesis/chapters/discussion.tex', f"Redis {rd['above']}/{thousands(rd['blocks'])} ({pc(rd['rate'])}\\%, trước đó "
        f"{pc(rd['v5_heldout']['rate'])}\\%)", [], MA)
    # third live run pulse-live-v6-1117 (pulse-live-v6-v1 + amendment 1): table tab:token-live-v6, native stream, rule harm, RCA
    V6 = 'results-20261118/pulse-live-v6-1117'
    T6 = receipt(f'{V6}/pulse-live-v6.json.gz')['arms']['T']
    p6, a6, d6, b6 = T6['primary'], T6['all_rates'], T6['dilution'], T6['burden']
    n2 = lambda x: num(x, 2)
    add('v6-recall', thesis, f"Recall & ≥ 95\\% & {frac(p6['attack'])} {br(*p6['attack']['ci95'], 1)} & {frac(a6['attack'])} \\\\", [], V6)
    add('v6-precision', thesis, f"Precision & ≥ 95\\% & {n2(100 * p6['precision']['rate'])}\\% {br(*p6['precision']['ci95'])} & "
        f"{n2(100 * a6['precision']['rate'])}\\% \\\\", [], V6)
    add('v6-control', thesis, f"Control dương & ≤ 5\\% & {frac(p6['control'])} ({n2(100 * p6['control']['rate'])}\\%) {br(*p6['control']['ci95'])} & "
        f"{frac(a6['control'])} \\\\", [], V6)
    add('v6-p95', thesis, f"p95 kernel → cuối cửa sổ báo & ≤ 3 s & {n2(p6['latency_p95'])} s (p50 {n2(p6['latency_p50'])} s) & "
        f"{n2(a6['latency_p95'])} s \\\\", [], V6)
    add('v6-benign', thesis, f"Binary vô hại bị gắn cờ & báo kèm & {frac(p6['benign'])} & {frac(a6['benign'])} \\\\", [], V6)
    add('v6-admin', thesis, f"Lệnh quản trị chưa từng thấy bị gắn cờ & báo kèm & {frac(p6['admin'])} & {frac(a6['admin'])} "
        f"({num(100 * a6['admin']['rate'], 1)}\\%) \\\\", [], V6)
    add('v6-lotl', thesis, f"Tấn công bằng tool của image (lotl) bị bắt & báo kèm & {frac(p6['lotl'])} & {frac(a6['lotl'])} \\\\", [], V6)
    add('v6-dilution', thesis, f"\\multicolumn{{2}}{{l}}{{{frac(d6['pad30']['attack'])} / {frac(d6['pad300']['attack'])}}} \\\\", [], V6)
    add('v6-burden', thesis, f"{b6['episodes']} đợt trên {num(b6['replica_hours'], 1)} replica-giờ ({n2(b6['value'])} {{[}}{n2(b6['ci95'][0])}; "
        f"{n2(b6['ci95'][1])}{{]}})", [], V6)
    ns = receipt(f'{V6}/native-stream.json')['intervals']
    nf = receipt('results-20261121/pulse-live-final-1119/native-stream-h0pairs.json')['intervals']
    kn = lambda x: f"{x['k']}/{x['n']}"
    for key, label in (('control', 'Control'), ('admin', 'Lệnh quản trị (bộ v6)'), ('benign', 'Binary vô hại'),
                       ('attack', 'Tấn công (fixture)'), ('lotl', 'Tấn công bằng tool của image')):
        add(f'v6-native-{key}', thesis, f"{label} & {kn(ns[key]['whole'])} & {kn(ns[key]['native'])} & {kn(nf[key]['whole'])} & "
            f"{kn(nf[key]['native'])} \\\\", [], f'{V6}/native-stream.json, results-20261121/pulse-live-final-1119/native-stream-h0pairs.json')
    add('final-native-eventgen', thesis, f"Event-generator & -- & -- & {kn(nf['eventgen']['whole'])} & {kn(nf['eventgen']['native'])} \\\\", [],
        'results-20261121/pulse-live-final-1119/native-stream-h0pairs.json')
    # final run (pulse-live-final-v1), token model t3, arm T
    FR = 'results-20261121/pulse-live-final-1119/pulse-live-final.json'
    dl, rr, bf = TF['dilution'], TF['recall_by_rate'], TF['burden']
    add('final-recall', thesis, f"Recall & ≥ 95\\% & {frac(pf['attack'])} {br(*pf['attack']['ci95'], 1)} & {frac(af['attack'])} \\\\", [], FR)
    add('final-precision', thesis, f"Precision & ≥ 95\\% & 100\\% {br(*pf['precision']['ci95'], 1)} & 100\\% \\\\", [], FR)
    add('final-control', thesis, f"Control dương & ≤ 5\\% & {frac(pf['control'])} {br(*pf['control']['ci95'], 1)} & {frac(af['control'])} \\\\", [], FR)
    add('final-p95', thesis, f"p95 kernel → cuối cửa sổ báo & ≤ 3 s & {n2(pf['latency_p95'])} s (p50 {n2(pf['latency_p50'])} s) & "
        f"{n2(af['latency_p95'])} s \\\\", [], FR)
    add('final-slow', thesis, f"\\multicolumn{{2}}{{l}}{{{frac(rr['0.5'])} / {frac(rr['0.1'])}}} \\\\", [], FR)
    add('final-onoff', thesis, f"{frac(dl['onoff10']['attack'])} (control {frac(dl['onoff10']['control'])}, p95 {n2(dl['onoff10']['latency_p95'])} s)", [], FR)
    add('final-pad300', thesis, f"{frac(dl['pad300']['attack'])} (p95 {n2(dl['pad300']['latency_p95'])} s)", [], FR)
    add('final-benign', thesis, f"Binary vô hại bị gắn cờ & báo kèm & {frac(pf['benign'])} & {frac(af['benign'])} \\\\", [], FR)
    add('final-admin', thesis, f"Lệnh quản trị bị gắn cờ & báo kèm & {frac(pf['admin'])} & {frac(af['admin'])} ({num(100 * af['admin']['rate'], 1)}\\%) \\\\", [], FR)
    add('final-lotl', thesis, f"Tấn công bằng tool của image bị bắt & báo kèm & {frac(pf['lotl'])} & {frac(af['lotl'])} \\\\", [], FR)
    add('final-eventgen', thesis, f"Hành động event-generator bị bắt & báo kèm & {frac(pf['eventgen'])} & {frac(af['eventgen'])} "
        f"({num(100 * af['eventgen']['rate'], 1)}\\%) \\\\", [], FR)
    add('final-burden', thesis, f"{bf['episodes']} đợt trên {num(bf['replica_hours'], 1)} replica-giờ: \\textbf{{{n2(bf['value'])} đợt/replica-giờ}} "
        f"{{[}}{n2(bf['ci95'][0])}; {n2(bf['ci95'][1])}{{]}}", [], FR)
    RI = 'results-20261121/pulse-live-final-1119/rule-intent.json'
    ri = receipt(RI)['intervals']
    for key, label in (('attack', 'Tấn công (fixture)'), ('lotl', 'Tấn công bằng tool của image'), ('eventgen', 'Event-generator'),
                       ('control', 'Control idle'), ('admin', 'Lệnh quản trị'), ('benign', 'Binary vô hại')):
        r_ = ri[key]
        add(f'rule-intent-{key}', thesis, f"{label} & {kn(r_['ml_only'])} & {kn(r_['rule_only'])} & {kn(r_['ml_or_rule'])} \\\\", [], RI)
    bu = receipt(RI)['burden']['systems']
    add('rule-intent-burden', thesis, f"Gánh (đợt/replica-giờ) & {n2(bu['ml_only']['per_replica_hour'])} & {n2(bu['rule_only']['per_replica_hour'])} & "
        f"{n2(bu['ml_or_rule']['per_replica_hour'])} \\\\", [], RI)

    rule6 = receipt(f'{V6}/rule-e.json')['comparison']
    h = lambda x: f"{x['hit']}/{x['n']}"
    rp, ra = rule6['primary'], rule6['all_rates']
    add('v6-r1-harm', thesis, f"mô hình một mình bắt {h(rp['ml_only']['lotl_recall'])} ở tập chính ({h(ra['ml_only']['lotl_recall'])} mọi tốc độ); "
        f"có R1 còn {h(rp['ml_plus_rule']['lotl_recall'])} ({h(ra['ml_plus_rule']['lotl_recall'])})", [], f'{V6}/rule-e.json')
    rc6 = receipt(f'{V6}/rca-coverage.json')
    o6 = rc6['rank_top1_by_order']
    add('v6-rca-order', thesis, f"binary fixture đứng hạng 1 trong {o6['attack_after_benign']['top1']}/{o6['attack_after_benign']['cases']} case khi tấn "
        f"công chạy sau binary vô hại ({num(100 * o6['attack_after_benign']['share'], 1)}\\%) và {o6['attack_before_benign']['top1']}/"
        f"{o6['attack_before_benign']['cases']} khi chạy trước ({num(100 * o6['attack_before_benign']['share'], 1)}\\%), tổng "
        f"{num(100 * rc6['stored_rank_top1'], 1)}\\%", [], f'{V6}/rca-coverage.json')
    add('v6-rca-own', thesis, f"Ở lượt v6, {rc6['attack_cases']}/{rc6['trials']} tấn công ({num(100 * rc6['attack_cases'] / rc6['trials'], 1)}\\%) có case riêng",
        [], f'{V6}/rca-coverage.json')
    # LID-DS 2019 once (lidds2019-confirmation-v2), reported with the 1 s label tolerance of amendment 1
    TOL = 'results-20261118/lidds2019-confirmation/tolerance.json'
    tl = receipt(TOL)
    t19, t21 = tl['lidds2019']['tolerance'], tl['lidds2021_official']['tolerance']
    pc2 = lambda x: num(100 * x, 2)
    add('l19-pooled', thesis, f"phát hiện {thousands(t19['detected'])}/{thousands(t19['attack_recordings'])} bản ghi tấn công ({pc2(t19['recall'])}\\%, CI "
        f"{{[}}{pc2(t19['recall_ci95'][0])}; {pc2(t19['recall_ci95'][1])}{{]}}), {t19['false_alarm_recordings']}/{thousands(t19['normal_recordings'])} "
        f"bản ghi normal bị báo nhầm ({pc2(t19['false_alarm_rate'])}\\%, CI {{[}}{pc2(t19['false_alarm_ci95'][0])}; "
        f"{pc2(t19['false_alarm_ci95'][1])}{{]}}), p95 {num(t19['latency_p95'], 2)} s (p50 {num(t19['latency_p50'], 2)} s)", [], TOL)
    add('l19-2021-same-rule', thesis, f"official, nơi nhãn chính xác, vẫn cho {thousands(t21['detected'])}/{thousands(t21['attack_recordings'])}", [], TOL)
    add('l19-abstract', 'thesis/chapters/abstract.tex', f"phát hiện {thousands(t19['detected'])}/{thousands(t19['attack_recordings'])} bản ghi tấn công ({pc2(t19['recall'])}\\%", [], TOL)
    for sname, mm in tl['lidds2019']['tolerance_scenarios'].items():
        add(f'l19-{sname}', thesis, f"{sname.replace('_', chr(92) + '_')}}} & {mm['detected']}/{mm['attack_recordings']} & "
            f"{mm['false_alarm_recordings']}/{mm['normal_recordings']} & {num(mm['latency_p95'], 2)} s \\\\", [], TOL)
    DEV = 'results-20261118/lidds2019-development/study.json'
    sd = receipt(DEV)
    c = sd['candidates']
    assert sd['selected'] == 'base'
    add('l19-dev', thesis, f"30\\% bản ghi test 2019 ({c['base']['tolerance']['attack_recordings']} tấn công, "
        f"{thousands(c['base']['tolerance']['normal_recordings'])} normal, chia theo sha256) làm development; {len(c)} ứng viên", [], DEV)
    add('l19-dev-top5', thesis, f"top 5: {c['top5']['tolerance']['detected']}/{c['top5']['tolerance']['attack_recordings']} so với "
        f"{c['base']['tolerance']['detected']}/{c['base']['tolerance']['attack_recordings']}, dung sai 1 s", [], DEV)
    LB = 'results-20261118/lidds2019-development/latency.json'
    lb = receipt(LB)
    add('l19-latency-bound', thesis, f"đến ở p95 {num(lb['first_unseen_after_p50_p95'][1], 2)} s trên các bản ghi tấn công development", [], LB)
    GR = 'results-20261118/lidds2019-development/grid.json'
    gr = receipt(GR)
    assert gr['pass_must'] == [gr['base']] and gr['lidds2021_gate']['passed']
    add('l19-grid', thesis, f"Mở rộng thêm {len(gr['candidates'])} tổ hợp", [], GR)
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
