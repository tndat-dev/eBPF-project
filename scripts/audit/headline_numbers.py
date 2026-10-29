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
    AO = 'results-20261029/app-overhead/APP-OVERHEAD.json'
    ao = receipt(AO)['per_endpoint']
    for e in ao['p95']:
        p95, p50 = ao['p95'][e], ao['p50'][e]
        added = p50['added_ms']
        cells = [f"{num(p95['off_ms'], 1)} / {num(p95['probe_ms'], 1)}",
                 *(f"{signed(100 * r['overhead'])}% [{signed(100 * r['ci95'][0])}; {signed(100 * r['ci95'][1])}]" for r in (p95, p50)),
                 num(added, 2 if added < 1 else 1)]
        add(f'g7-{e}', pulse, f"| `{e}` | {' | '.join(cells)} |", [], AO)
        add(f'g7-thesis-{e}', thesis, ' & '.join([''] + cells).replace('%', r'\%') + r' \\', [], AO)
    LD = 'results-20261029/lidds/lidds-evaluation.json'
    ld = receipt(LD)
    for arm, label, tex in (('ml', 'ML', 'ML'), ('tripwire', 'Tripwire', 'Tripwire'), ('system', '**Hệ thống**', 'Hệ thống (ML hoặc tripwire)')):
        p = ld['pooled'][arm]
        det = (pct(p['detection_rate']), ci(p['detection_ci95'], 1))
        fa = (pct(p['false_alarm_rate']), ci(p['false_alarm_ci95'], 1))
        tail = [num(p['false_alarm_episodes_per_hour'], 2), f"{num(p['latency_p50'], 2)} / {num(p['latency_p95'], 2)}"]
        bold = (lambda x: f'**{x}**') if arm == 'system' else (lambda x: x)
        add(f'lidds-{arm}', pulse, f"| {label} | {bold(det[0])} ({thousands(p['detected'])}) {det[1]} | {bold(fa[0])} "
            f"({thousands(p['false_alarm_recordings'])}) {fa[1]} | {' | '.join(tail)} |", [], LD)
        add(f'lidds-thesis-{arm}', thesis, f"{tex} & {det[0]} ({p['detected']}/{p['attack_recordings']}) {det[1]} & {fa[0]} "
            f"({p['false_alarm_recordings']}/{p['normal_recordings']}) {fa[1]} & {' & '.join(tail)}".replace('%', r'\%') + r' \\', [], LD)
    macro = [s['arms']['system']['detection_rate'] for s in ld['scenarios'].values()]
    add('lidds-macro', pulse, f"hệ thống tính cùng cách đạt {num(sum(macro) / len(macro), 2)} (trung bình {len(macro)} kịch bản; "
        f"gộp theo bản ghi {pct(ld['pooled']['system']['detection_rate'])})", [], f'{LD} (mean over scenarios)')
    add('lidds-macro-thesis', thesis, f"Tính cùng cách (trung bình của {len(macro)} kịch bản), hệ thống của luận văn đạt "
        f"{num(sum(macro) / len(macro), 2)}.", [], f'{LD} (mean over scenarios)')
    return out


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
