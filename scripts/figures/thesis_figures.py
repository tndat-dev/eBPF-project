#!/usr/bin/env python3
"""Thesis / paper figures drawn only from receipts committed under validation-evidence/ (no cluster access).

    ~/.venvs/sentinel-figures/bin/python scripts/figures/thesis_figures.py [--lang vi|en] [--output docs/figures]

Figures (PNG at 200 dpi + PDF):
  live-runs-metrics   precision / recall / idle control / benign launch flagged, five live runs, Wilson 95 % CI
                      (the two confirmation runs on their registered subset, attack rates 6, 12, 24 per second)
  live-latency-cdf    kernel -> preview delay of detected attacks, the four latest live runs, 2 s / 3 s marks
  policy-pareto       34 confirmation policies (pulse-stable-candidate, refreshed calibration): burden vs p95,
                      rule-v2 feasible set filled
  baselines-budget    recall and benign-launch flag rate against normal alert burden for Pulse and three baselines
  feature-groups      syscall 5B.3: change against base29 when a feature group or a p-value branch is removed
                      (recall and separation with bootstrap 95 % CI, p95), main holdout, two attack sets
  burden-levers       normal alert burden of the 5.22 levers: two development runs and the blind test on the confirmation
                      run (rule 5), with the 0.1/h budget
  live-runs-table.md  the numbers of live-runs-metrics as a table (counts, Wilson CI, p50/p95)
  alert-delivery-cdf  confirmation run: kernel -> recipient per delivery path (Alertmanager push, Prometheus pull
                      fast / default), registered subset, share of all attack trials

Colours: the validated categorical order (blue, orange, aqua, yellow); every series also has its own marker and
line style and a direct label, so identity never rests on colour alone (print, colour-vision deficiency).
"""
from __future__ import annotations

import argparse
import gzip
import json
import math
from pathlib import Path

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.ticker import FuncFormatter  # noqa: E402
import numpy as np  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
EV = ROOT/'validation-evidence'
SERIES = ['#2a78d6', '#eb6834', '#1baf7a', '#eda100']
MARKERS = ['o', 's', '^', 'D']
STYLES = ['-', '--', '-.', ':']
INK, INK2, MUTED, GRID, SURFACE = '#0b0b0b', '#52514e', '#8a8984', '#e4e3df', '#fcfcfb'
CONFIRM = EV/'results-20261023/pulse-stable-confirm'
PRIMARY_RATES = (6, 12, 24)        # stable-confirmation-v1: the composition of the earlier runs
RUNS = [('pulse-live-recalibrated', EV/'results-20261019/pulse-live-recalibrated/campaign-main-RESULTS.json.gz', 'policy-1win-a3', None),
        ('pulse-stable-candidate', EV/'results-20261021/pulse-stable-candidate/campaign-RESULTS.json', 'k2of2, α×10', None),
        ('pulse-stable-refreshed', EV/'results-20261021/pulse-stable-refreshed/campaign-RESULTS.json', 'k2of2, α×10 + {refreshed}', None),
        ('pulse-stable-confirm', CONFIRM/'campaign-RESULTS.json', 'CUSUM b3/h6 cap, 6–24/s', PRIMARY_RATES),
        ('pulse-peer-discount-confirm', EV/'results-20261025/pulse-peer-discount-confirm/campaign-RESULTS.json',
         'k2of2 α×5 + replica 30 s, 6–24/s', PRIMARY_RATES)]
LATENCY_RUNS = RUNS[-4:]           # four validated colours; the first run (policy-1win-a3) is in the table and metrics

TEXT = {
    'vi': dict(precision='Precision', recall='Recall', control='Control idle dương', benign='Binary vô hại bị gắn cờ',
               expectation='kỳ vọng', share='Tỉ lệ (%)', delay='Độ trễ kernel → preview (s)',
               cdf='Tỉ lệ attack đã phát hiện (%)', burden='Đợt cảnh báo trên normal / replica-giờ',
               p95='p95 độ trễ (s)', feasible='thỏa luật v2 (recall, precision ≥ 95%, control ≤ 5%)',
               infeasible='không thỏa', running='đang chạy', preferred='2 s (ưu tiên)', acceptable='3 s (chấp nhận)',
               budget='ngân sách', benign_rate='Binary vô hại bị gắn cờ (%)',
               d_recall='Δ recall (điểm %)', d_sep='Δ tách binary vô hại (điểm %)', d_p95='Δ p95 (s)',
               recipient='Độ trễ kernel → người nhận (s, thang log)', delivered='Trial attack có cảnh báo mới (%)',
               preview_ref='kernel → preview (tham chiếu)', push='push vào Alertmanager', pull_fast='Prometheus pull nhanh',
               pull_default='Prometheus pull mặc định', refreshed='calib. mới', blind='test blind',
               levers=dict(k2of2='k2of2 α×10', keep='CUSUM b3/h6 keep\n(tham chiếu)', cap='CUSUM b3/h6 cap\n(stable)', lt2s='< 2 s: Mondrian + replica 60 s\n+ k2of2 α×15', le3s='≤ 3 s: replica 30 s + k2of2 α×5\n(đạt test blind)'), strict='chỉ đợt mở từ cửa sổ trong trial',
               groups=dict(tree='chỉ nhánh tree', support='chỉ nhánh support', bins_only='chỉ bin (bỏ kênh syscall)',
                           drop_aggregates='bỏ 5 tổng hợp', drop_all_bins='bỏ mọi bin', drop_transition_bins='bỏ bin cặp',
                           drop_rolling='bỏ rolling', history1='lịch sử 1 cửa sổ', history2='lịch sử 2 cửa sổ',
                           drop_log_counts='bỏ log-count', drop_ratios='bỏ tỉ lệ', drop_syscall_bins='bỏ 64 bin syscall')),
    'en': dict(precision='Precision', recall='Recall', control='Idle control positive', benign='Benign launch flagged',
               expectation='target', share='Rate (%)', delay='Kernel → preview delay (s)',
               cdf='Detected attacks (%)', burden='Normal alert episodes / replica-hour',
               p95='p95 delay (s)', feasible='meets rule v2 (recall, precision ≥ 95%, control ≤ 5%)',
               infeasible='does not', running='running', preferred='2 s (preferred)', acceptable='3 s (acceptable)',
               budget='budget', benign_rate='Benign launch flagged (%)',
               d_recall='Δ recall (points)', d_sep='Δ benign separation (points)', d_p95='Δ p95 (s)',
               recipient='Kernel → recipient delay (s, log scale)', delivered='Attack trials with a new alert (%)',
               preview_ref='kernel → preview (reference)', push='Alertmanager push', pull_fast='Prometheus pull, fast',
               pull_default='Prometheus pull, default', refreshed='refreshed calib.', blind='blind test',
               levers=dict(k2of2='k2of2 α×10', keep='CUSUM b3/h6 keep\n(reference)', cap='CUSUM b3/h6 cap\n(stable)', lt2s='< 2 s: Mondrian + replica 60 s\n+ k2of2 α×15', le3s='≤ 3 s: replica 30 s + k2of2 α×5\n(passes the blind test)'), strict='episodes opened inside the trial only',
               groups=dict(tree='tree branch only', support='support branch only', bins_only='bins only (no syscall channels)',
                           drop_aggregates='drop 5 aggregates', drop_all_bins='drop all bins', drop_transition_bins='drop pair bins',
                           drop_rolling='drop rolling', history1='history 1 window', history2='history 2 windows',
                           drop_log_counts='drop log counts', drop_ratios='drop ratios', drop_syscall_bins='drop 64 syscall bins')),
}


def style():
    plt.rcParams.update({
        'figure.facecolor': SURFACE, 'axes.facecolor': SURFACE, 'savefig.facecolor': SURFACE,
        'axes.edgecolor': MUTED, 'axes.labelcolor': INK2, 'xtick.color': INK2, 'ytick.color': INK2,
        'axes.grid': True, 'grid.color': GRID, 'grid.linewidth': 0.8, 'axes.axisbelow': True,
        'axes.spines.top': False, 'axes.spines.right': False, 'font.size': 9.5, 'axes.titlesize': 10.5,
        'axes.titleweight': 'bold', 'axes.titlecolor': INK, 'legend.frameon': False, 'lines.linewidth': 2,
        'font.family': 'DejaVu Sans'})


def wilson(k, n, z=1.96):
    if not n:
        return (math.nan, math.nan)
    p = k / n; d = 1 + z*z/n; c = p + z*z/(2*n); h = z*math.sqrt(p*(1-p)/n + z*z/(4*n*n))
    return ((c - h)/d, (c + h)/d)


def load(path: Path):
    with (gzip.open(path, 'rt') if path.suffix == '.gz' else path.open()) as f:
        return json.load(f)


def run_counts(path, rates=None):
    """Counts and detected-attack delays of one campaign; ``rates`` keeps only trials at those attack rates (the
    trial table sits next to the results)."""
    keep = None
    if rates is not None:
        trials = load(path.parent/'campaign-trials.json')['trials']
        keep = {i for i, tr in trials.items() if tr['rate_per_second'] in rates}
    c, delays = {}, []
    for rows in load(path)['completed'].values():
        for r in rows:
            if keep is not None and str(r['trial_id']).split(':')[0] not in keep:
                continue
            kind = 'benign' if r.get('control_kind') == 'benign_exec' else r['label']
            c[kind, r['outcome']] = c.get((kind, r['outcome']), 0) + 1
            if r['label'] == 'attack' and r.get('kernel_to_preview_seconds') is not None:
                delays.append(float(r['kernel_to_preview_seconds']))
    tp, fn = c.get(('attack', 'TP'), 0), c.get(('attack', 'FN'), 0)
    fp, tn = c.get(('expected_normal', 'FP_expected'), 0), c.get(('expected_normal', 'TN_expected'), 0)
    bfp, btn = c.get(('benign', 'FP_expected'), 0), c.get(('benign', 'TN_expected'), 0)
    return dict(precision=(tp, tp + fp), recall=(tp, tp + fn), control=(fp, fp + tn), benign=(bfp, bfp + btn)), delays


def save(fig, out: Path, name):
    for ext in ('png', 'pdf'):          # no creation date: an unchanged figure redraws byte-identical
        fig.savefig(out/f'{name}.{ext}', dpi=200, bbox_inches='tight',
                    metadata={'CreationDate': None} if ext == 'pdf' else {'Software': None})
    plt.close(fig)


def fig_live_metrics(out, t, ci=True):
    data = [(name, run_counts(path, rates)[0]) for name, path, _, rates in RUNS]
    panels = [('precision', 95), ('recall', 95), ('control', 5), ('benign', None)]
    fig, axes = plt.subplots(1, 4, figsize=(15, 3.5), sharey=False)
    x = np.arange(len(data))
    for ax, (key, target) in zip(axes, panels):
        for i, (name, m) in enumerate(data):
            k, n = m[key]; lo, hi = wilson(k, n); v = 100*k/n
            if ci:
                ax.errorbar(i, v, yerr=[[v - 100*lo], [100*hi - v]], fmt='o', color=SERIES[0], ms=6, capsize=3, lw=1.5)
            else:  # meeting reports and slides carry no interval (owner, 23/10)
                ax.plot(i, v, 'o', color=SERIES[0], ms=6)
            ax.annotate(f'{v:.1f}', (i, v), textcoords='offset points', xytext=(7, 0), ha='left', va='center', fontsize=8.5, color=INK)
        if target is not None:
            ax.axhline(target, color=INK2, lw=1, ls='--')
            ax.annotate(f"{t['expectation']} {'≥' if target > 50 else '≤'} {target}%", (-0.45, target),
                        textcoords='offset points', xytext=(0, -11), ha='left', fontsize=8, color=INK2)
        ax.set_title(t[key]); ax.set_xticks(x)
        ax.set_xticklabels(['-\n'.join(n.replace('pulse-', '').rsplit('-', 1)) for n, _ in data], fontsize=7.5)
        ax.set_xlim(-0.5, len(data) - 0.15)        # room for the value label of the last run
        lo_y = {'precision': 85, 'recall': 85, 'control': 0, 'benign': 70}[key]
        ax.set_ylim(lo_y, {'control': 16}.get(key, 101.5))
    axes[0].set_ylabel(t['share'])
    fig.tight_layout(); save(fig, out, 'live-runs-metrics')


def table_live_runs(out, t):
    """The numbers behind live-runs-metrics and live-latency-cdf, one row per run (same counting)."""
    head = {'vi': '| Lượt | Luật | Precision | Recall | Control idle dương | Binary vô hại bị gắn cờ | p50 / p95 (s) |',
            'en': '| Run | Rule | Precision | Recall | Idle control positive | Benign launch flagged | p50 / p95 (s) |'}
    lang = 'vi' if t is TEXT['vi'] else 'en'
    rows = [head[lang], '|---|---|---|---|---|---|---|']
    num = lambda v, d: f'{v:.{d}f}'.replace('.', ',') if lang == 'vi' else f'{v:.{d}f}'
    fmt = lambda v: num(v, 1)
    for name, path, policy, rates in RUNS:
        m, delays = run_counts(path, rates)
        cells = []
        for key in ('precision', 'recall', 'control', 'benign'):
            k, n = m[key]; lo, hi = wilson(k, n)
            cells.append(f'{fmt(100 * k / n)}% ({k}/{n}) [{fmt(100 * lo)}; {fmt(100 * hi)}]')
        p50, p95 = np.percentile(delays, 50), np.percentile(delays, 95)
        rows.append(f"| {name} | {policy.format(refreshed=t['refreshed'])} | {' | '.join(cells)} | {num(p50, 2)} / {num(p95, 2)} |")
    note = {'vi': 'Lượt xác nhận chỉ tính tập chính (tốc độ 6, 12, 24/s). CI 95% Wilson. Nhãn kỳ vọng, chưa review.',
            'en': 'The confirmation run counts its registered subset (6, 12, 24 per second). Wilson 95 % CI. Expected labels, not adjudicated.'}
    (out/'live-runs-table.md').write_text('\n'.join(rows) + '\n\n' + note[lang] + '\n')


def fig_latency(out, t):
    fig, ax = plt.subplots(figsize=(6.4, 3.8))
    for i, (name, path, policy, rates) in enumerate(LATENCY_RUNS):
        d = np.sort(run_counts(path, rates)[1])
        y = 100*np.arange(1, len(d) + 1)/len(d)
        p95 = float(np.percentile(d, 95))
        ax.step(d, y, where='post', color=SERIES[i], ls=STYLES[i], lw=2)
        ax.plot([p95], [95], marker=MARKERS[i], color=SERIES[i], ms=7, mec=SURFACE, mew=1.5)
        ax.plot([], [], color=SERIES[i], ls=STYLES[i], marker=MARKERS[i], ms=6, lw=2,
                label=f"{name} ({policy.format(refreshed=t['refreshed'])}): p95 {p95:.2f} s, n = {len(d)}")
    ax.axhline(95, color=GRID, lw=1)
    ax.legend(loc='upper center', bbox_to_anchor=(0.45, -0.17), fontsize=8.5, handlelength=3)
    for x, label in ((2, t['preferred']), (3, t['acceptable'])):
        ax.axvline(x, color=INK2, lw=1, ls='--')
        ax.annotate(label, (x, 50), textcoords='offset points', xytext=(3, 0), fontsize=8, color=INK2)
    ax.set_xlim(0, 6); ax.set_ylim(0, 101); ax.set_xlabel(t['delay']); ax.set_ylabel(t['cdf'])
    fig.tight_layout(); save(fig, out, 'live-latency-cdf')


def fig_pareto(out, t):
    d = load(EV/'results-20261021/pulse-stable-candidate/final/policy-pareto-refreshed.json')
    feasible = set(d['v2_feasible'])
    fig, ax = plt.subplots(figsize=(6.4, 4))
    rows = d['policies']
    for name, r in rows.items():
        on = name in feasible
        ax.plot(r['burden'], r['p95'], marker='o', ms=7 if on else 6, ls='none',
                color=SERIES[0] if on else 'none', mec=SERIES[0] if on else MUTED, mew=1.5)
    for name, tx, ty in (('k2of2_a10', 10, 2.45), ('k3of4_a10', 1.25, 2.3)):
        r = rows[name]
        label = f"{name} ({t['running']})" if name == d.get('chosen') else name
        label += f"\n{r['burden']:.1f} / h, p95 {r['p95']:.2f} s"
        ax.annotate(label, (r['burden'], r['p95']), xytext=(tx, ty), fontsize=8.5, color=INK,
                    arrowprops=dict(arrowstyle='-', color=INK2, lw=0.8, shrinkA=0, shrinkB=4))
    for y, label in ((2, t['preferred']), (3, t['acceptable'])):
        ax.axhline(y, color=INK2, lw=1, ls='--')
        ax.annotate(label, (1.05, y), textcoords='offset points', xytext=(0, 3), fontsize=8, color=INK2)
    ax.set_xscale('log'); ax.set_xlim(1, 80); ax.set_ylim(0.5, 6)
    ax.xaxis.set_major_formatter(FuncFormatter(lambda v, _: f'{v:g}'))
    ax.set_xlabel(t['burden']); ax.set_ylabel(t['p95'])
    ax.plot([], [], marker='o', ls='none', color=SERIES[0], ms=7, label=t['feasible'])
    ax.plot([], [], marker='o', ls='none', color='none', mec=MUTED, mew=1.5, ms=6, label=t['infeasible'])
    ax.legend(loc='upper right', fontsize=8)
    fig.tight_layout(); save(fig, out, 'policy-pareto')


def fig_baselines(out, t):
    d = load(EV/'results-20261021/baselines/RESULTS-budget.json')
    arms = [('base29', 'Pulse (base29)'), ('autoencoder', 'autoencoder'), ('freq_profile', 'freq_profile (BoSC)'),
            ('iforest', 'Isolation Forest')]
    fig, axes = plt.subplots(1, 2, figsize=(11, 3.9), sharex=True)
    for i, (arm, label) in enumerate(arms):
        scales = sorted(d['arms'][arm]['scales'].values(), key=lambda r: r['episodes_per_replica_hour'])
        x = [r['episodes_per_replica_hour'] for r in scales]
        for ax, key in zip(axes, ('recall', 'benign_positive_rate')):
            y = [100*r[key] for r in scales]
            ax.plot(x, y, color=SERIES[i], ls=STYLES[i], marker=MARKERS[i], ms=5, lw=2, mec=SURFACE, mew=1,
                    label=label if ax is axes[0] else None)
    for ax, ylabel in zip(axes, (t['recall'] + ' (%)', t['benign_rate'])):
        for b in (1, 5):
            ax.axvline(b, color=INK2, lw=1, ls='--')
            ax.annotate(f"{t['budget']} {b}", (b, 30), textcoords='offset points', xytext=(-3, 0), fontsize=8,
                        color=INK2, rotation=90, ha='right', va='bottom')
        ax.set_xscale('log'); ax.set_xlim(0.002, 60); ax.set_ylim(0, 103)
        ax.xaxis.set_major_formatter(FuncFormatter(lambda v, _: f'{v:g}'))
        ax.set_xlabel(t['burden']); ax.set_ylabel(ylabel)
    axes[0].set_title(t['recall']); axes[1].set_title(t['benign'])
    fig.legend(loc='upper center', ncol=4, fontsize=9, bbox_to_anchor=(0.5, 1.07), handlelength=3)
    fig.tight_layout(); save(fig, out, 'baselines-budget')


def fig_feature_groups(out, t):
    base = EV/'results-20261022/syscall'
    comps = {**load(base/'feature-groups-primary/VERDICT.json')['components'],
             **{k: v for k, v in load(base/'feature-groups-branches/VERDICT.json')['components'].items() if k.startswith('base29@')}}
    order = ['base29@tree', 'base29@support', 'bins_only', 'drop_aggregates', 'drop_all_bins', 'drop_transition_bins',
             'drop_rolling', 'history1', 'history2', 'drop_log_counts', 'drop_ratios', 'drop_syscall_bins']
    names = [t['groups'][k.split('@')[-1]] if k.startswith('base29@') else t['groups'][k] for k in order]
    sets = [('pulse-attack-dev', 0), ('pulse-live-recalibrated', 1)]
    fig, axes = plt.subplots(1, 3, figsize=(12, 4.6), sharey=True, gridspec_kw=dict(width_ratios=[1.3, 1.1, 0.8]))
    y = np.arange(len(order))[::-1]
    for ax, key in zip(axes, ('recall_diff', 'separation_diff', 'p95_diff_seconds')):
        ax.axvline(0, color=INK2, lw=1)
        for name, i in sets:
            off = 0.15 if i == 0 else -0.15
            for yy, comp in zip(y, order):
                r = comps[comp]['sets'][name].get(key)
                if r is None:
                    continue
                if key == 'p95_diff_seconds':
                    ax.plot(r, yy + off, MARKERS[i], color=SERIES[i], ms=6, mec=SURFACE, mew=1)
                else:
                    lo, hi = 100*r['ci95'][0], 100*r['ci95'][1]; v = 100*r['point']
                    ax.plot([lo, hi], [yy + off]*2, color=SERIES[i], lw=2, solid_capstyle='round')
                    ax.plot(v, yy + off, MARKERS[i], color=SERIES[i], ms=6, mec=SURFACE, mew=1)
    axes[0].set_yticks(y); axes[0].set_yticklabels(names); axes[0].set_ylim(-0.6, len(order) - 0.4)
    for ax, label in zip(axes, (t['d_recall'], t['d_sep'], t['d_p95'])):
        ax.set_xlabel(label); ax.grid(axis='y', visible=False)
    for name, i in sets:
        axes[0].plot([], [], MARKERS[i], color=SERIES[i], ls='-', lw=2, ms=6, label=name)
    fig.legend(loc='upper center', ncol=2, fontsize=9, bbox_to_anchor=(0.5, 1.04), handlelength=2.5)
    fig.tight_layout(); save(fig, out, 'feature-groups')


def fig_burden(out, t):
    dev = load(EV/'results-20261022/pulse/burden-levers.json')['candidates']
    cap = load(EV/'results-20261021/pulse-stable-refreshed/final/cusum-carryover.json')['metrics']
    blind = load(CONFIRM/'burden-blind-test.json')
    names = {'k2of2': 'joint|none|k2of2_a10', 'keep': 'joint|none|cusum_b3_h6', 'lt2s': 'mjoint|peer60|k2of2_a15',
             'le3s': 'joint|peer30|k2of2_a5'}
    order = ['k2of2', 'keep', 'cap', 'lt2s', 'le3s']
    blind_key = {'keep': 'reference', 'cap': 'stable', 'lt2s': 'lt2s', 'le3s': 'le3s'}
    series = []
    for run in ('pulse-stable-candidate', 'pulse-stable-refreshed'):
        series.append((run, {k: (cap[run]['cusum_b3_h6_cap']['burden'] if k == 'cap' else dev[run][names[k]]['burden'])
                             for k in order}))
    series.append((f"pulse-stable-confirm ({t['blind']})", {k: blind['metrics'][blind_key[k]]['burden'] for k in blind_key}))
    fig, ax = plt.subplots(figsize=(7.4, 4.2))
    y = np.arange(len(order))[::-1]
    for i, (name, values) in enumerate(series):
        off = (1 - i) * 0.18
        xs = [values.get(k) for k in order]
        ax.plot([v for v in xs if v is not None], [yy + off for yy, v in zip(y, xs) if v is not None], MARKERS[i],
                color=SERIES[i], ms=7, mec=SURFACE, mew=1, ls='none', label=name)
        if i == 2:
            for yy, v in zip(y, xs):
                if v is not None:
                    ax.annotate(f'{v:.2f}', (v, yy + off), textcoords='offset points', xytext=(0, -12), ha='center',
                                va='center', fontsize=8, color=INK)
    ci = blind['burden_ci']['stable']['ci95']
    ax.plot(ci, [y[order.index('cap')] - 0.18] * 2, color=SERIES[2], lw=2, solid_capstyle='round')
    ax.axvline(0.1, color=INK2, lw=1, ls='--')
    ax.annotate(f"{t['budget']} 0,1" if t is TEXT['vi'] else f"{t['budget']} 0.1", (0.1, y[0] + 0.45), textcoords='offset points',
                xytext=(4, 0), fontsize=8, color=INK2)
    ax.set_yticks(y); ax.set_yticklabels([t['levers'][k] for k in order], fontsize=8.5)
    ax.set_xlim(0, 8.5); ax.set_ylim(-0.6, len(order) - 0.2); ax.grid(axis='y', visible=False)
    ax.set_xlabel(t['burden'])
    ax.legend(loc='lower right', fontsize=8)
    fig.tight_layout(); save(fig, out, 'burden-levers')


def fig_alert_delivery(out, t):
    rows = [r for r in load(CONFIRM/'delivery-latency-campaign.json')['trials'] if r['rate_per_second'] in PRIMARY_RATES]
    n = len(rows)
    q = lambda v, x: float(np.percentile(v, 100*x, method='nearest'))     # as alert_delivery_latency.quantile
    fig, ax = plt.subplots(figsize=(6.6, 4.6))
    ref = np.sort([r['kernel_to_preview_seconds'] for r in rows if r.get('kernel_to_preview_seconds') is not None])
    ax.step(ref, 100*np.arange(1, len(ref) + 1)/n, where='post', color=MUTED, ls=':', lw=1.6,
            label=f"{t['preview_ref']}: p95 {q(ref, .95):.2f} s")
    paths = (('push', t['push'], (-8, 0), 'right'), ('pull-fast', t['pull_fast'], (6, -13), 'left'),
             ('pull-default', t['pull_default'], (-6, 6), 'right'))
    for i, (path, label, offset, ha) in enumerate(paths):
        d = np.sort([r[f'{path}_kernel_to_recipient_seconds'] for r in rows if r.get(f'{path}_kernel_to_recipient_seconds') is not None])
        share = 100*np.arange(1, len(d) + 1)/n
        ax.step(d, share, where='post', color=SERIES[i], ls=STYLES[i], lw=2)
        text = f'{label}: {len(d)}/{n}, p50 {q(d, .5):.2f} s, p95 {q(d, .95):.2f} s'
        if path == 'push':
            strict = [r['push_kernel_to_recipient_seconds'] for r in rows if r.get('push_kernel_to_recipient_seconds') is not None
                      and not r.get('episode_window_starts_before_attack')]
            text += f' ({t["strict"]}: {len(strict)}, p95 {q(strict, .95):.2f} s)'
        ax.plot([], [], color=SERIES[i], ls=STYLES[i], lw=2, label=text)
        at = len(d)//2 if path == 'push' else -1          # push: beside its steep middle, clear of the 2 s / 3 s marks
        ax.annotate(label, (d[at], share[at]), textcoords='offset points', xytext=offset, ha=ha, va='center' if path == 'push' else 'baseline',
                    fontsize=8, color=INK)
    for x in (2, 3):
        ax.axvline(x, color=INK2, lw=1, ls='--')
        ax.annotate(f'{x} s', (x, 2), textcoords='offset points', xytext=(3, 0), fontsize=8, color=INK2)
    ax.set_xscale('log'); ax.set_xlim(0.1, 100); ax.set_ylim(0, 101)
    ax.xaxis.set_major_formatter(FuncFormatter(lambda v, _: f'{v:g}'))
    ax.set_xlabel(t['recipient']); ax.set_ylabel(t['delivered'])
    ax.legend(loc='upper center', bbox_to_anchor=(0.45, -0.17), fontsize=7.8, handlelength=2.8)
    fig.tight_layout(); save(fig, out, 'alert-delivery-cdf')


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--lang', choices=sorted(TEXT), default='vi')
    p.add_argument('--output', type=Path, default=ROOT/'docs'/'figures')
    p.add_argument('--no-ci', action='store_true', help='draw point values only (docx/pptx reports)')
    a = p.parse_args()
    out = a.output/a.lang; out.mkdir(parents=True, exist_ok=True)
    style(); t = TEXT[a.lang]
    fig_live_metrics(out, t, ci=not a.no_ci)
    for f in (fig_latency, fig_pareto, fig_baselines, fig_feature_groups, fig_burden, fig_alert_delivery, table_live_runs):
        f(out, t)
    print(sorted(x.name for x in out.iterdir()))


if __name__ == '__main__':
    main()
