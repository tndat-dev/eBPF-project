#!/usr/bin/env python3
"""Thesis / paper figures drawn only from receipts committed under validation-evidence/ (no cluster access).

    ~/.venvs/sentinel-figures/bin/python scripts/figures/thesis_figures.py [--lang vi|en] [--output docs/figures]

Figures (PNG at 200 dpi + PDF):
  live-runs-metrics   precision / recall / idle control / benign launch flagged, three live runs, Wilson 95 % CI
  live-latency-cdf    kernel -> preview delay of detected attacks, three live runs, 2 s / 3 s marks
  policy-pareto       34 confirmation policies (pulse-stable-candidate, refreshed calibration): burden vs p95,
                      rule-v2 feasible set filled
  baselines-budget    recall and benign-launch flag rate against normal alert burden for Pulse and three baselines

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
RUNS = [('pulse-live-recalibrated', EV/'results-20261019/pulse-live-recalibrated/campaign-main-RESULTS.json.gz', 'policy-1win-a3'),
        ('pulse-stable-candidate', EV/'results-20261021/pulse-stable-candidate/campaign-RESULTS.json', 'k2of2, α×10'),
        ('pulse-stable-refreshed', EV/'results-20261021/pulse-stable-refreshed/campaign-RESULTS.json', 'k2of2, α×10 + calib. mới')]

TEXT = {
    'vi': dict(precision='Precision', recall='Recall', control='Control idle dương', benign='Binary vô hại bị gắn cờ',
               expectation='kỳ vọng', share='Tỉ lệ (%)', delay='Độ trễ kernel → preview (s)',
               cdf='Tỉ lệ attack đã phát hiện (%)', burden='Đợt cảnh báo trên normal / replica-giờ',
               p95='p95 độ trễ (s)', feasible='thỏa luật v2 (recall, precision ≥ 95%, control ≤ 5%)',
               infeasible='không thỏa', running='đang chạy', preferred='2 s (ưu tiên)', acceptable='3 s (chấp nhận)',
               budget='ngân sách', benign_rate='Binary vô hại bị gắn cờ (%)'),
    'en': dict(precision='Precision', recall='Recall', control='Idle control positive', benign='Benign launch flagged',
               expectation='target', share='Rate (%)', delay='Kernel → preview delay (s)',
               cdf='Detected attacks (%)', burden='Normal alert episodes / replica-hour',
               p95='p95 delay (s)', feasible='meets rule v2 (recall, precision ≥ 95%, control ≤ 5%)',
               infeasible='does not', running='running', preferred='2 s (preferred)', acceptable='3 s (acceptable)',
               budget='budget', benign_rate='Benign launch flagged (%)'),
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


def run_counts(path):
    c, delays = {}, []
    for rows in load(path)['completed'].values():
        for r in rows:
            kind = 'benign' if r.get('control_kind') == 'benign_exec' else r['label']
            c[kind, r['outcome']] = c.get((kind, r['outcome']), 0) + 1
            if r['label'] == 'attack' and r.get('kernel_to_preview_seconds') is not None:
                delays.append(float(r['kernel_to_preview_seconds']))
    tp, fn = c.get(('attack', 'TP'), 0), c.get(('attack', 'FN'), 0)
    fp, tn = c.get(('expected_normal', 'FP_expected'), 0), c.get(('expected_normal', 'TN_expected'), 0)
    bfp, btn = c.get(('benign', 'FP_expected'), 0), c.get(('benign', 'TN_expected'), 0)
    return dict(precision=(tp, tp + fp), recall=(tp, tp + fn), control=(fp, fp + tn), benign=(bfp, bfp + btn)), delays


def save(fig, out: Path, name):
    for ext in ('png', 'pdf'):
        fig.savefig(out/f'{name}.{ext}', dpi=200, bbox_inches='tight')
    plt.close(fig)


def fig_live_metrics(out, t, ci=True):
    data = [(name, run_counts(path)[0]) for name, path, _ in RUNS]
    panels = [('precision', 95), ('recall', 95), ('control', 5), ('benign', None)]
    fig, axes = plt.subplots(1, 4, figsize=(11, 3.2), sharey=False)
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
        ax.set_xticklabels([n.replace('pulse-', '').replace('-', '-\n', 1) for n, _ in data], fontsize=8)
        ax.set_xlim(-0.5, len(data) - 0.5)
        lo_y = {'precision': 85, 'recall': 85, 'control': 0, 'benign': 70}[key]
        ax.set_ylim(lo_y, {'control': 16}.get(key, 101.5))
    axes[0].set_ylabel(t['share'])
    fig.tight_layout(); save(fig, out, 'live-runs-metrics')


def fig_latency(out, t):
    fig, ax = plt.subplots(figsize=(6.4, 3.8))
    for i, (name, path, policy) in enumerate(RUNS):
        d = np.sort(run_counts(path)[1])
        y = 100*np.arange(1, len(d) + 1)/len(d)
        p95 = float(np.percentile(d, 95))
        ax.step(d, y, where='post', color=SERIES[i], ls=STYLES[i], lw=2)
        ax.plot([p95], [95], marker=MARKERS[i], color=SERIES[i], ms=7, mec=SURFACE, mew=1.5)
        ax.plot([], [], color=SERIES[i], ls=STYLES[i], marker=MARKERS[i], ms=6, lw=2,
                label=f'{name} ({policy}): p95 {p95:.2f} s, n = {len(d)}')
    ax.axhline(95, color=GRID, lw=1)
    ax.legend(loc='lower right', fontsize=8.5, handlelength=3)
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


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--lang', choices=sorted(TEXT), default='vi')
    p.add_argument('--output', type=Path, default=ROOT/'docs'/'figures')
    p.add_argument('--no-ci', action='store_true', help='draw point values only (docx/pptx reports)')
    a = p.parse_args()
    out = a.output/a.lang; out.mkdir(parents=True, exist_ok=True)
    style(); t = TEXT[a.lang]
    fig_live_metrics(out, t, ci=not a.no_ci)
    for f in (fig_latency, fig_pareto, fig_baselines):
        f(out, t)
    print(sorted(x.name for x in out.iterdir()))


if __name__ == '__main__':
    main()
