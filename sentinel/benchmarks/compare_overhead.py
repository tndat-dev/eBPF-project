"""Compare immutable no-tracing, Tetragon-only and full-pipeline reports."""

import argparse
import json
import random
import statistics
from pathlib import Path


PHASES = ("no_tracing", "tetragon_only", "full_pipeline")


def median(values):
    values = [float(value) for value in values if value is not None]
    return statistics.median(values) if values else None


def effect(treatment, control, kind):
    """Return percent overhead and a deterministic bootstrap 95% interval."""
    treatment = [float(value) for value in treatment if value is not None]
    control = [float(value) for value in control if value is not None]
    if not treatment or not control:
        return None

    def statistic(a, b):
        a_median, b_median = statistics.median(a), statistics.median(b)
        if b_median == 0:
            return None
        if kind == "throughput_loss":
            return 100.0 * (1.0 - a_median / b_median)
        return 100.0 * (a_median / b_median - 1.0)

    estimate = statistic(treatment, control)
    rng = random.Random(20260721)
    bootstrap = []
    for _ in range(10_000):
        a = [rng.choice(treatment) for _ in treatment]
        b = [rng.choice(control) for _ in control]
        value = statistic(a, b)
        if value is not None:
            bootstrap.append(value)
    bootstrap.sort()
    return {
        "estimate_percent": estimate,
        "bootstrap_95ci_percent": [
            bootstrap[int(0.025 * (len(bootstrap) - 1))],
            bootstrap[int(0.975 * (len(bootstrap) - 1))],
        ],
    }


def summarize_report(path):
    report = json.loads(path.read_text())
    tetragon_cpu, tetragon_memory = [], []
    for snapshot in report.get("top_snapshots", []):
        rows = [
            row for row in snapshot.get("rows", [])
            if row["namespace"] == "kube-system"
            and row["pod"].startswith("tetragon-")
        ]
        if rows:
            tetragon_cpu.append(sum(row["cpu_millicores"] for row in rows))
            tetragon_memory.append(sum(row["memory_mib"] for row in rows))

    snapshots = report.get("systemd_snapshots", [])
    active = [row for row in snapshots if row.get("ActiveState") == "active"]
    detector_memory = median(
        int(row["MemoryCurrent"]) / (1024 * 1024)
        for row in active if str(row.get("MemoryCurrent", "")).isdigit()
    )
    detector_cpu = None
    usage_rows = [
        row for row in active if str(row.get("CPUUsageNSec", "")).isdigit()
    ]
    if len(usage_rows) >= 2:
        elapsed = usage_rows[-1]["ts"] - usage_rows[0]["ts"]
        consumed = (
            int(usage_rows[-1]["CPUUsageNSec"])
            - int(usage_rows[0]["CPUUsageNSec"])
        ) / 1e9
        if elapsed > 0 and consumed >= 0:
            detector_cpu = 100.0 * consumed / elapsed

    return {
        "path": str(path),
        "phase": report["phase"],
        "experiment_id": report.get("experiment_id"),
        "tool": report.get("tool", "ab"),
        "runs": len(report["runs"]),
        "failed_requests_total": report["failed_requests_total"],
        "rps": [row["requests_per_second"] for row in report["runs"]],
        "latency_p99_ms": [row["latency_p99_ms"] for row in report["runs"]],
        "rps_median": report["requests_per_second"]["median"],
        "latency_p99_ms_median": report["latency_p99_ms"]["median"],
        "latency_mean_ms_median": report[
            "time_per_request_concurrent_ms"
        ]["median"],
        "tetragon_total_cpu_millicores_median": median(tetragon_cpu),
        "tetragon_total_memory_mib_median": median(tetragon_memory),
        "detector_cpu_percent_one_core": detector_cpu,
        "detector_memory_mib_median": detector_memory,
    }


def latest_reports(root, tool, experiment_id=None):
    selected = {}
    for phase in PHASES:
        candidates = []
        for path in root.glob(f"{phase}-*/report.json"):
            report = json.loads(path.read_text())
            if (
                report.get("tool", "ab") == tool
                and (
                    experiment_id is None
                    or report.get("experiment_id") == experiment_id
                )
            ):
                candidates.append(path)
        if not candidates:
            qualifier = f" experiment={experiment_id}" if experiment_id else ""
            raise FileNotFoundError(
                f"no {tool}{qualifier} report for phase {phase} under {root}"
            )
        selected[phase] = summarize_report(max(candidates, key=lambda p: p.parent.name))
    return selected


def markdown(result):
    lines = [
        "# Runtime overhead benchmark",
        "",
        "| Phase | Median RPS | Median p99 | Failed | Tetragon CPU | Tetragon RAM | Detector CPU | Detector RAM |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for phase in ("no_tracing", "tetragon_only", "full_pipeline"):
        row = result["phases"][phase]
        lines.append(
            f"| {phase} | {row['rps_median']:.2f} | "
            f"{row['latency_p99_ms_median']:.3f} ms | "
            f"{row['failed_requests_total']} | "
            f"{row['tetragon_total_cpu_millicores_median']:.1f}m | "
            f"{row['tetragon_total_memory_mib_median']:.1f} MiB | "
            f"{row['detector_cpu_percent_one_core'] or 0:.2f}% | "
            f"{row['detector_memory_mib_median'] or 0:.1f} MiB |"
        )
    lines += [
        "",
        "Percentages use phase medians. Confidence intervals are deterministic "
        "non-parametric bootstrap intervals over complete benchmark repetitions. "
        "`kubectl top` is a lagged Metrics Server signal, so CPU/RAM values are "
        "resource snapshots rather than request-level causal estimates.",
        "",
        "```json",
        json.dumps(result["effects"], indent=2, sort_keys=True),
        "```",
        "",
    ]
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default="overhead-final")
    parser.add_argument("--tool", choices=("ab", "wrk"), default="wrk")
    parser.add_argument("--experiment-id", default=None)
    parser.add_argument("--output", default=None)
    args = parser.parse_args()

    root = Path(args.root)
    phases = latest_reports(root, args.tool, args.experiment_id)
    baseline = phases["no_tracing"]
    effects = {}
    for name, treatment, control in (
        ("tetragon_vs_no_tracing", phases["tetragon_only"], baseline),
        ("full_pipeline_vs_no_tracing", phases["full_pipeline"], baseline),
        (
            "detector_increment_vs_tetragon",
            phases["full_pipeline"], phases["tetragon_only"],
        ),
    ):
        effects[name] = {
            "throughput_loss": effect(
                treatment["rps"], control["rps"], "throughput_loss"
            ),
            "p99_latency_increase": effect(
                treatment["latency_p99_ms"], control["latency_p99_ms"],
                "latency_increase",
            ),
        }
    experiment_ids = {
        row.get("experiment_id") for row in phases.values()
    }
    if len(experiment_ids) != 1:
        raise ValueError(f"phase experiment IDs differ: {sorted(experiment_ids)}")
    result = {
        "tool": args.tool,
        "experiment_id": experiment_ids.pop(),
        "phases": phases,
        "effects": effects,
    }

    output = Path(args.output) if args.output else root / f"comparison-{args.tool}.json"
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    output.with_suffix(".md").write_text(markdown(result))
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
