"""Render deterministic Markdown/CSV tables from the validated syscall matrix."""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
from typing import Any


METHOD_LABELS = {
    "syscall__tetragon_rule_only": "Tetragon rule-only",
    "syscall__falco_rule_only": "Falco rule-only",
    "syscall__isolation_forest": "Isolation Forest",
    "syscall__lstm_only": "LSTM-only",
    "syscall__evt_pot": "LSTM + EVT-POT/adaptive calibration",
    "syscall__full_v7": "Full V7 confirmation",
    "syscall__without_fast_path": "Ablation: no fast path",
    "syscall__without_behavior_gate": "Ablation: no behavior gate",
    "syscall__without_extreme_volume_gate": "Ablation: no volume gate",
    "syscall__without_two_window_confirmation": "Ablation: one window",
    "syscall__shared_workload_model": "Ablation: shared model",
}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def number(value: Any, digits: int = 3) -> str:
    if value is None:
        return "—"
    return f"{float(value):.{digits}f}"


def load_matrix(root: Path) -> tuple[dict[str, dict], dict[str, Any]]:
    results = {}
    for path in sorted(root.glob("syscall__*/result.json")):
        document = json.loads(path.read_text())
        experiment_id = str(document.get("experiment_id", ""))
        if experiment_id in results or experiment_id not in METHOD_LABELS:
            raise ValueError("unknown or duplicate syscall experiment")
        results[experiment_id] = document
    if set(results) != set(METHOD_LABELS):
        raise ValueError("paper table requires all 11 syscall experiments")
    statistics_path = root / "paired_statistics.json"
    statistics = json.loads(statistics_path.read_text())
    if statistics.get("methods") != 11 or statistics.get("pairwise_comparisons") != 55:
        raise ValueError("paired statistics are incomplete")
    return results, statistics


def result_row(experiment_id: str, result: dict[str, Any]) -> dict[str, Any]:
    normal, attack = result["normal"], result["attack"]
    latency = result.get("latency_seconds", {})
    inference = result.get("inference_ms", {})
    recall = attack.get("recall", {})
    return {
        "experiment_id": experiment_id,
        "method": METHOD_LABELS[experiment_id],
        "normal_runs": int(normal["independent_runs"]),
        "normal_phases": int(normal["phases"]),
        "normal_windows": int(normal["windows"]),
        "normal_eligible_windows": normal.get("eligible_windows"),
        "normal_exposure_hours": float(normal["exposure_hours"]),
        "normal_false_alerts": int(normal["false_alerts"]),
        "normal_false_alerts_per_hour": float(normal["false_alerts_per_hour"]),
        "normal_false_alert_rate_per_eligible_window": normal.get(
            "false_alert_rate_per_eligible_window"
        ),
        "attack_trials": int(attack["trials"]),
        "attack_detected": int(attack["detected"]),
        "recall": float(attack["recall_point"]),
        "recall_ci_lower": float(recall["lower"]),
        "recall_ci_upper": float(recall["upper"]),
        "precision": float(attack["precision"]),
        "f1": float(attack["f1"]),
        "confirmation_latency_median_seconds": latency.get("median"),
        "confirmation_latency_p95_seconds": latency.get("p95"),
        "confirmation_latency_p99_seconds": latency.get("p99"),
        "inference_median_ms": inference.get("median"),
        "development_gate_accepted": result.get(
            "development_gate", {}
        ).get("accepted", True),
        "rejected_shared_ablation_evaluation_only": result.get(
            "development_gate", {}
        ).get("rejected_shared_ablation_evaluation_only", False),
    }


def csv_document(rows: list[dict[str, Any]]) -> str:
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
    writer.writeheader()
    writer.writerows(rows)
    return stream.getvalue()


def markdown_document(
    rows: list[dict[str, Any]], results: dict[str, dict], statistics: dict[str, Any],
    source_hashes: dict[str, str],
) -> str:
    lines = [
        "# Kết quả terminal V8 — Tetragon/Falco + ML runtime security",
        "",
        "> Bảng được sinh tự động từ 11 `result.json` đã paired và checksum; "
        "không sửa số thủ công.",
        "",
        "| Phương pháp | Normal h / feature / eligible window | "
        "False alert (giờ⁻¹ / eligible-window⁻¹) | "
        "Attack detected | Recall 95% CI | Protocol-mixed precision / F1* | "
        "Confirmation p50 / p95 / p99 (s) | Inference p50 (ms) |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for row in rows:
        lines.append(
            f"| {row['method']} | {number(row['normal_exposure_hours'], 2)} / "
            f"{row['normal_windows']} / "
            f"{row['normal_eligible_windows'] or '—'} | "
            f"{row['normal_false_alerts']} "
            f"({number(row['normal_false_alerts_per_hour'], 4)} / "
            f"{number(row['normal_false_alert_rate_per_eligible_window'], 6)}) | "
            f"{row['attack_detected']}/{row['attack_trials']} | "
            f"{number(row['recall'])} "
            f"[{number(row['recall_ci_lower'])}, {number(row['recall_ci_upper'])}] | "
            f"{number(row['precision'])} / {number(row['f1'])} | "
            f"{number(row['confirmation_latency_median_seconds'])} / "
            f"{number(row['confirmation_latency_p95_seconds'])} / "
            f"{number(row['confirmation_latency_p99_seconds'])} | "
            f"{number(row['inference_median_ms'])} |"
        )

    comparisons = statistics["comparisons"]
    attack_significant = sum(row["significant_at_0_05"] for row in comparisons)
    normal_significant = sum(row["normal_significant_at_0_05"] for row in comparisons)
    full = results["syscall__full_v7"].get("fast_path", {})
    shared_gate = results["syscall__shared_workload_model"].get(
        "development_gate", {}
    )
    normal_fast = full.get("normal_operational_evidence", {})
    attack_fast = full.get("latency_seconds", {})
    if normal_fast.get("status") == "excluded":
        normal_fast_line = (
            "- Normal: track retrospective bị loại khỏi claim; lý do: "
            f"{normal_fast.get('reason', 'evidence không hợp lệ')}."
        )
    else:
        normal_fast_line = (
            f"- Normal: {normal_fast.get('early_warning_count', '—')} warning trong "
            f"{number(normal_fast.get('exposure_hours'), 2)} giờ "
            f"({number(normal_fast.get('early_warnings_per_hour'), 4)} warning/giờ)."
        )
    lines.extend([
        "",
        "## Paired inference",
        "",
        f"- Detection recall: {attack_significant}/55 cặp khác biệt có ý nghĩa "
        "sau exact McNemar + Holm–Bonferroni.",
        f"- Normal false-alert rate: {normal_significant}/55 cặp có ý nghĩa sau "
        "exact run-level sign-flip + Holm–Bonferroni.",
        "- Recall CI dùng Wilson 95%; chênh recall/latency bootstrap theo workload. "
        "False-alert bootstrap lấy toàn bộ independent run làm block.",
        "",
        "## Fast path early warning (live, không replay)",
        "",
        normal_fast_line,
        f"- Blind attack latency p50/p95/p99: "
        f"{number(attack_fast.get('median'))}/"
        f"{number(attack_fast.get('p95'))}/"
        f"{number(attack_fast.get('p99'))} giây.",
        f"- Claim scope: {normal_fast.get('claim_limit', 'không có evidence')}.",
        "",
        "## Giới hạn bắt buộc khi trích dẫn",
        "",
        "- Shared-workload candidate không qua development gate nhưng vẫn được "
        "replay như ablation evaluation-only; không đủ điều kiện promotion."
        if shared_gate.get("rejected_shared_ablation_evaluation_only") else
        "- Shared-workload candidate đã qua development gate trước replay.",
        "- `false alerts/hour` không phải statistical FPR; rule/early-warning lane "
        "không có scored Bernoulli opportunity thống nhất.",
        "- `Precision/F1*` chỉ là số mô tả theo protocol frozen: TP là attack "
        "interval còn FP là normal window. Hai sampling unit và exposure khác "
        "nhau, nên không được trích dẫn như deployment precision/F1.",
        "- Confirmation latency là feature-window end trừ injection acknowledgement, "
        "không phải exact kernel-event latency.",
        "- Detected-only latency có selection bias; dùng restricted time-to-detection "
        "trong `paired_statistics.json` khi so sánh có miss.",
        "- Fast-path normal evidence là retrospective operational evidence; attack "
        "fast path lấy từ live blind harness và cả hai đều `replayed=false`.",
        "- Năm normal run chỉ cho exact two-sided sign-flip p nhỏ nhất 0,0625; "
        "không suy diễn significance 0,05 nếu chưa có campaign độc lập bổ sung.",
        "",
        "## Provenance",
        "",
    ])
    lines.extend(f"- `{name}`: `{digest}`" for name, digest in sorted(source_hashes.items()))
    return "\n".join(lines) + "\n"


def render(root: Path, markdown_path: Path, csv_path: Path) -> dict[str, Any]:
    results, statistics = load_matrix(root)
    rows = [result_row(experiment_id, results[experiment_id]) for experiment_id in METHOD_LABELS]
    source_hashes = {
        "paired_statistics.json": sha256(root / "paired_statistics.json"),
        **{
            f"{experiment_id}/result.json": sha256(root / experiment_id / "result.json")
            for experiment_id in METHOD_LABELS
        },
    }
    csv_path.write_text(csv_document(rows))
    markdown_path.write_text(markdown_document(
        rows, results, statistics, source_hashes,
    ))
    return {
        "methods": len(rows), "comparisons": len(statistics["comparisons"]),
        "markdown_sha256": sha256(markdown_path), "csv_sha256": sha256(csv_path),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("matrix_root", type=Path)
    parser.add_argument("--markdown", type=Path)
    parser.add_argument("--csv", type=Path)
    args = parser.parse_args()
    root = args.matrix_root.resolve()
    markdown = args.markdown or root / "syscall_results.md"
    csv_path = args.csv or root / "syscall_results.csv"
    report = render(root, markdown, csv_path)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
