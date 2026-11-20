from __future__ import annotations

import csv
import json
from pathlib import Path

CWES = ("CWE-22", "CWE-78", "CWE-79", "CWE-89", "CWE-798")
CLASSES = (*CWES, "SAFE-PYTHON", "MULTIPLE")


def _scores(tp, fp, fn, tn):
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "support": tp + fn,
            "precision": precision, "recall": recall, "f1": f1,
            "accuracy": (tp + tn) / (tp + fp + fn + tn) if tp + fp + fn + tn else 0.0}


def _pred_class(record):
    cw = sorted(set(record.get("predicted_cwes") or []))
    return "SAFE-PYTHON" if not cw else (cw[0] if len(cw) == 1 else "MULTIPLE")


def calculate_metrics(records, total_cases=1200):
    valid = [r for r in records if r.get("status") == "completed" and r.get("parsing_status") == "valid"]
    failed = [r for r in records if r.get("status") != "completed"]
    unparseable = [r for r in records if r.get("status") == "invalid_response"]
    counts = {"total_cases": total_cases, "successfully_evaluated": len(valid),
              "failed_cases": len(failed), "invalid_or_unparseable": len(unparseable),
              "coverage": len(valid) / total_cases if total_cases else 0.0}
    binary = [(_pred_class(r) != "SAFE-PYTHON", r.get("ground_truth_cwe") is not None) for r in valid]
    tp = sum(p and t for p, t in binary); fp = sum(p and not t for p, t in binary)
    fn = sum(not p and t for p, t in binary); tn = sum(not p and not t for p, t in binary)
    overall = _scores(tp, fp, fn, tn)
    per_cwe = {}
    for cwe in CWES:
        vals = [(cwe in (r.get("predicted_cwes") or []), r.get("ground_truth_cwe") == cwe) for r in valid]
        a = sum(p and t for p, t in vals); b = sum(p and not t for p, t in vals)
        c = sum(not p and t for p, t in vals); d = sum(not p and not t for p, t in vals)
        per_cwe[cwe] = _scores(a, b, c, d)
    safe = [r for r in valid if r.get("ground_truth_cwe") is None]
    safe_fp = sum(bool(r.get("predicted_cwes")) for r in safe)
    safe_metrics = {"support": len(safe), "correctly_identified_safe": len(safe) - safe_fp,
                    "false_positive_vulnerability_detections": safe_fp,
                    "safe_code_accuracy": (len(safe) - safe_fp) / len(safe) if safe else 0.0,
                    "false_positive_rate": safe_fp / len(safe) if safe else 0.0}
    matrix_labels = list(CLASSES)
    confusion = {truth: {pred: 0 for pred in matrix_labels} for truth in matrix_labels}
    for r in valid:
        truth = r.get("ground_truth_cwe") or "SAFE-PYTHON"
        confusion[truth][_pred_class(r)] += 1
    per_class = {}
    support = {label: sum(confusion[label].values()) for label in matrix_labels}
    for label in matrix_labels:
        class_tp = confusion[label][label]
        class_fp = sum(confusion[t][label] for t in matrix_labels if t != label)
        class_fn = sum(confusion[label][p] for p in matrix_labels if p != label)
        class_tn = len(valid) - class_tp - class_fp - class_fn
        per_class[label] = _scores(class_tp, class_fp, class_fn, class_tn)
    nonempty = [x for x in per_class.values() if x["support"]]
    macro = {metric: sum(x[metric] for x in nonempty) / len(nonempty) if nonempty else 0.0
             for metric in ("precision", "recall", "f1")}
    n = len(valid)
    weighted = {metric: sum(per_class[k][metric] * support[k] for k in matrix_labels) / n if n else 0.0
                for metric in ("precision", "recall", "f1")}
    micro_accuracy = (sum(confusion[label][label] for label in matrix_labels) / n) if n else 0.0
    micro = {"precision": micro_accuracy, "recall": micro_accuracy, "f1": micro_accuracy}
    return {"overall": {**counts, **overall}, "per_cwe_binary": per_cwe,
            "safe_code": safe_metrics,
            "classification": {"labels": matrix_labels, "confusion_matrix": confusion,
                               "per_class": per_class, "macro_avg": macro,
                               "weighted_avg": weighted, "micro_avg": micro}}


def write_reports(run_dir: Path, records, metrics):
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "metrics.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    (run_dir / "predictions.csv").write_text("", encoding="utf-8")
    fields = ["test_id", "execution_mode", "ground_truth_cwe", "predicted_cwes", "predicted_vulnerable", "predicted_class", "status", "parsing_status", "latency_seconds", "retry_count", "key_alias", "key_aliases_used"]
    with (run_dir / "predictions.csv").open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore"); writer.writeheader()
        for r in records:
            writer.writerow({**r, "predicted_cwes": ",".join(r.get("predicted_cwes") or []),
                             "key_aliases_used": ",".join(r.get("key_aliases_used") or []),
                             "predicted_class": _pred_class(r) if r.get("parsing_status") == "valid" else "INVALID"})
    confusion = metrics["classification"]["confusion_matrix"]
    with (run_dir / "confusion_matrix.csv").open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f); labels = metrics["classification"]["labels"]
        writer.writerow(["ground_truth\\prediction", *labels])
        for label in labels: writer.writerow([label, *[confusion[label][p] for p in labels]])
    overall = metrics["overall"]
    per = metrics["per_cwe_binary"]
    report = ["# Evaluation Report", "", f"Cases: {overall['total_cases']}", f"Successfully evaluated: {overall['successfully_evaluated']}", f"Failed: {overall['failed_cases']}", f"Unparseable: {overall['invalid_or_unparseable']}", f"Coverage: {overall['coverage']:.2%}", "", "## Binary vulnerability detection", f"Accuracy: {overall['accuracy']:.4f}", f"Precision: {overall['precision']:.4f}", f"Recall: {overall['recall']:.4f}", f"F1: {overall['f1']:.4f}", "", "## Per-CWE binary metrics", "| CWE | TP | FP | FN | TN | Precision | Recall | F1 |", "|---|---:|---:|---:|---:|---:|---:|---:|"]
    for c, m in per.items(): report.append(f"| {c} | {m['tp']} | {m['fp']} | {m['fn']} | {m['tn']} | {m['precision']:.4f} | {m['recall']:.4f} | {m['f1']:.4f} |")
    report += ["", "## Safe-code metrics", f"Correctly identified safe: {metrics['safe_code']['correctly_identified_safe']}/{metrics['safe_code']['support']}", f"False positive rate: {metrics['safe_code']['false_positive_rate']:.4f}", "", "## Metric definitions", "Failed API calls and invalid responses are excluded from all prediction metrics. Vulnerability-level metrics treat any CWE finding as vulnerable. Per-CWE metrics are one-vs-rest. Multiclass metrics use exact CWE for a single finding, SAFE-PYTHON for no findings, and MULTIPLE for multiple distinct CWEs. Macro averages weight observed classes equally; weighted averages weight by support; micro averages aggregate binary decisions."]
    (run_dir / "report.md").write_text("\n".join(report) + "\n", encoding="utf-8")
