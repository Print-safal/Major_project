"""Offline-safe harness for the approved 150-case and 30-case evaluations.

Run the full benchmark with ``--mode full150`` (the default), or the fixed,
approved subset with ``--mode preliminary30``. Other dataset sizes/content are
rejected. Use a distinct ``--output`` path for each experiment.
"""

import argparse
from collections import Counter
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import time


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from rag_int.confidence import (  # noqa: E402
    DEFAULT_THRESHOLDS,
    DEFAULT_WEIGHTS,
    SUPPORTED_CWES,
)
from rag_int.llm_service import MODEL, SYSTEM_PROMPT  # noqa: E402
from rag_int.rag_llm_integration import (  # noqa: E402
    USE_CONTEXTUAL_EVIDENCE,
    USE_SHADOW_RANKING,
    LAST_RAG_STATS,
    review_code_with_rag,
)


INPUT_FILE = PROJECT_ROOT / "llm" / "final_150_cases.json"
OUTPUT_FILE = PROJECT_ROOT / "rag_int" / "rag_llm_150_case_results.json"
TARGET_CWES = tuple(SUPPORTED_CWES)
EVALUATION_SCRIPT_VERSION = "rag-llm-benchmark-v3"
EVALUATION_CRITERIA_VERSION = "ground-truth-cwe-hit-or-clean-safe-v1"
CONFIDENCE_ALGORITHM_VERSION = "evidence-confidence-v1"
PROMPT_IDENTIFIER = "rag_int.llm_service.SYSTEM_PROMPT:v1"

DATASET_MODES = {
    "full150": {
        "path": PROJECT_ROOT / "llm" / "final_150_cases.json",
        "case_count": 150,
        "sha256": "00db53f028bf4421f955022ad8087ad3a23f394f749dfe2099ec90b45d7258a5",
        "distribution": {**{cwe: 25 for cwe in TARGET_CWES}, None: 25},
    },
    "preliminary30": {
        "path": PROJECT_ROOT / "rag_int" / "context_aware_30_case_subset.json",
        "case_count": 30,
        "sha256": "46aebc9fec189b86a601bf4a0fdadc91a6cca065367c00320405ccf344a640bc",
        "distribution": {**{cwe: 5 for cwe in TARGET_CWES}, None: 5},
    },
}

PROTECTED_OUTPUTS = {
    (PROJECT_ROOT / "rag_int" / name).resolve()
    for name in (
        "rag_llm_150_case_results.json",
        "rag_llm_150_case_results_historical.json",
        "rag_llm_150_case_results_backup_20261115_150726.json",
    )
}


class BenchmarkIntegrityError(ValueError):
    """Raised when an input or resume file cannot be safely evaluated."""


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_hash(value) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True,
                         separators=(",", ":")).encode("utf-8")
    return _sha256(encoded)


def validate_cases(cases, mode: str, dataset_sha256: str):
    """Validate a dataset against its fixed approved mode and checksum."""
    if mode not in DATASET_MODES:
        raise BenchmarkIntegrityError(f"Unsupported evaluation mode: {mode}")
    spec = DATASET_MODES[mode]
    if not isinstance(cases, list):
        raise BenchmarkIntegrityError("Dataset must contain a JSON list.")
    if len(cases) != spec["case_count"]:
        raise BenchmarkIntegrityError(
            f"Mode {mode} requires exactly {spec['case_count']} cases; found {len(cases)}."
        )
    if dataset_sha256 != spec["sha256"]:
        raise BenchmarkIntegrityError(
            f"Dataset SHA-256 does not match the approved {mode} dataset."
        )

    ids = []
    observed = Counter()
    required = {"test_id", "ground_truth_cwe", "code"}
    for index, case in enumerate(cases):
        if not isinstance(case, dict):
            raise BenchmarkIntegrityError(f"Case {index} must be a JSON object.")
        missing = required - case.keys()
        if missing:
            raise BenchmarkIntegrityError(
                f"Case {case.get('test_id', index)} is missing fields: {sorted(missing)}"
            )
        test_id = case["test_id"]
        cwe = case["ground_truth_cwe"]
        if not isinstance(test_id, str) or not test_id.strip():
            raise BenchmarkIntegrityError(f"Case {index} has an invalid test_id.")
        if cwe is not None and cwe not in TARGET_CWES:
            raise BenchmarkIntegrityError(f"Case {test_id} has unsupported CWE {cwe!r}.")
        if not isinstance(case["code"], str):
            raise BenchmarkIntegrityError(f"Case {test_id} has non-string code.")
        ids.append(test_id)
        observed[cwe] += 1

    if len(set(ids)) != len(ids):
        raise BenchmarkIntegrityError("Dataset contains duplicate test IDs.")
    if dict(observed) != spec["distribution"]:
        raise BenchmarkIntegrityError(
            f"Mode {mode} requires distribution {spec['distribution']}; found {dict(observed)}."
        )
    return cases


def load_cases(input_file: Path = INPUT_FILE, mode: str = "full150"):
    raw = input_file.read_bytes()
    try:
        cases = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BenchmarkIntegrityError(f"Dataset is not valid UTF-8 JSON: {exc}") from exc
    return validate_cases(cases, mode, _sha256(raw))


def build_resume_signature(cases, dataset_sha256: str, mode: str,
                           contextual_enabled: bool, shadow_enabled: bool,
                           model_identifier: str = MODEL,
                           prompt_text: str = SYSTEM_PROMPT,
                           weights=None, thresholds=None):
    weights = weights if weights is not None else DEFAULT_WEIGHTS
    thresholds = thresholds if thresholds is not None else DEFAULT_THRESHOLDS
    ordered_labels = [
        {"test_id": case["test_id"], "ground_truth_cwe": case["ground_truth_cwe"]}
        for case in cases
    ]
    return {
        "signature_version": 1,
        "mode": mode,
        "dataset_sha256": dataset_sha256,
        "ordered_cases_sha256": _canonical_hash(ordered_labels),
        "case_count": len(cases),
        "target_cwes": sorted(TARGET_CWES),
        "model_identifier": model_identifier,
        "contextual_evidence_enabled": bool(contextual_enabled),
        "shadow_ranking_enabled": bool(shadow_enabled),
        "prompt": {
            "identifier": PROMPT_IDENTIFIER,
            "sha256": _sha256(prompt_text.encode("utf-8")),
        },
        "confidence_scoring": {
            "algorithm_version": CONFIDENCE_ALGORITHM_VERSION,
            "implementation_sha256": _sha256(Path(__file__).with_name("confidence.py").read_bytes()),
            "weights": asdict(weights),
            "thresholds": asdict(thresholds),
        },
        "evaluation_script_version": EVALUATION_SCRIPT_VERSION,
        "evaluation_script_sha256": _sha256(Path(__file__).read_bytes()),
        "evaluation_criteria_version": EVALUATION_CRITERIA_VERSION,
    }


def validate_resume_records(results, cases):
    """Check every saved row; omitted expected IDs remain pending resume work."""
    if not isinstance(results, list):
        raise BenchmarkIntegrityError("Existing results must be a list.")
    expected = {case["test_id"]: case["ground_truth_cwe"] for case in cases}
    positions = {case["test_id"]: index for index, case in enumerate(cases)}
    seen = set()
    previous_index = -1
    for index, result in enumerate(results):
        if not isinstance(result, dict):
            raise BenchmarkIntegrityError(f"Saved result {index} is not an object.")
        test_id = result.get("test_id")
        if not isinstance(test_id, str) or not test_id:
            raise BenchmarkIntegrityError(f"Saved result {index} is missing a valid test_id.")
        if test_id in seen:
            raise BenchmarkIntegrityError(f"Duplicate saved result ID: {test_id}")
        if test_id not in expected:
            raise BenchmarkIntegrityError(f"Unexpected saved result ID: {test_id}")
        if result.get("ground_truth_cwe", object()) != expected[test_id]:
            raise BenchmarkIntegrityError(f"Ground-truth label mismatch for {test_id}.")
        status = result.get("status")
        if status not in {"completed", "error"}:
            raise BenchmarkIntegrityError(f"Invalid status for {test_id}: {status!r}")
        if status == "completed":
            if not isinstance(result.get("predicted_cwes"), list):
                raise BenchmarkIntegrityError(f"Completed result {test_id} lacks predicted_cwes.")
            if not isinstance(result.get("pass"), bool):
                raise BenchmarkIntegrityError(f"Completed result {test_id} lacks a boolean pass value.")
            if not isinstance(result.get("predicted_vulnerable"), bool):
                raise BenchmarkIntegrityError(f"Completed result {test_id} lacks a boolean prediction.")
        elif not isinstance(result.get("error"), str) or not result["error"]:
            raise BenchmarkIntegrityError(f"Error result {test_id} lacks its error details.")
        elif result.get("predicted_vulnerable") is not None:
            raise BenchmarkIntegrityError(f"Error result {test_id} must not contain a prediction.")

        current_index = positions[test_id]
        if current_index <= previous_index:
            raise BenchmarkIntegrityError("Saved results are not in dataset order.")
        previous_index = current_index
        seen.add(test_id)
    return results


def load_existing_results(output_file: Path, resume_signature, cases):
    if not output_file.exists():
        return None
    try:
        data = json.loads(output_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BenchmarkIntegrityError(f"Cannot read existing result file: {exc}") from exc
    if not isinstance(data, dict):
        raise BenchmarkIntegrityError("Existing results file has an invalid format.")
    saved_signature = data.get("resume_signature")
    if saved_signature is None:
        raise BenchmarkIntegrityError(
            "Existing results lack a resume signature. Use a new output file; "
            "legacy results are not migrated or trusted automatically."
        )
    if saved_signature != resume_signature:
        raise BenchmarkIntegrityError(
            "Existing output has a different dataset, model, feature, prompt, "
            "confidence, or evaluation signature. Choose a new output file."
        )
    results = data.get("results")
    validate_resume_records(results, cases)
    return results


def save_results(output_file: Path, results, metrics, mode: str,
                 input_file: Path, resume_signature):
    output_file.parent.mkdir(parents=True, exist_ok=True)
    output = {
        "evaluation": {
            "mode": mode,
            "dataset": input_file.name,
            "total_cases": DATASET_MODES[mode]["case_count"],
            "pipeline": "RAG + LLM",
            "target_cwes": sorted(TARGET_CWES),
        },
        "resume_signature": resume_signature,
        "metrics": metrics,
        "results": results,
    }
    # Replace atomically so interruption cannot truncate a previously saved run.
    fd, temporary_name = tempfile.mkstemp(prefix=f".{output_file.name}.", suffix=".tmp",
                                          dir=output_file.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as stream:
            json.dump(output, stream, indent=2, ensure_ascii=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_name, output_file)
    except Exception:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise


def _ratio(numerator, denominator):
    return numerator / denominator if denominator else None


def calculate_metrics(results, expected_total=None):
    """Calculate accuracy from completed predictions only; errors stay errors."""
    attempted = len(results)
    completed = [result for result in results if result.get("status") == "completed"]
    errors = [result for result in results if result.get("status") == "error"]
    correct = sum(result["pass"] is True for result in completed)
    incorrect = len(completed) - correct
    total = expected_total if expected_total is not None else attempted
    pending = max(total - attempted, 0)

    completed_vulnerable = [r for r in completed if r["ground_truth_cwe"] in TARGET_CWES]
    completed_safe = [r for r in completed if r["ground_truth_cwe"] is None]
    vulnerable_correct = sum(r["pass"] is True for r in completed_vulnerable)
    safe_correct = sum(r["pass"] is True for r in completed_safe)

    per_cwe = {}
    for cwe in sorted(TARGET_CWES):
        cwe_cases = [r for r in completed_vulnerable if r["ground_truth_cwe"] == cwe]
        cwe_correct = sum(r["pass"] is True for r in cwe_cases)
        per_cwe[cwe] = {
            "total": len(cwe_cases),
            "correct": cwe_correct,
            "incorrect": len(cwe_cases) - cwe_correct,
            "accuracy": _ratio(cwe_correct, len(cwe_cases)),
        }

    tp = sum(r["ground_truth_cwe"] is not None and r["predicted_vulnerable"] is True for r in completed)
    tn = sum(r["ground_truth_cwe"] is None and r["predicted_vulnerable"] is False for r in completed)
    fp = sum(r["ground_truth_cwe"] is None and r["predicted_vulnerable"] is True for r in completed)
    fn = sum(r["ground_truth_cwe"] is not None and r["predicted_vulnerable"] is False for r in completed)
    precision = _ratio(tp, tp + fp)
    recall = _ratio(tp, tp + fn)
    f1 = _ratio(2 * precision * recall, precision + recall) if precision is not None and recall is not None else None
    if len(completed) == 0:
        accuracy = vulnerable_accuracy = safe_accuracy = strict_exact_accuracy = None
    else:
        accuracy = _ratio(correct, len(completed))
        vulnerable_accuracy = _ratio(vulnerable_correct, len(completed_vulnerable))
        safe_accuracy = _ratio(safe_correct, len(completed_safe))
        strict_correct = sum(
            len(r["predicted_cwes"]) == 1 and r["predicted_cwes"][0] == r["ground_truth_cwe"]
            for r in completed_vulnerable
        )
        strict_exact_accuracy = _ratio(strict_correct, len(completed_vulnerable))

    confidence_distribution = {level: 0 for level in ("High", "Medium", "Low", "Undetermined")}
    for result in completed:
        level = result.get("assessment_confidence", {}).get("level")
        if level in confidence_distribution:
            confidence_distribution[level] += 1
    correct_scores = [r["assessment_confidence"]["score"] for r in completed
                      if r.get("pass") and r.get("assessment_confidence", {}).get("score") is not None]
    incorrect_scores = [r["assessment_confidence"]["score"] for r in completed
                        if not r.get("pass") and r.get("assessment_confidence", {}).get("score") is not None]
    latencies = [r["latency_seconds"] for r in completed if r.get("latency_seconds") is not None]

    return {
        "total_cases": total,
        "attempted_count": attempted,
        "completed_count": len(completed),
        "correct_count": correct,
        "incorrect_count": incorrect,
        "error_count": len(errors),
        "pending_count": pending,
        "completion_rate": _ratio(len(completed), total),
        "vulnerable_completed_count": len(completed_vulnerable),
        "safe_completed_count": len(completed_safe),
        "vulnerable_cwe_accuracy": vulnerable_accuracy,
        "strict_exact_cwe_accuracy": strict_exact_accuracy,
        "safe_code_accuracy": safe_accuracy,
        "overall_case_accuracy": accuracy,
        "overall_passed": correct,
        "per_cwe": per_cwe,
        "binary_confusion": {"tp": tp, "tn": tn, "fp": fp, "fn": fn},
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "assessment_confidence_distribution": confidence_distribution,
        "mean_confidence_when_correct": _ratio(sum(correct_scores), len(correct_scores)),
        "mean_confidence_when_incorrect": _ratio(sum(incorrect_scores), len(incorrect_scores)),
        "average_latency_seconds": _ratio(sum(latencies), len(latencies)),
        "token_usage_available": False,
    }


def create_result(case, review, stats, elapsed_seconds):
    predicted_cwes = [vulnerability.cwe for vulnerability in review.vulnerabilities]
    if case["ground_truth_cwe"] in TARGET_CWES:
        passed = case["ground_truth_cwe"] in predicted_cwes
    else:
        passed = review.vulnerable is False and predicted_cwes == []
    return {
        "test_id": case["test_id"],
        "ground_truth_cwe": case["ground_truth_cwe"],
        "predicted_vulnerable": review.vulnerable,
        "predicted_cwes": predicted_cwes,
        "vulnerabilities": [
            {
                "cwe": vulnerability.cwe,
                "vulnerability_name": vulnerability.vulnerability_name,
                "location": vulnerability.location,
                "explanation": vulnerability.explanation,
                "remediation": vulnerability.remediation,
                "confidence": vulnerability.confidence.model_dump(),
            }
            for vulnerability in review.vulnerabilities
        ],
        "status": "completed",
        "pass": passed,
        "assessment_confidence": review.assessment_confidence.model_dump(),
        "retrieval_stats": dict(stats),
        "latency_seconds": elapsed_seconds,
        "token_usage": None,
    }


def create_error_result(case, error):
    return {
        "test_id": case["test_id"],
        "ground_truth_cwe": case["ground_truth_cwe"],
        "predicted_vulnerable": None,
        "predicted_cwes": [],
        "vulnerabilities": [],
        "status": "error",
        "error": str(error),
    }


def preserve_prior_errors(new_result, previous_result):
    """Keep transient API error details when retrying the same case."""
    if not previous_result:
        return new_result
    prior = list(previous_result.get("prior_error_attempts", []))
    if previous_result.get("status") == "error":
        prior.append({"error": previous_result.get("error", "Unknown error")})
    if prior:
        new_result["prior_error_attempts"] = prior
    return new_result


def run_benchmark(input_file: Path, output_file: Path, mode: str):
    output_file = output_file.resolve()
    input_file = input_file.resolve()
    if output_file == input_file or output_file in PROTECTED_OUTPUTS:
        raise BenchmarkIntegrityError(f"Refusing to overwrite protected input/result: {output_file}")
    raw = input_file.read_bytes()
    dataset_sha256 = _sha256(raw)
    cases = load_cases(input_file, mode)
    signature = build_resume_signature(
        cases, dataset_sha256, mode, USE_CONTEXTUAL_EVIDENCE, USE_SHADOW_RANKING
    )
    existing = load_existing_results(output_file, signature, cases)
    results_by_id = {r["test_id"]: r for r in (existing or [])}
    case_positions = {case["test_id"]: index for index, case in enumerate(cases)}
    pending = [case for case in cases if results_by_id.get(case["test_id"], {}).get("status") != "completed"]

    print(f"Mode: {mode}; dataset: {input_file}; cases: {len(cases)}")
    print(f"Feature flags: contextual={USE_CONTEXTUAL_EVIDENCE}, shadow={USE_SHADOW_RANKING}")
    print(f"Attempted: {len(results_by_id)}; completed preserved: {sum(r.get('status') == 'completed' for r in results_by_id.values())}; to process/retry: {len(pending)}")

    for case in pending:
        print(f"CASE {case_positions[case['test_id']] + 1}/{len(cases)}: {case['test_id']} | Expected: {case['ground_truth_cwe']}")
        previous_result = results_by_id.get(case["test_id"])
        try:
            started = time.perf_counter()
            review = review_code_with_rag(case["code"])
            result = create_result(case, review, LAST_RAG_STATS, time.perf_counter() - started)
            results_by_id[case["test_id"]] = preserve_prior_errors(result, previous_result)
            print(f"Predicted CWEs: {result['predicted_cwes']} | {'PASS' if result['pass'] else 'FAIL'}")
        except Exception as exc:  # Persist provider failures distinctly from predictions.
            result = preserve_prior_errors(create_error_result(case, exc), previous_result)
            results_by_id[case["test_id"]] = result
            print(f"ERROR: {exc}")

        ordered = [results_by_id[c["test_id"]] for c in cases if c["test_id"] in results_by_id]
        validate_resume_records(ordered, cases)
        metrics = calculate_metrics(ordered, expected_total=len(cases))
        save_results(output_file, ordered, metrics, mode, input_file, signature)
        print(f"Saved progress: {len(ordered)}/{len(cases)}; completed={metrics['completed_count']}; errors={metrics['error_count']}")
        time.sleep(0.5)

    final_results = [results_by_id[c["test_id"]] for c in cases if c["test_id"] in results_by_id]
    metrics = calculate_metrics(final_results, expected_total=len(cases))
    save_results(output_file, final_results, metrics, mode, input_file, signature)
    print(json.dumps(metrics, indent=2))
    print(f"Results saved to: {output_file}")
    return metrics


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True,
                        help="Dedicated result JSON path; use a new path for each experiment.")
    parser.add_argument("--input", type=Path, default=INPUT_FILE)
    parser.add_argument("--mode", choices=tuple(DATASET_MODES), default="full150",
                        help="full150 validates the fixed dataset; preliminary30 validates the approved subset.")
    args = parser.parse_args()
    run_benchmark(args.input, args.output, args.mode)


if __name__ == "__main__":
    main()
