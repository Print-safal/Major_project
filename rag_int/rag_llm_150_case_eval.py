import json
import argparse
import sys
import time
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


from rag_int.rag_llm_integration import review_code_with_rag

PROJECT_ROOT = Path(__file__).resolve().parents[1]

INPUT_FILE = PROJECT_ROOT / "llm" / "final_150_cases.json"

OUTPUT_FILE = (
    PROJECT_ROOT
    / "rag_int"
    / "rag_llm_150_case_results.json"
)
EXPERIMENT_CONFIG = {}

TARGET_CWES = {
    "CWE-22",
    "CWE-78",
    "CWE-79",
    "CWE-89",
    "CWE-798",
}


def load_cases():
    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        cases = json.load(f)

    if not isinstance(cases, list):
        raise ValueError(
            "Expected final_150_cases.json to contain a list."
        )

    if len(cases) != 150:
        raise ValueError(
            f"Expected 150 cases, but found {len(cases)}."
        )

    required_fields = {
        "test_id",
        "ground_truth_cwe",
        "code",
    }

    for case in cases:
        missing = required_fields - case.keys()

        if missing:
            raise ValueError(
                f"Case {case.get('test_id')} is missing: {missing}"
            )

    return cases


def load_existing_results():
    if not OUTPUT_FILE.exists():
        return None

    with open(OUTPUT_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, dict):
        raise ValueError(
            "Existing results file has an invalid format."
        )

    results = data.get("results")

    if not isinstance(results, list):
        raise ValueError(
            "Existing results file does not contain a valid results list."
        )

    if data.get("evaluation", {}).get("experiment_config") != EXPERIMENT_CONFIG:
        raise ValueError(
            "Existing output belongs to a different experiment configuration; "
            "choose a new output path or matching configuration."
        )

    return results


def save_results(results, metrics):
    output = {
        "evaluation": {
            "dataset": "final_150_cases.json",
            "total_cases": 150,
            "pipeline": "RAG + LLM",
            "target_cwes": sorted(TARGET_CWES),
            "experiment_config": EXPERIMENT_CONFIG,
        },
        "metrics": metrics,
        "results": results,
    }

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(
            output,
            f,
            indent=2,
            ensure_ascii=False,
        )


def calculate_metrics(results):
    total = len(results)

    vulnerable_cases = [
        r
        for r in results
        if r["ground_truth_cwe"] in TARGET_CWES
    ]

    safe_cases = [
        r
        for r in results
        if r["ground_truth_cwe"] is None
    ]

    # Vulnerable-case CWE hit:
    # Ground-truth CWE appears in the LLM's returned vulnerabilities.
    vulnerable_correct = sum(
        r["ground_truth_cwe"] in r["predicted_cwes"]
        for r in vulnerable_cases
    )

    vulnerable_count = len(vulnerable_cases)

    vulnerable_cwe_accuracy = (
        vulnerable_correct / vulnerable_count
        if vulnerable_count
        else 0.0
    )

    # Strict vulnerable-case accuracy:
    # Exactly one vulnerability is returned and it is the ground-truth CWE.
    strict_exact_correct = sum(
        len(r["predicted_cwes"]) == 1
        and r["predicted_cwes"][0] == r["ground_truth_cwe"]
        for r in vulnerable_cases
    )

    strict_exact_accuracy = (
        strict_exact_correct / vulnerable_count
        if vulnerable_count
        else 0.0
    )

    # Safe-code handling.
    safe_correct = sum(
        r["predicted_vulnerable"] is False
        and r["predicted_cwes"] == []
        for r in safe_cases
    )

    safe_count = len(safe_cases)

    safe_accuracy = (
        safe_correct / safe_count
        if safe_count
        else 0.0
    )

    # Overall case pass:
    # Vulnerable = expected CWE detected.
    # Safe = no vulnerability reported.
    overall_passed = sum(
        (
            r["ground_truth_cwe"] in TARGET_CWES
            and r["ground_truth_cwe"] in r["predicted_cwes"]
        )
        or (
            r["ground_truth_cwe"] is None
            and r["predicted_vulnerable"] is False
            and r["predicted_cwes"] == []
        )
        for r in results
    )

    overall_accuracy = (
        overall_passed / total
        if total
        else 0.0
    )

    # Per-CWE metrics.
    per_cwe = {}

    for cwe in sorted(TARGET_CWES):
        cwe_cases = [
            r
            for r in vulnerable_cases
            if r["ground_truth_cwe"] == cwe
        ]

        correct = sum(
            cwe in r["predicted_cwes"]
            for r in cwe_cases
        )

        per_cwe[cwe] = {
            "total": len(cwe_cases),
            "correct": correct,
            "accuracy": (
                correct / len(cwe_cases)
                if cwe_cases
                else 0.0
            ),
        }

    completed = [r for r in results if r.get("status") == "completed"]
    tp = sum(r["ground_truth_cwe"] in TARGET_CWES and r["predicted_vulnerable"] is True for r in completed)
    tn = sum(r["ground_truth_cwe"] is None and r["predicted_vulnerable"] is False for r in completed)
    fp = sum(r["ground_truth_cwe"] is None and r["predicted_vulnerable"] is True for r in completed)
    fn = sum(r["ground_truth_cwe"] in TARGET_CWES and r["predicted_vulnerable"] is False for r in completed)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
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
        "vulnerable_cases": vulnerable_count,
        "safe_cases": safe_count,
        "vulnerable_cwe_accuracy": vulnerable_cwe_accuracy,
        "strict_exact_cwe_accuracy": strict_exact_accuracy,
        "safe_code_accuracy": safe_accuracy,
        "overall_case_accuracy": overall_accuracy,
        "overall_passed": overall_passed,
        "per_cwe": per_cwe,
        "binary_confusion": {"tp": tp, "tn": tn, "fp": fp, "fn": fn},
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "assessment_confidence_distribution": confidence_distribution,
        "mean_confidence_when_correct": sum(correct_scores) / len(correct_scores) if correct_scores else None,
        "mean_confidence_when_incorrect": sum(incorrect_scores) / len(incorrect_scores) if incorrect_scores else None,
        "average_latency_seconds": sum(latencies) / len(latencies) if latencies else None,
        "token_usage_available": False,
    }


def create_result(case, review, stats, elapsed_seconds):
    ground_truth = case["ground_truth_cwe"]

    predicted_cwes = [
        vulnerability.cwe
        for vulnerability in review.vulnerabilities
    ]

    case_result = {
        "test_id": case["test_id"],
        "ground_truth_cwe": ground_truth,
        "predicted_vulnerable": review.vulnerable,
        "predicted_cwes": predicted_cwes,
        "vulnerabilities": [
            {
                "cwe": vulnerability.cwe,
                "vulnerability_name": (
                    vulnerability.vulnerability_name
                ),
                "location": vulnerability.location,
                "explanation": vulnerability.explanation,
                "remediation": vulnerability.remediation,
                "confidence": vulnerability.confidence.model_dump(),
            }
            for vulnerability in review.vulnerabilities
        ],
        "status": "completed",
    }

    if ground_truth in TARGET_CWES:
        passed = ground_truth in predicted_cwes
    else:
        passed = (
            review.vulnerable is False
            and predicted_cwes == []
        )

    case_result["pass"] = passed
    case_result["assessment_confidence"] = review.assessment_confidence.model_dump()
    case_result["retrieval_stats"] = dict(stats)
    case_result["latency_seconds"] = elapsed_seconds
    case_result["token_usage"] = None

    return case_result


def create_error_result(case, error):
    return {
        "test_id": case["test_id"],
        "ground_truth_cwe": case["ground_truth_cwe"],
        "predicted_vulnerable": None,
        "predicted_cwes": [],
        "vulnerabilities": [],
        "status": "error",
        "pass": False,
        "error": str(error),
    }


def main():
    global OUTPUT_FILE, EXPERIMENT_CONFIG
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    OUTPUT_FILE = args.output.resolve()
    from rag_int import rag_llm_integration
    from rag_int.llm_service import MODEL
    EXPERIMENT_CONFIG = {
        "contextual_evidence_enabled": rag_llm_integration.USE_CONTEXTUAL_EVIDENCE,
        "shadow_ranking_enabled": rag_llm_integration.USE_SHADOW_RANKING,
        "model": MODEL,
        "prompt": "unchanged production prompt",
    }
    print("=" * 70)
    print("RAG + LLM 150-CASE RESUME EVALUATION")
    print("=" * 70)

    cases = load_cases()

    print(f"Dataset: {INPUT_FILE}")
    print(f"Total cases: {len(cases)}")
    print()

    existing_results = load_existing_results()

    if existing_results is None:
        print("No existing results file found.")
        print("Starting a fresh evaluation.")
        print()

        results_by_id = {}

    else:
        print(f"Existing results found: {OUTPUT_FILE}")
        print(
            f"Existing result records: "
            f"{len(existing_results)}"
        )
        print()

        results_by_id = {
            result["test_id"]: result
            for result in existing_results
        }

        completed_count = sum(
            result.get("status") == "completed"
            for result in existing_results
        )

        error_count = sum(
            result.get("status") == "error"
            for result in existing_results
        )

        print(f"Completed cases already saved: {completed_count}")
        print(f"Error cases to retry: {error_count}")
        print()

    # Map dataset cases by test ID.
    cases_by_id = {
        case["test_id"]: case
        for case in cases
    }

    # Determine which cases need to be processed.
    cases_to_process = []

    for case in cases:
        test_id = case["test_id"]

        existing = results_by_id.get(test_id)

        if existing is None:
            cases_to_process.append(case)

        elif existing.get("status") == "error":
            cases_to_process.append(case)

        else:
            # Completed results are preserved.
            pass

    print(
        f"Cases that will be processed now: "
        f"{len(cases_to_process)}"
    )

    print(
        f"Cases preserved from previous run: "
        f"{len(cases) - len(cases_to_process)}"
    )

    print()

    if not cases_to_process:
        print("No cases need processing.")
        print("All existing results are already completed.")
        print()

    for case in cases_to_process:
        test_id = case["test_id"]
        ground_truth = case["ground_truth_cwe"]
        code = case["code"]

        # Find the original dataset position.
        case_number = next(
            i
            for i, item in enumerate(cases, start=1)
            if item["test_id"] == test_id
        )

        print("=" * 70)
        print(
            f"CASE {case_number}/{len(cases)}: "
            f"{test_id} | Expected: {ground_truth}"
        )
        print("=" * 70)

        try:
            started = time.perf_counter()
            review = review_code_with_rag(code)
            elapsed_seconds = time.perf_counter() - started

            case_result = create_result(
                case,
                review,
                rag_llm_integration.LAST_RAG_STATS,
                elapsed_seconds,
            )

            results_by_id[test_id] = case_result

            print(
                f"Predicted CWEs: "
                f"{case_result['predicted_cwes']}"
            )

            print(
                f"Vulnerable: "
                f"{case_result['predicted_vulnerable']}"
            )

            print(
                f"RESULT: "
                f"{'PASS' if case_result['pass'] else 'FAIL'}"
            )

        except Exception as e:
            print(f"ERROR: {e}")

            error_result = create_error_result(
                case,
                e,
            )

            results_by_id[test_id] = error_result

            print("RESULT: ERROR")

        # Rebuild results in original dataset order.
        ordered_results = [
            results_by_id[case["test_id"]]
            for case in cases
            if case["test_id"] in results_by_id
        ]

        metrics = calculate_metrics(
            ordered_results
        )

        save_results(
            ordered_results,
            metrics,
        )

        print(
            f"Saved progress: "
            f"{len(ordered_results)}/{len(cases)} cases"
        )

        print()

        # Small delay between API calls.
        time.sleep(0.5)

    # Final ordered results.
    results = [
        results_by_id[case["test_id"]]
        for case in cases
        if case["test_id"] in results_by_id
    ]

    metrics = calculate_metrics(results)

    save_results(
        results,
        metrics,
    )

    completed_count = sum(
        result.get("status") == "completed"
        for result in results
    )

    error_count = sum(
        result.get("status") == "error"
        for result in results
    )

    print("=" * 70)
    print("FINAL RAG + LLM RESULTS")
    print("=" * 70)

    print(
        f"Total cases: "
        f"{metrics['total_cases']}"
    )

    print(
        f"Completed cases: "
        f"{completed_count}"
    )

    print(
        f"Remaining errors: "
        f"{error_count}"
    )

    print(
        f"Vulnerable cases: "
        f"{metrics['vulnerable_cases']}"
    )

    print(
        f"Safe cases: "
        f"{metrics['safe_cases']}"
    )

    print()

    print(
        "Vulnerable CWE accuracy: "
        f"{metrics['vulnerable_cwe_accuracy']:.2%}"
    )

    print(
        "Strict exact CWE accuracy: "
        f"{metrics['strict_exact_cwe_accuracy']:.2%}"
    )

    print(
        "Safe-code accuracy: "
        f"{metrics['safe_code_accuracy']:.2%}"
    )

    print(
        "Overall case accuracy: "
        f"{metrics['overall_case_accuracy']:.2%}"
    )

    print(
        f"Overall passed: "
        f"{metrics['overall_passed']}/"
        f"{metrics['total_cases']}"
    )

    print()

    print("PER-CWE RESULTS")

    for cwe, data in metrics["per_cwe"].items():
        print(
            f"{cwe}: "
            f"{data['correct']}/{data['total']} "
            f"({data['accuracy']:.2%})"
        )

    print()

    if error_count > 0:
        print("REMAINING ERROR CASES")

        for result in results:
            if result.get("status") == "error":
                print(
                    f"- {result['test_id']}: "
                    f"{result.get('error', 'Unknown error')}"
                )

        print()

    print(
        "COMPLETED FAILURES "
        "(not automatically retried)"
    )

    for result in results:
        if (
            result.get("status") == "completed"
            and result.get("pass") is False
        ):
            print(
                f"- {result['test_id']}"
            )

    print()

    print(
        f"Results saved to: "
        f"{OUTPUT_FILE}"
    )

    print("=" * 70)


if __name__ == "__main__":
    main()
