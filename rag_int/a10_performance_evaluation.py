import json
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from rag_int.rag_llm_integration import (
    review_code_with_rag,
    LAST_RAG_STATS,
)
from rag_int.llm_service import LAST_CALL_STATS


INPUT_FILE = PROJECT_ROOT / "llm" / "final_150_cases.json"

OUTPUT_FILE = (
    PROJECT_ROOT
    / "rag_int"
    / "a10_performance_results.json"
)

MODEL = "openai/gpt-oss-120b"


def load_cases():
    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        cases = json.load(f)

    if not isinstance(cases, list) or len(cases) != 150:
        raise ValueError(
            f"Expected 150 cases, found {len(cases)}"
        )

    return cases


def load_existing_results():
    if not OUTPUT_FILE.exists():
        return {}

    with open(OUTPUT_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)

    existing = data.get("results", [])

    return {
        result["test_id"]: result
        for result in existing
        if "test_id" in result
    }


def is_successful(result):
    """Only skip cases with complete successful measurements."""

    required_fields = [
        "rag_retrieval_latency_seconds",
        "llm_latency_seconds",
        "total_pipeline_latency_seconds",
        "prompt_tokens",
        "completion_tokens",
        "total_tokens",
    ]

    return (
        result.get("status") == "completed"
        and all(
            isinstance(result.get(field), (int, float))
            for field in required_fields
        )
    )


def is_rate_limit_error(error):
    """Detect Groq 429 rate-limit errors."""

    message = str(error).lower()

    if getattr(error, "status_code", None) == 429:
        return True

    response = getattr(error, "response", None)

    if response is not None:
        if getattr(response, "status_code", None) == 429:
            return True

    keywords = [
        "rate limit reached",
        "rate_limit_exceeded",
        "tokens per day",
        "tokens per minute",
        "too many requests",
        "error code: 429",
        "status code: 429",
    ]

    return any(keyword in message for keyword in keywords)


def calculate_summary(results):
    completed = [
        r for r in results
        if is_successful(r)
    ]

    def average(field):
        values = [
            r[field]
            for r in completed
            if isinstance(r.get(field), (int, float))
        ]

        return sum(values) / len(values) if values else None

    return {
        "total_cases": len(results),
        "completed_cases": len(completed),
        "error_cases": len(results) - len(completed),

        "average_rag_latency_seconds": average(
            "rag_retrieval_latency_seconds"
        ),
        "average_llm_latency_seconds": average(
            "llm_latency_seconds"
        ),
        "average_total_pipeline_latency_seconds": average(
            "total_pipeline_latency_seconds"
        ),

        "average_prompt_tokens": average("prompt_tokens"),
        "average_completion_tokens": average("completion_tokens"),
        "average_total_tokens": average("total_tokens"),

        "token_usage_recorded_cases": len([
            r for r in results
            if isinstance(r.get("total_tokens"), (int, float))
        ]),

        "total_prompt_tokens": sum(
            r.get("prompt_tokens") or 0 for r in results
        ),
        "total_completion_tokens": sum(
            r.get("completion_tokens") or 0 for r in results
        ),
        "total_tokens_used": sum(
            r.get("total_tokens") or 0 for r in results
        ),
    }


def save_results(results_by_id, cases):
    ordered_results = [
        results_by_id[case["test_id"]]
        for case in cases
        if case["test_id"] in results_by_id
    ]

    output = {
        "evaluation": {
            "dataset": "final_150_cases.json",
            "total_cases": 150,
            "model": MODEL,
            "pipeline": "RAG + LLM",
        },
        "summary": calculate_summary(ordered_results),
        "results": ordered_results,
    }

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)


def main():
    cases = load_cases()
    results_by_id = load_existing_results()

    print("=" * 65)
    print("A10 - LATENCY AND TOKEN USAGE EVALUATION")
    print("=" * 65)

    print(f"Total dataset cases: {len(cases)}")

    completed_before = sum(
        is_successful(results_by_id.get(case["test_id"], {}))
        for case in cases
    )

    print(f"Existing successful cases: {completed_before}")

    cases_to_process = [
        case for case in cases
        if not is_successful(
            results_by_id.get(case["test_id"], {})
        )
    ]

    print(f"Cases remaining: {len(cases_to_process)}")
    print("Successful cases will NOT be called again.")
    print()

    if not cases_to_process:
        print("All 150 cases already have successful measurements.")

    for index, case in enumerate(cases_to_process, start=1):
        test_id = case["test_id"]
        code = case["code"]

        print(
            f"[{index}/{len(cases_to_process)}] "
            f"Processing {test_id}..."
        )

        LAST_RAG_STATS.clear()
        LAST_CALL_STATS.clear()

        pipeline_start = time.perf_counter()

        try:
            review = review_code_with_rag(code)

            total_latency = time.perf_counter() - pipeline_start

            result = {
                "test_id": test_id,
                "status": "completed",
                "predicted_vulnerable": review.vulnerable,
                "predicted_cwes": [
                    v.cwe for v in review.vulnerabilities
                ],
            }

            print("Result: COMPLETED")

        except Exception as e:
            total_latency = time.perf_counter() - pipeline_start

            result = {
                "test_id": test_id,
                "status": "error",
                "error": str(e),
            }

            result.update({
                "rag_retrieval_latency_seconds":
                    LAST_RAG_STATS.get("retrieval_latency_seconds"),
                "llm_latency_seconds":
                    LAST_CALL_STATS.get("llm_latency_seconds"),
                "total_pipeline_latency_seconds": total_latency,
                "prompt_tokens": LAST_CALL_STATS.get("prompt_tokens"),
                "completion_tokens": LAST_CALL_STATS.get("completion_tokens"),
                "total_tokens": LAST_CALL_STATS.get("total_tokens"),
            })

            results_by_id[test_id] = result
            save_results(results_by_id, cases)

            if is_rate_limit_error(e):
                print("\nGROQ RATE LIMIT DETECTED.")
                print("Stopping immediately to protect your API quota.")
                print(f"Details: {e}")
                print("Wait for the rate limit to reset, then run again.")
                break

            print(f"Result: ERROR - {e}")
            print("This case will be retried on the next run.")

            time.sleep(1)
            continue

        result.update({
            "rag_retrieval_latency_seconds":
                LAST_RAG_STATS.get("retrieval_latency_seconds"),
            "llm_latency_seconds":
                LAST_CALL_STATS.get("llm_latency_seconds"),
            "total_pipeline_latency_seconds": total_latency,
            "prompt_tokens": LAST_CALL_STATS.get("prompt_tokens"),
            "completion_tokens": LAST_CALL_STATS.get("completion_tokens"),
            "total_tokens": LAST_CALL_STATS.get("total_tokens"),
        })

        results_by_id[test_id] = result

        # Save immediately after each successful case.
        save_results(results_by_id, cases)

        print(f"Tokens recorded: {result['total_tokens']}")
        print()

        time.sleep(0.5)

    # Final save in original dataset order.
    save_results(results_by_id, cases)

    with open(OUTPUT_FILE, "r", encoding="utf-8") as f:
        saved_data = json.load(f)

    summary = saved_data["summary"]

    print("\n" + "=" * 65)
    print("A10 PERFORMANCE SUMMARY")
    print("=" * 65)

    for key, value in summary.items():
        print(f"{key}: {value}")

    print(f"\nSaved to: {OUTPUT_FILE}")
    print("=" * 65)


if __name__ == "__main__":
    main()