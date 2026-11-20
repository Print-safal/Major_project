import argparse
import json
from pathlib import Path
from collections import defaultdict

from rag.retrieval.cwe_aggregator import aggregate_cwe_results


TARGET_CWES = [
    "CWE-89",
    "CWE-78",
    "CWE-79",
    "CWE-22",
    "CWE-798",
]


def load_cases(path):
    with open(path, "r", encoding="utf-8") as file:
        cases = json.load(file)

    if not isinstance(cases, list):
        raise ValueError(
            "Evaluation file must contain a JSON list."
        )

    required_fields = {
        "test_id",
        "code",
        "ground_truth_cwe",
    }

    for case in cases:
        missing = required_fields - set(case.keys())

        if missing:
            raise ValueError(
                f"Case {case.get('test_id', '<unknown>')} "
                f"is missing: {sorted(missing)}"
            )

        ground_truth = case["ground_truth_cwe"]

        if ground_truth is not None:
            if ground_truth not in TARGET_CWES:
                raise ValueError(
                    f"Invalid ground_truth_cwe in "
                    f"{case['test_id']}: {ground_truth}"
                )

    return cases


def evaluate_case(case):
    results = aggregate_cwe_results(
        case["code"],
        candidate_k=30,
        top_k=5,
    )

    retrieved_cwes = [
        result["cwe_id"]
        for result in results
    ]

    expected = case["ground_truth_cwe"]

    return {
        "test_id": case["test_id"],
        "ground_truth_cwe": expected,
        "retrieved_cwes": retrieved_cwes,
        "top_1": expected in retrieved_cwes[:1],
        "top_3": expected in retrieved_cwes[:3],
        "top_5": expected in retrieved_cwes[:5],
        "top_result": (
            results[0]["cwe_id"]
            if results
            else None
        ),
    }


def calculate_metrics(cases, results):
    total = len(cases)

    top_1 = sum(
        result["top_1"]
        for result in results
    )

    top_3 = sum(
        result["top_3"]
        for result in results
    )

    top_5 = sum(
        result["top_5"]
        for result in results
    )

    vulnerable_cases = [
        case
        for case in cases
        if case["ground_truth_cwe"] is not None
    ]

    vulnerable_results = {
        result["test_id"]: result
        for result in results
    }

    exact_matches = sum(
        vulnerable_results[case["test_id"]]["top_1"]
        for case in vulnerable_cases
    )

    per_cwe = defaultdict(
        lambda: {
            "total": 0,
            "top_1": 0,
            "top_3": 0,
            "top_5": 0,
        }
    )

    for case, result in zip(cases, results):

        cwe = case["ground_truth_cwe"]

        if cwe is None:
            continue

        per_cwe[cwe]["total"] += 1

        if result["top_1"]:
            per_cwe[cwe]["top_1"] += 1

        if result["top_3"]:
            per_cwe[cwe]["top_3"] += 1

        if result["top_5"]:
            per_cwe[cwe]["top_5"] += 1

    for cwe in per_cwe:

        total_cwe = per_cwe[cwe]["total"]

        per_cwe[cwe]["top_1_recall"] = (
            per_cwe[cwe]["top_1"]
            / total_cwe
        )

        per_cwe[cwe]["top_3_recall"] = (
            per_cwe[cwe]["top_3"]
            / total_cwe
        )

        per_cwe[cwe]["top_5_recall"] = (
            per_cwe[cwe]["top_5"]
            / total_cwe
        )

    return {
        "total_cases": total,
        "top_1_matches": top_1,
        "top_3_matches": top_3,
        "top_5_matches": top_5,
        "recall_at_1": top_1 / total,
        "recall_at_3": top_3 / total,
        "recall_at_5": top_5 / total,
        "vulnerable_cases": len(
            vulnerable_cases
        ),
        "exact_cwe_matches": exact_matches,
        "exact_cwe_accuracy": (
            exact_matches
            / len(vulnerable_cases)
            if vulnerable_cases
            else 0.0
        ),
        "per_cwe": dict(per_cwe),
    }


def main():

    parser = argparse.ArgumentParser(
        description=(
            "Evaluate the dynamic RAG system "
            "on a controlled CWE benchmark."
        )
    )

    parser.add_argument(
        "--input",
        required=True,
        help=(
            "Path to the evaluation JSON "
            "dataset."
        ),
    )

    parser.add_argument(
        "--output",
        default=(
            "rag/evaluation/"
            "rag_150_case_results.json"
        ),
        help=(
            "Path for the RAG evaluation "
            "results JSON."
        ),
    )

    args = parser.parse_args()

    cases = load_cases(args.input)

    print("=" * 70)
    print("DYNAMIC RAG — CONTROLLED DATASET EVALUATION")
    print("=" * 70)

    print(
        f"Total test cases: {len(cases)}"
    )

    print(
        f"Input: {args.input}"
    )

    print()

    results = []

    for index, case in enumerate(
        cases,
        start=1
    ):

        print(
            f"[{index:03d}/{len(cases):03d}] "
            f"Running {case['test_id']}...",
            end=" ",
            flush=True,
        )

        result = evaluate_case(case)

        results.append(result)

        print(
            f"GT={case['ground_truth_cwe']} "
            f"-> Top-1={result['top_result']} "
            f"| Top-1="
            f"{'PASS' if result['top_1'] else 'FAIL'}"
        )

    metrics = calculate_metrics(
        cases,
        results
    )

    print("\n" + "=" * 70)
    print("RAG EVALUATION RESULTS")
    print("=" * 70)

    print(
        f"Top-1 Recall: "
        f"{metrics['recall_at_1'] * 100:.2f}% "
        f"({metrics['top_1_matches']}/"
        f"{metrics['total_cases']})"
    )

    print(
        f"Top-3 Recall: "
        f"{metrics['recall_at_3'] * 100:.2f}% "
        f"({metrics['top_3_matches']}/"
        f"{metrics['total_cases']})"
    )

    print(
        f"Top-5 Recall: "
        f"{metrics['recall_at_5'] * 100:.2f}% "
        f"({metrics['top_5_matches']}/"
        f"{metrics['total_cases']})"
    )

    print(
        f"Exact CWE accuracy: "
        f"{metrics['exact_cwe_accuracy'] * 100:.2f}% "
        f"({metrics['exact_cwe_matches']}/"
        f"{metrics['vulnerable_cases']})"
    )

    print("\nPer-CWE results:")

    for cwe in TARGET_CWES:

        data = metrics["per_cwe"].get(cwe)

        if not data:
            print(
                f"  {cwe}: no cases"
            )
            continue

        print(
            f"  {cwe}: "
            f"Top-1={data['top_1_recall'] * 100:.2f}% "
            f"Top-3={data['top_3_recall'] * 100:.2f}% "
            f"Top-5={data['top_5_recall'] * 100:.2f}% "
            f"(n={data['total']})"
        )

    output = {
        "experiment": {
            "system": "Dynamic RAG",
            "evaluation_set": args.input,
            "total_cases": len(cases),
            "target_cwes": TARGET_CWES,
        },
        "metrics": metrics,
        "results": results,
    }

    output_path = Path(args.output)

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with open(
        output_path,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            output,
            file,
            indent=2,
            ensure_ascii=False
        )

    print(
        f"\nResults saved to: "
        f"{output_path}"
    )


if __name__ == "__main__":
    main()