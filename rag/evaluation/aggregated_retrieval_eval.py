import json
from pathlib import Path

from rag.retrieval.cwe_aggregator import aggregate_cwe_results


DATASET_PATH = Path(__file__).parent / "retrieval_dataset.json"


def load_dataset():
    with open(
        DATASET_PATH,
        "r",
        encoding="utf-8"
    ) as file:
        return json.load(file)


def evaluate():
    dataset = load_dataset()

    results = {
        "top_1": 0,
        "top_3": 0,
        "top_5": 0,
    }

    total = len(dataset)

    if total == 0:
        raise RuntimeError(
            "Evaluation dataset is empty."
        )

    print("=" * 70)
    print("AGGREGATED RAG RETRIEVAL EVALUATION")
    print("=" * 70)

    print(
        f"\nEvaluating {total} queries...\n"
    )

    for item in dataset:

        query = item["query"]
        expected = item["expected_cwe"]

        search_results = aggregate_cwe_results(
            query,
            candidate_k=30,
            top_k=5
        )

        retrieved_cwes = [
            result["cwe_id"]
            for result in search_results
        ]

        top_1_match = (
            expected in retrieved_cwes[:1]
        )

        top_3_match = (
            expected in retrieved_cwes[:3]
        )

        top_5_match = (
            expected in retrieved_cwes[:5]
        )

        if top_1_match:
            results["top_1"] += 1

        if top_3_match:
            results["top_3"] += 1

        if top_5_match:
            results["top_5"] += 1

        print(
            f"Query {item['id']:02d} | "
            f"Expected: {expected} | "
            f"Top-1: "
            f"{'PASS' if top_1_match else 'FAIL'} | "
            f"Top-3: "
            f"{'PASS' if top_3_match else 'FAIL'} | "
            f"Top-5: "
            f"{'PASS' if top_5_match else 'FAIL'}"
        )

        if not top_1_match:
            print(
                f"  Retrieved order: "
                f"{retrieved_cwes}"
            )

    print("\n" + "=" * 70)
    print("RESULTS")
    print("=" * 70)

    metrics = {}

    for k in [
        "top_1",
        "top_3",
        "top_5"
    ]:

        recall = (
            results[k] / total
        )

        recall_key = (
            f"recall@{k.split('_')[1]}"
        )

        metrics[recall_key] = recall

        print(
            f"Recall@{k.split('_')[1]}: "
            f"{recall:.4f} "
            f"({recall * 100:.2f}%)"
        )

    return metrics


if __name__ == "__main__":
    evaluate()