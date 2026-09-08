import json
from pathlib import Path

from vector_store.search import search






DATASET_PATH = Path(__file__).parent / "retrieval_dataset.json"


def load_dataset():
    with open(DATASET_PATH, "r", encoding="utf-8") as file:
        return json.load(file)


def evaluate():
    dataset = load_dataset()

    results = {
        "top_1": 0,
        "top_3": 0,
        "top_5": 0
    }

    total = len(dataset)

    print(f"\nEvaluating {total} queries...\n")

    for item in dataset:

        query = item["query"]
        expected = item["expected_cwe"]

        search_results = search(query, top_k=5)

        print("DEBUG TYPE:", type(search_results))
        print("DEBUG VALUE:", search_results)

        retrieved_cwes = [
        result["source"].replace(".json", "").split("_")[0]
        for result in search_results
]

        top_1_match = expected in retrieved_cwes[:1]
        top_3_match = expected in retrieved_cwes[:3]
        top_5_match = expected in retrieved_cwes[:5]

        if top_1_match:
            results["top_1"] += 1

        if top_3_match:
            results["top_3"] += 1

        if top_5_match:
            results["top_5"] += 1

        print(
            f"Query {item['id']:02d} | "
            f"Expected: {expected} | "
            f"Top-1: {'PASS' if top_1_match else 'FAIL'} | "
            f"Top-3: {'PASS' if top_3_match else 'FAIL'} | "
            f"Top-5: {'PASS' if top_5_match else 'FAIL'}"
        )

    print("\n========== RESULTS ==========")

    for k in ["top_1", "top_3", "top_5"]:

        recall = results[k] / total

        print(
            f"Recall@{k.split('_')[1]}: "
            f"{recall:.4f} "
            f"({recall * 100:.2f}%)"
        )


if __name__ == "__main__":
    evaluate()