from rag.retrieval.cwe_aggregator import aggregate_cwe_results


code = """
from flask import request

username = request.args.get("username")

query = "SELECT * FROM users WHERE username = '" + username + "'"

cursor.execute(query)
"""


print("=" * 70)
print("CWE AGGREGATION TEST")
print("=" * 70)

results = aggregate_cwe_results(
    code,
    candidate_k=30,
    top_k=5
)

print("\n" + "=" * 70)
print("RANKED CWEs")
print("=" * 70)

for rank, result in enumerate(
    results,
    start=1
):

    print(
        f"\nRank {rank}: "
        f"{result['cwe_id']} - "
        f"{result['cwe_name']}"
    )

    print(
        f"CWE Score: "
        f"{result['score']:.4f}"
    )

    print(
        f"Security Signal: "
        f"{result['security_score']:.4f}"
    )

    print(
        f"Supporting chunks: "
        f"{result['supporting_chunk_count']}"
    )

    print("\nTop supporting evidence:")

    for chunk in result[
        "supporting_chunks"
    ][:3]:

        print(
            f"  - {chunk['section']} "
            f"(combined="
            f"{chunk['combined_score']:.4f})"
        )

        print(
            f"    {chunk['text'][:180]}"
        )