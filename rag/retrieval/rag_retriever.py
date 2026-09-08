from vector_store.search import search


def retrieve_security_context(query, top_k=5):
    """
    Retrieve the most relevant security knowledge
    for a given code-review query.
    """

    results = search(
        query,
        top_k=top_k
    )

    context_parts = []

    for i, result in enumerate(results, start=1):

        context_parts.append(
            f"""
--- Security Knowledge {i} ---

CWE: {result["source"].replace(".json", "").split("_")[0]}

Source: {result["source"]}

Similarity Score: {result["score"]:.4f}

Knowledge:
{result["text"]}
"""
        )

    context = "\n".join(context_parts)

    return {
        "query": query,
        "results": results,
        "context": context
    }


if __name__ == "__main__":

    query = input(
        "\nEnter code/security query: "
    )

    retrieved = retrieve_security_context(
        query,
        top_k=5
    )

    print("\n")
    print("=" * 70)
    print("RAG RETRIEVAL CONTEXT")
    print("=" * 70)

    print(retrieved["context"])

    print("=" * 70)