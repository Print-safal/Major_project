import json
from pathlib import Path

import faiss
import numpy as np
from sentence_transformers import SentenceTransformer


BASE_DIR = Path(__file__).resolve().parent.parent

VECTOR_STORE_DIR = BASE_DIR / "vector_store"

INDEX_PATH = VECTOR_STORE_DIR / "dynamic_index.faiss"
METADATA_PATH = VECTOR_STORE_DIR / "dynamic_metadata.json"

MODEL_NAME = "all-MiniLM-L6-v2"


def load_dynamic_database():
    index = faiss.read_index(
        str(INDEX_PATH)
    )

    with open(
        METADATA_PATH,
        "r",
        encoding="utf-8"
    ) as file:
        metadata = json.load(file)

    model = SentenceTransformer(
        MODEL_NAME
    )

    return index, metadata, model


INDEX, METADATA, MODEL = load_dynamic_database()


def search_dynamic(query, top_k=5):

    query_embedding = MODEL.encode(
        [query],
        convert_to_numpy=True,
        normalize_embeddings=True
    )

    query_embedding = np.asarray(
        query_embedding,
        dtype="float32"
    )

    scores, indices = INDEX.search(
        query_embedding,
        top_k
    )

    results = []

    for score, index_id in zip(
        scores[0],
        indices[0]
    ):

        if index_id == -1:
            continue

        document = METADATA[index_id]

        results.append({
            "score": float(score),
            "cwe_id": document["cwe_id"],
            "source": document["source"],
            "section": document["section"],
            "text": document["text"]
        })

    return results


if __name__ == "__main__":

    print("=" * 60)
    print("DYNAMIC RAG SEARCH")
    print("=" * 60)

    test_queries = [
        "SQL injection",
        "OS command injection",
        "cross site scripting XSS",
        "path traversal",
        "hard coded credentials"
    ]

    for query in test_queries:

        print("\n" + "=" * 60)
        print(f"QUERY: {query}")
        print("=" * 60)

        results = search_dynamic(
            query,
            top_k=3
        )

        for rank, result in enumerate(
            results,
            start=1
        ):

            print(
                f"\nRank {rank}"
            )

            print(
                f"CWE: {result['cwe_id']}"
            )

            print(
                f"Section: {result['section']}"
            )

            print(
                f"Score: {result['score']:.4f}"
            )

            print(
                f"Text: {result['text'][:250]}"
            )