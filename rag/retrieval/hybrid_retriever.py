import json
from pathlib import Path

import faiss
import numpy as np
from sentence_transformers import SentenceTransformer

from rag.retrieval.security_profiles import (
    SECURITY_PROFILES,
    calculate_security_signal,
)


BASE_DIR = Path(__file__).resolve().parents[1]

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


def semantic_search(query, top_k=20):

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
            "semantic_score": float(score),
            "cwe_id": document["cwe_id"],
            "source": document["source"],
            "section": document["section"],
            "text": document["text"],
        })

    return results


def hybrid_search(query, top_k=5):

    semantic_results = semantic_search(
        query,
        top_k=20
    )

    # -----------------------------------------------------
    # Calculate security signal for each CWE
    # -----------------------------------------------------

    security_scores = {}

    for cwe_id in SECURITY_PROFILES:

        security_scores[cwe_id] = (
            calculate_security_signal(
                query,
                cwe_id
            )
        )

    # -----------------------------------------------------
    # Combine semantic + security evidence
    # -----------------------------------------------------

    for result in semantic_results:

        cwe_id = result["cwe_id"]

        security_score = security_scores.get(
            cwe_id,
            0.0
        )

        semantic_score = result[
            "semantic_score"
        ]

        # Weighted combination.
        #
        # Semantic similarity remains the main signal.
        # Security pattern matching provides additional
        # evidence for the CWE.
        #
        combined_score = (
            0.70 * semantic_score
            + 0.30 * security_score
        )

        result["security_score"] = (
            security_score
        )

        result["combined_score"] = (
            combined_score
        )

    # -----------------------------------------------------
    # Rank by combined score
    # -----------------------------------------------------

    semantic_results.sort(
        key=lambda result: result[
            "combined_score"
        ],
        reverse=True
    )

    return semantic_results[:top_k]


if __name__ == "__main__":

    print("=" * 70)
    print("HYBRID SECURITY RETRIEVAL")
    print("=" * 70)

    test_queries = [
        "SQL injection",
        "OS command injection",
        "cross site scripting XSS",
        "path traversal",
        "hard coded credentials",
    ]

    for query in test_queries:

        print("\n" + "=" * 70)
        print(f"QUERY: {query}")
        print("=" * 70)

        results = hybrid_search(
            query,
            top_k=5
        )

        for rank, result in enumerate(
            results,
            start=1
        ):

            print(
                f"\nRank {rank}: "
                f"{result['cwe_id']}"
            )

            print(
                f"Semantic: "
                f"{result['semantic_score']:.4f}"
            )

            print(
                f"Security: "
                f"{result['security_score']:.4f}"
            )

            print(
                f"Combined: "
                f"{result['combined_score']:.4f}"
            )

            print(
                f"Section: "
                f"{result['section']}"
            )

            print(
                f"Text: "
                f"{result['text'][:200]}"
            )