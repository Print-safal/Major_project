from pathlib import Path

import faiss
import numpy as np
from sentence_transformers import SentenceTransformer


# ============================================================
# Project root
# ============================================================

BASE_DIR = Path(__file__).resolve().parent.parent


# ============================================================
# Saved vector database
# ============================================================

INDEX_FILE = (
    BASE_DIR
    / "vector_store"
    / "security_knowledge.index"
)


# ============================================================
# Saved document metadata
# ============================================================

METADATA_FILE = (
    BASE_DIR
    / "vector_store"
    / "metadata.npy"
)


# ============================================================
# Same embedding model used during index creation
# ============================================================

MODEL_NAME = "all-MiniLM-L6-v2"


# ============================================================
# Load vector database
# ============================================================

def load_vector_database():

    print("Loading vector database...")

    # Load FAISS index
    index = faiss.read_index(
        str(INDEX_FILE)
    )

    # Load document metadata
    metadata = np.load(
        METADATA_FILE,
        allow_pickle=True
    )

    # Load embedding model
    model = SentenceTransformer(
        MODEL_NAME
    )

    return index, metadata, model


# ============================================================
# Load database ONCE
# ============================================================

INDEX, METADATA, MODEL = load_vector_database()


# ============================================================
# Semantic search
# ============================================================

def search(query, top_k=5):

    # Convert query into an embedding
    query_embedding = MODEL.encode(
        [query],
        convert_to_numpy=True,
        normalize_embeddings=True
    )

    # FAISS expects float32 vectors
    query_embedding = np.asarray(
        query_embedding,
        dtype="float32"
    )

    # Search the FAISS vector database
    scores, indices = INDEX.search(
        query_embedding,
        top_k
    )

    results = []

    # Process retrieved results
    for score, index_id in zip(
        scores[0],
        indices[0]
    ):

        # Ignore invalid FAISS index
        if index_id == -1:
            continue

        # Get corresponding document
        document = METADATA[index_id]

        results.append(
            {
                "score": float(score),
                "source": document["source"],
                "chunk_id": int(document["chunk_id"]),
                "text": document["text"]
            }
        )

    return results


# ============================================================
# Run directly for manual testing
# ============================================================

if __name__ == "__main__":

    query = input(
        "\nEnter security query: "
    )

    results = search(
        query,
        top_k=5
    )

    print("\n")
    print("==============================")
    print("SEARCH RESULTS")
    print("==============================")

    for i, result in enumerate(
        results,
        start=1
    ):

        print(
            f"\nResult {i}"
        )

        print(
            "Similarity Score:",
            round(result["score"], 4)
        )

        print(
            "Source:",
            result["source"]
        )

        print(
            "Chunk:",
            result["chunk_id"]
        )

        print("\nContent:")

        print(
            result["text"]
        )

        print(
            "------------------------------"
        )