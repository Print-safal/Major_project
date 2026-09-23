import json
from pathlib import Path

import faiss
import numpy as np

from rag.ingestion.dynamic_loader import load_enriched_documents
from rag.ingestion.embedder import create_embeddings


BASE_DIR = Path(__file__).resolve().parent.parent

VECTOR_STORE_DIR = BASE_DIR / "vector_store"

INDEX_PATH = VECTOR_STORE_DIR / "dynamic_index.faiss"
METADATA_PATH = VECTOR_STORE_DIR / "dynamic_metadata.json"


def build_dynamic_index():
    print("=" * 60)
    print("DYNAMIC FAISS INDEX BUILDER")
    print("=" * 60)

    # -----------------------------------------------------
    # Load structured knowledge
    # -----------------------------------------------------

    print("\nLoading enriched knowledge...")

    documents = load_enriched_documents()

    if not documents:
        raise RuntimeError(
            "No documents were loaded from the enriched knowledge base."
        )

    print(
        f"Loaded {len(documents)} knowledge documents."
    )

    # -----------------------------------------------------
    # Extract text
    # -----------------------------------------------------

    texts = [
        document["text"]
        for document in documents
    ]

    # -----------------------------------------------------
    # Create embeddings
    # -----------------------------------------------------

    print("\nCreating embeddings...")

    embeddings = create_embeddings(texts)

    embeddings = np.asarray(
        embeddings,
        dtype="float32"
    )

    print(
        f"Embedding shape: {embeddings.shape}"
    )

    # -----------------------------------------------------
    # Build FAISS index
    # -----------------------------------------------------

    print("\nBuilding FAISS index...")

    dimension = embeddings.shape[1]

    index = faiss.IndexFlatIP(
        dimension
    )

    index.add(embeddings)

    print(
        f"FAISS vectors: {index.ntotal}"
    )

    # -----------------------------------------------------
    # Save index
    # -----------------------------------------------------

    VECTOR_STORE_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    faiss.write_index(
        index,
        str(INDEX_PATH)
    )

    # -----------------------------------------------------
    # Save metadata
    # -----------------------------------------------------

    metadata = []

    for document in documents:

        metadata.append({
            "source": document["source"],
            "cwe_id": document["cwe_id"],
            "section": document["section"],
            "item_id": document.get(
                "item_id"
            ),
            "text": document["text"]
        })

    with open(
        METADATA_PATH,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            metadata,
            file,
            indent=2,
            ensure_ascii=False
        )

    print("\nSaved dynamic index:")
    print(INDEX_PATH)

    print("\nSaved dynamic metadata:")
    print(METADATA_PATH)

    print("\n" + "=" * 60)
    print("DYNAMIC INDEX BUILD COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    build_dynamic_index()