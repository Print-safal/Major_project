from pathlib import Path

import faiss
import numpy as np

from ingestion.loader import load_documents
from ingestion.embedder import create_embeddings


# Project root
BASE_DIR = Path(__file__).resolve().parent.parent


# Knowledge base
KNOWLEDGE_BASE = BASE_DIR / "knowledge_base"


# Vector database files
INDEX_FILE = (
    BASE_DIR
    / "vector_store"
    / "security_knowledge.index"
)

METADATA_FILE = (
    BASE_DIR
    / "vector_store"
    / "metadata.npy"
)


def build_index():

    print("Loading documents...")

    documents = load_documents(
        str(KNOWLEDGE_BASE)
    )

    print(
        f"Loaded {len(documents)} chunks."
    )

    if not documents:
        print(
            "ERROR: No documents found "
            "in knowledge_base."
        )
        return

    # Extract text
    texts = [
        document["text"]
        for document in documents
    ]

    print("Creating embeddings...")

    embeddings = create_embeddings(
        texts
    )

    print(
        f"Embedding shape: {embeddings.shape}"
    )

    # Convert to float32
    embeddings = np.asarray(
        embeddings,
        dtype="float32"
    )

    # Vector dimension
    dimension = embeddings.shape[1]

    print(
        f"Vector dimension: {dimension}"
    )

    # Create FAISS index
    index = faiss.IndexFlatIP(
        dimension
    )

    # Add embeddings
    index.add(embeddings)

    print(
        f"Vectors stored in index: "
        f"{index.ntotal}"
    )

    # Save FAISS index
    faiss.write_index(
        index,
        str(INDEX_FILE)
    )

    # Save metadata
    np.save(
        METADATA_FILE,
        np.array(
            documents,
            dtype=object
        ),
        allow_pickle=True
    )

    print()
    print("==============================")
    print("Vector database created!")
    print("==============================")
    print(
        f"Index saved to: {INDEX_FILE}"
    )
    print(
        f"Metadata saved to: {METADATA_FILE}"
    )


if __name__ == "__main__":
    build_index()