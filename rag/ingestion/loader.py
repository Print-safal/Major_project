from pathlib import Path
import json

from ingestion.chunker import chunk_text


def load_documents(directory: str):

    documents = []

    directory_path = Path(directory)

    print("Looking for knowledge files in:")
    print(directory_path.resolve())

    # Find JSON files
    json_files = list(directory_path.glob("*.json"))

    print(f"Found {len(json_files)} JSON files.")

    for file_path in json_files:

        print(f"Loading: {file_path.name}")

        try:
            with open(
                file_path,
                "r",
                encoding="utf-8"
            ) as file:

                data = json.load(file)

            # Convert JSON data into text
            text = json.dumps(
                data,
                indent=2,
                ensure_ascii=False
            )

            # Split into chunks
            chunks = chunk_text(text)

            for index, chunk in enumerate(chunks):

                documents.append({
                    "source": file_path.name,
                    "chunk_id": index,
                    "text": chunk
                })

        except Exception as e:

            print(
                f"ERROR loading {file_path.name}: {e}"
            )

    return documents


if __name__ == "__main__":

    # Project root / knowledge_base
    BASE_DIR = Path(__file__).resolve().parent.parent

    KNOWLEDGE_BASE = BASE_DIR / "knowledge_base"

    documents = load_documents(
        str(KNOWLEDGE_BASE)
    )

    print()
    print("==============================")
    print(f"Total chunks: {len(documents)}")
    print("==============================")

    for document in documents[:5]:

        print()
        print("------------------------------")

        print(
            "Source:",
            document["source"]
        )

        print(
            "Chunk:",
            document["chunk_id"]
        )

        print(
            document["text"][:300]
        )