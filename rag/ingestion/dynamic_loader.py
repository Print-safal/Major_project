import json
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent

ENRICHED_DIR = (
    BASE_DIR
    / "knowledge_base"
    / "enriched"
)


# MITRE sections that are useful for security-code review.
# Everything else is ignored.
USEFUL_MITRE_SECTIONS = {
    "Description",
    "ExtendedDescription",
    "LikelihoodOfExploit",
    "AlternateTerms",
    "ModesOfIntroduction",
    "CommonConsequences",
    "DetectionMethods",
    "PotentialMitigations",
    "DemonstrativeExamples",
    "ObservedExamples",
    "ApplicablePlatforms",
    "RelatedWeaknesses",
}


def load_enriched_documents():
    """
    Load enriched CWE knowledge and convert it into
    retrieval-friendly documents.
    """

    documents = []

    json_files = sorted(
        ENRICHED_DIR.glob("CWE-*.json")
    )

    for file_path in json_files:

        with open(
            file_path,
            "r",
            encoding="utf-8"
        ) as file:
            data = json.load(file)

        metadata = data.get(
            "metadata",
            {}
        )

        security = data.get(
            "security_analysis",
            {}
        )

        cwe_id = metadata.get(
            "cwe_id",
            file_path.stem
        )

        # =================================================
        # 1. MITRE CWE DATA
        # =================================================

        mitre_data = data.get(
            "mitre_data",
            {}
        )

        if isinstance(mitre_data, dict):

            weaknesses = mitre_data.get(
                "Weaknesses",
                []
            )

            for weakness in weaknesses:

                if not isinstance(
                    weakness,
                    dict
                ):
                    continue

                # -----------------------------------------
                # Basic CWE description
                # -----------------------------------------

                basic_fields = [
                    "ID",
                    "Name",
                    "Abstraction",
                    "Structure",
                    "Status",
                    "Description",
                ]

                basic_content = {}

                for field in basic_fields:

                    if field in weakness:
                        basic_content[field] = (
                            weakness[field]
                        )

                if basic_content:

                    documents.append({
                        "source": file_path.name,
                        "cwe_id": cwe_id,
                        "section": "mitre_description",
                        "text": json.dumps(
                            basic_content,
                            indent=2,
                            ensure_ascii=False
                        )
                    })

                # -----------------------------------------
                # Security-relevant MITRE sections
                # -----------------------------------------

                for key, value in weakness.items():

                    if key not in USEFUL_MITRE_SECTIONS:
                        continue

                    if value in (
                        None,
                        "",
                        [],
                        {}
                    ):
                        continue

                    if isinstance(
                        value,
                        (dict, list)
                    ):
                        text = json.dumps(
                            value,
                            indent=2,
                            ensure_ascii=False
                        )
                    else:
                        text = str(value)

                    documents.append({
                        "source": file_path.name,
                        "cwe_id": cwe_id,
                        "section": (
                            f"mitre_{key.lower()}"
                        ),
                        "text": text
                    })

        # =================================================
        # 2. PROJECT-SPECIFIC SECURITY KNOWLEDGE
        # =================================================

        for section_name, content in security.items():

            if not content:
                continue

            if isinstance(content, list):

                for index, item in enumerate(
                    content
                ):

                    if isinstance(
                        item,
                        dict
                    ):
                        text = json.dumps(
                            item,
                            indent=2,
                            ensure_ascii=False
                        )
                    else:
                        text = str(item)

                    documents.append({
                        "source": file_path.name,
                        "cwe_id": cwe_id,
                        "section": section_name,
                        "item_id": index,
                        "text": text
                    })

            else:

                documents.append({
                    "source": file_path.name,
                    "cwe_id": cwe_id,
                    "section": section_name,
                    "text": str(content)
                })

    return documents


if __name__ == "__main__":

    documents = load_enriched_documents()

    print("=" * 60)
    print("DYNAMIC KNOWLEDGE BASE LOADER")
    print("=" * 60)

    print(
        f"\nLoaded {len(documents)} knowledge documents."
    )

    print("\nSample documents:\n")

    for document in documents[:10]:

        print("-" * 60)

        print(
            f"CWE: {document['cwe_id']}"
        )

        print(
            f"Section: {document['section']}"
        )

        print(
            f"Source: {document['source']}"
        )

        print(
            f"Text: {document['text'][:300]}"
        )

    print("\n" + "=" * 60)