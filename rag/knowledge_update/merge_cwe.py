import json
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parents[1]

RAW_DIR = BASE_DIR / "knowledge_base" / "raw"
ENRICHED_DIR = BASE_DIR / "knowledge_base" / "enriched"
CURATED_DIR = BASE_DIR / "knowledge_base"


CWE_FILES = {
    "22": "CWE-22_Path_Traversal.json",
    "78": "CWE-78_Command_Injection.json",
    "79": "CWE-79_XSS.json",
    "89": "CWE-89_SQL_Injection.json",
    "798": "CWE-798_Hardcoded_Credentials.json",
}


def load_json(path):
    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


def save_json(data, path):
    with open(path, "w", encoding="utf-8") as file:
        json.dump(
            data,
            file,
            indent=2,
            ensure_ascii=False
        )


def merge_list(existing, new_items):
    """
    Merge two lists while removing exact duplicates.
    """
    result = []

    for item in existing:
        if item not in result:
            result.append(item)

    for item in new_items:
        if item not in result:
            result.append(item)

    return result


def merge_cwe(cwe_id, curated_data, enriched_data):
    """
    Preserve the MITRE data while adding the project's
    existing curated Python security knowledge.
    """

    security_analysis = enriched_data.get(
        "security_analysis",
        {}
    )

    # Existing curated fields from your original KB
    curated_fields = [
        "common_causes",
        "vulnerable_patterns",
        "vulnerable_examples",
        "secure_patterns",
        "secure_examples",
        "detection_indicators",
        "remediation",
        "keywords",
    ]

    for field in curated_fields:

        value = curated_data.get(field)

        if value is None:
            continue

        if field not in security_analysis:
            security_analysis[field] = value

        elif isinstance(value, list):
            security_analysis[field] = merge_list(
                security_analysis[field],
                value
            )

        elif isinstance(value, str):
            if not security_analysis[field]:
                security_analysis[field] = value

    # Preserve the original curated metadata
    enriched_data["project_metadata"].update({
        "language": curated_data.get(
            "language",
            "Python"
        ),
        "manually_reviewed": True,
        "curated_source": CWE_FILES[cwe_id]
    })

    enriched_data["security_analysis"] = security_analysis

    return enriched_data


def main():
    ENRICHED_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    print("=" * 60)
    print("CWE KNOWLEDGE BASE MERGE")
    print("=" * 60)

    for cwe_id, curated_filename in CWE_FILES.items():

        raw_file = RAW_DIR / f"CWE-{cwe_id}.json"
        enriched_file = ENRICHED_DIR / f"CWE-{cwe_id}.json"
        curated_file = CURATED_DIR / curated_filename

        print(f"\nProcessing CWE-{cwe_id}...")

        if not raw_file.exists():
            print(
                f"Skipping CWE-{cwe_id}: "
                f"raw file not found."
            )
            continue

        if not enriched_file.exists():
            print(
                f"Skipping CWE-{cwe_id}: "
                f"enriched file not found."
            )
            continue

        if not curated_file.exists():
            print(
                f"Skipping CWE-{cwe_id}: "
                f"curated file not found."
            )
            continue

        enriched_data = load_json(
            enriched_file
        )

        curated_data = load_json(
            curated_file
        )

        merged_data = merge_cwe(
            cwe_id,
            curated_data,
            enriched_data
        )

        save_json(
            merged_data,
            enriched_file
        )

        print(
            f"Merged curated knowledge into "
            f"CWE-{cwe_id}"
        )

    print("\n" + "=" * 60)
    print("MERGE COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    main()