import json
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parents[1]

RAW_DIR = BASE_DIR / "knowledge_base" / "raw"
ENRICHED_DIR = BASE_DIR / "knowledge_base" / "enriched"


CWE_IDS = [
    "22",
    "78",
    "79",
    "89",
    "798",
]


def load_json(path):
    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


def extract_cwe_data(raw_data):
    """
    Extract the useful CWE information while keeping
    the original MITRE data available.
    """

    if isinstance(raw_data, dict):
        return raw_data

    if isinstance(raw_data, list):
        if len(raw_data) > 0:
            return raw_data[0]

    return {}


def enrich_cwe(cwe_id, raw_data):
    data = extract_cwe_data(raw_data)

    enriched = {
        "metadata": {
            "cwe_id": f"CWE-{cwe_id}",
            "source": "MITRE CWE REST API",
            "source_type": "official",
            "automatically_fetched": True
        },

        "mitre_data": data,

        "security_analysis": {
            "sources": [],
            "sinks": [],
            "dangerous_apis": [],
            "data_flow_patterns": [],
            "vulnerable_patterns": [],
            "secure_patterns": [],
            "vulnerable_examples": [],
            "secure_examples": [],
            "false_positive_cases": [],
            "detection_indicators": [],
            "exclusion_rules": [],
            "distinguishing_features": [],
            "framework_specific": [],
            "common_incomplete_fixes": []
        },

        "project_metadata": {
            "language": "Python",
            "project": "AI Code Reviewer",
            "manually_reviewed": False
        }
    }

    return enriched


def main():
    ENRICHED_DIR.mkdir(parents=True, exist_ok=True)

    print("=" * 60)
    print("CWE KNOWLEDGE BASE ENRICHMENT")
    print("=" * 60)

    for cwe_id in CWE_IDS:

        raw_file = RAW_DIR / f"CWE-{cwe_id}.json"

        if not raw_file.exists():
            print(f"\nSkipping CWE-{cwe_id}: raw file not found.")
            continue

        print(f"\nEnriching CWE-{cwe_id}...")

        raw_data = load_json(raw_file)

        enriched_data = enrich_cwe(
            cwe_id,
            raw_data
        )

        output_file = (
            ENRICHED_DIR / f"CWE-{cwe_id}.json"
        )

        with open(
            output_file,
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(
                enriched_data,
                file,
                indent=2,
                ensure_ascii=False
            )

        print(f"Saved: {output_file}")

    print("\n" + "=" * 60)
    print("ENRICHMENT COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    main()