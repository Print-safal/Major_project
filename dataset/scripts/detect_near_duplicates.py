import json
import re
from pathlib import Path
from difflib import SequenceMatcher
from itertools import combinations

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "dataset" / "exclusion_manifest.json"
OUTPUT = ROOT / "dataset" / "near_duplicate_report.json"

SIMILARITY_THRESHOLD = 0.85


def normalize_code(code):
    """Normalize formatting while preserving identifiers and logic."""
    code = code or ""
    code = re.sub(r"#.*", "", code)
    code = re.sub(r"\s+", " ", code)
    return code.strip().lower()


def main():
    with MANIFEST.open("r", encoding="utf-8") as f:
        manifest = json.load(f)

    # Inspect manifest structure.
    records = manifest.get("records", [])

    if not records:
        raise ValueError(
            "No records found under manifest['records']. "
            "Inspect the manifest structure before proceeding."
        )

    candidates = []

    for record in records:
        code = record.get("code", "")
        if code.strip():
            candidates.append({
                "source": record.get("source", "unknown"),
                "test_id": record.get("test_id", "unknown"),
                "code": code,
                "normalized": normalize_code(code)
            })

    matches = []

    for a, b in combinations(candidates, 2):
        score = SequenceMatcher(
            None, a["normalized"], b["normalized"]
        ).ratio()

        if score >= SIMILARITY_THRESHOLD:
            matches.append({
                "sample_a": {
                    "source": a["source"],
                    "test_id": a["test_id"]
                },
                "sample_b": {
                    "source": b["source"],
                    "test_id": b["test_id"]
                },
                "similarity": round(score, 4),
                "review_required": True
            })

    report = {
        "total_samples": len(candidates),
        "similarity_threshold": SIMILARITY_THRESHOLD,
        "suspicious_pairs": len(matches),
        "matches": matches
    }

    with OUTPUT.open("w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print("=" * 55)
    print("NEAR-DUPLICATE DETECTION")
    print("=" * 55)
    print("Samples:", len(candidates))
    print("Threshold:", SIMILARITY_THRESHOLD)
    print("Suspicious pairs:", len(matches))
    print("Report:", OUTPUT)


if __name__ == "__main__":
    main()