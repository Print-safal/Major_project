import json
from pathlib import Path

root = Path.cwd()

base = (
    root / "dataset" / "raw_downloads" / "codeql" /
    "python" / "ql"
)

examples = base / "src" / "experimental" / "Security" / (
    "CWE-287-ConstantSecretKey"
) / "examples"

output = root / "dataset" / "processed" / "cwe798_supplement"
output.mkdir(parents=True, exist_ok=True)

review = {
    "config.py": ("candidate_cwe798", "Hard-coded secret and fallback."),
    "config1.py": ("candidate_cwe798", "Hard-coded secret and fallback."),
    "config2.py": ("candidate_cwe798", "Hard-coded constant assigned to SECRET_KEY."),
    "config3.py": ("candidate_cwe798", "Hard-coded environment fallback."),
    "example_Django_unsafe.py": ("candidate_cwe798", "Hard-coded Django secrets."),
    "example_Flask_unsafe.py": ("candidate_cwe798", "Hard-coded Flask secret."),
    "example_Flask_unsafe2.py": ("candidate_cwe798", "Hard-coded Flask secret."),
    "example_Django_safe.py": ("potential_safe_control", "Uses generated secret keys."),
    "example_Flask_safe.py": ("requires_context_review", "Loads config3.py with a hard-coded fallback."),
}

records = []

for filename, (status, notes) in review.items():
    path = examples / filename

    if not path.exists():
        print("Missing:", filename)
        continue

    records.append({
        "record_id": "CODEQL_" + filename,
        "source": "GitHub CodeQL Python test examples",
        "source_type": "static_analysis_test_fixture",
        "source_path": str(path.relative_to(root)),
        "candidate_cwe": "CWE-798" if status == "candidate_cwe798" else None,
        "label_status": status,
        "review_notes": notes,
        "code": path.read_text(encoding="utf-8"),
        "cve": None,
        "is_real_world_cve_case": False
    })

fixture = (
    base / "test" / "query-tests" / "Security" /
    "CWE-798-HardcodedCredentials" / "test.py"
)

if fixture.exists():
    records.append({
        "record_id": "CODEQL_HardcodedCredentials_test",
        "source": "GitHub CodeQL CWE-798 query test",
        "source_type": "static_analysis_test_fixture",
        "source_path": str(fixture.relative_to(root)),
        "candidate_cwe": "CWE-798",
        "label_status": "candidate_requires_review",
        "review_notes": "Contains CodeQL alert and sink markers; review case segmentation.",
        "code": fixture.read_text(encoding="utf-8"),
        "cve": None,
        "is_real_world_cve_case": False
    })

jsonl = output / "codeql_cwe798_reviewed_examples.jsonl"

with jsonl.open("w", encoding="utf-8") as file:
    for record in records:
        file.write(json.dumps(record) + "\n")

report = {
    "total_records": len(records),
    "candidate_files": sum(
        r["label_status"] == "candidate_cwe798" for r in records
    ),
    "potential_safe_controls": sum(
        r["label_status"] == "potential_safe_control" for r in records
    ),
    "requires_context_review": sum(
        r["label_status"] == "requires_context_review" for r in records
    ),
    "source": "GitHub CodeQL",
    "cve_linked_records": 0,
    "benchmark_acceptance": "Not automatically accepted"
}

(output / "codeql_cwe798_review_report.json").write_text(
    json.dumps(report, indent=2),
    encoding="utf-8"
)

print(json.dumps(report, indent=2))
print("Saved:", jsonl)