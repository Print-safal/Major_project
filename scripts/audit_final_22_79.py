import json
from pathlib import Path
from collections import Counter

path = Path("dataset/processed/consolidated/master_candidate_inventory.jsonl")

rows = [
    json.loads(line)
    for line in path.read_text(encoding="utf-8").splitlines()
    if line.strip()
]

for cwe in ["CWE-22", "CWE-79"]:
    cases = [row for row in rows if row["cwe"] == cwe]

    with_code = sum(
        any(record.get("code") for record in row["source_records"])
        for row in cases
    )

    without_code = len(cases) - with_code

    source_counts = Counter(
        record["source"]
        for row in cases
        for record in row["source_records"]
    )

    print("\n", cwe)
    print("Total associations:", len(cases))
    print("Associations with code:", with_code)
    print("Associations without code:", without_code)
    print("Source records:", dict(source_counts))