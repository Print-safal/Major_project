import json
from pathlib import Path

path = Path("dataset/processed/consolidated/master_candidate_inventory.jsonl")

rows = [
    json.loads(line)
    for line in path.read_text(encoding="utf-8").splitlines()
    if line.strip()
]

missing = [
    row for row in rows
    if row["cwe"] == "CWE-79"
    and not any(s.get("code") for s in row["source_records"])
]

print("CWE-79 associations without code:", len(missing))

for row in missing:
    print("\nCVE:", row["cve"])
    for source in row["source_records"]:
        print("Source:", source["source"])
        print("Metadata:", source.get("metadata", {}))
