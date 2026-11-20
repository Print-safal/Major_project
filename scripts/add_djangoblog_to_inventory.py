import json
from pathlib import Path

root = Path.cwd()

source_file = root / "dataset" / "processed" / "cwe798_supplement" / "djangoblog_cve_2026_6610.jsonl"
inventory_file = root / "dataset" / "processed" / "consolidated" / "master_candidate_inventory.jsonl"

record = json.loads(source_file.read_text(encoding="utf-8").splitlines()[0])

rows = [
    json.loads(line)
    for line in inventory_file.read_text(encoding="utf-8").splitlines()
    if line.strip()
]

if any(row.get("cve") == record["cve"] for row in rows):
    print("Already present. No changes made.")
else:
    new_entry = {
        "cve": record["cve"],
        "cwe": "CWE-798",
        "source_records": [
            {
                "source": "DjangoBlog_CVE_2026_6610",
                "code": record["code"],
                "metadata": {
                    "record_id": record["record_id"],
                    "project": record["project"],
                    "version": record["version"],
                    "repository": record["repository"],
                    "commit": record["commit"],
                    "file_path": record["file_path"],
                    "source_type": record["source_type"],
                    "label_status": record["label_status"],
                    "evidence": record["evidence"]
                }
            }
        ]
    }

    with inventory_file.open("a", encoding="utf-8") as f:
        f.write(json.dumps(new_entry, ensure_ascii=False) + "\n")

    print("Added:", record["cve"])

print("Total associations:", len(rows) + (0 if any(row.get("cve") == record["cve"] for row in rows) else 1))