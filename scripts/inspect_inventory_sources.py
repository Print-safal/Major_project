import json
from pathlib import Path

files = [
    "dataset/realvuln_extracted.jsonl",
    "dataset/patchwork_patch_queue.jsonl",
    "dataset/patchwork_extraction_report.json",
    "dataset/exclusion_manifest.json",
]

for filename in files:
    path = Path(filename)
    print("\nFILE:", filename)
    print("EXISTS:", path.exists())

    if not path.exists():
        continue

    if path.suffix == ".jsonl":
        rows = [
            json.loads(line)
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        print("RECORDS:", len(rows))
        if rows and isinstance(rows[0], dict):
            print("FIELDS:", list(rows[0].keys()))
    else:
        data = json.loads(path.read_text(encoding="utf-8"))
        print("TYPE:", type(data).__name__)
        if isinstance(data, dict):
            print("KEYS:", list(data.keys())[:30])