import json
import csv
from pathlib import Path
from collections import Counter

root = Path("dataset")
out_dir = root / "processed" / "patchwork_additions"
out_dir.mkdir(parents=True, exist_ok=True)

def read_jsonl(path):
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]

def norm(value):
    return str(value or "").strip().upper()

candidates = read_jsonl(root / "patchwork_python_candidates.jsonl")
enriched = read_jsonl(root / "patchwork_python_enriched.jsonl")

enriched_cves = {
    norm(x.get("cve_id") or x.get("cve"))
    for x in enriched
}

strong = [
    x for x in candidates
    if norm(x.get("cve")) not in enriched_cves
    and x.get("analyzable") is True
    and x.get("patch_sufficient_pro") is True
]

with open(root / "raw_downloads" / "Zenodo_Python" / "data_Python.csv",
          encoding="utf-8-sig", newline="") as f:
    zenodo = {norm(x["cve_id"]) for x in csv.DictReader(f) if x.get("cve_id")}

cevud_data = json.loads(
    (root / "raw_downloads" / "CEVuD" / "train.json").read_text(encoding="utf-8")
)

cevud = {
    norm(sample.get("cve_id"))
    for project in cevud_data
    for sample in project.get("samples", [])
    if sample.get("cve_id")
}

with open(root / "processed" / "cyberset" / "cyberset_cve_candidates.csv",
          encoding="utf-8-sig", newline="") as f:
    cyberset = {norm(x["cve_id"]) for x in csv.DictReader(f) if x.get("cve_id")}

existing = zenodo | cevud | cyberset

additions = [
    x for x in strong
    if norm(x.get("cve")) not in existing
]

output_file = out_dir / "patchwork_unique_additions.jsonl"

with output_file.open("w", encoding="utf-8") as f:
    for record in additions:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")

cwe_counts = Counter(x.get("cwe_final") for x in additions)

report = {
    "source": "Patchwork",
    "strong_candidates": len(strong),
    "unique_additions": len(additions),
    "cwe_distribution": dict(sorted(cwe_counts.items())),
    "records_file": str(output_file)
}

report_file = out_dir / "patchwork_unique_additions_report.json"
report_file.write_text(json.dumps(report, indent=2), encoding="utf-8")

print("SAVED RECORDS:", len(additions))
print("CWE DISTRIBUTION:")
for cwe, count in sorted(cwe_counts.items()):
    print(f"  {cwe}: {count}")
print("RECORDS FILE:", output_file)
print("REPORT FILE:", report_file)