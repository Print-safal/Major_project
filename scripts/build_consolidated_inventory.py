import json
import csv
import pandas as pd
from pathlib import Path
from collections import defaultdict, Counter

BASE = Path("dataset")
OUT = BASE / "processed" / "consolidated"
OUT.mkdir(parents=True, exist_ok=True)

TARGETS = {"CWE-22", "CWE-78", "CWE-79", "CWE-89", "CWE-798"}
inventory = {}

def clean(value):
    if value is None:
        return None
    try:
        if pd.isna(value):
            return None
    except (TypeError, ValueError):
        pass
    if hasattr(value, "item"):
        try:
            return value.item()
        except ValueError:
            pass
    return value

def add(cve, cwe, source, code=None, metadata=None):
    cve = str(cve or "").strip().upper()
    cwe = str(cwe or "").strip().upper()

    if not cve or cwe not in TARGETS:
        return

    key = (cve, cwe)

    if key not in inventory:
        inventory[key] = {
            "cve": cve,
            "cwe": cwe,
            "source_records": []
        }

    item = {
        "source": source,
        "code": code if isinstance(code, str) else None,
        "metadata": metadata or {}
    }

    # Avoid adding an identical source record twice
    if item not in inventory[key]["source_records"]:
        inventory[key]["source_records"].append(item)


# 1. Patchwork enriched
path = BASE / "patchwork_python_enriched.jsonl"
with path.open(encoding="utf-8") as f:
    for line in f:
        if not line.strip():
            continue
        r = json.loads(line)
        code = r.get("vulnerable_removed_lines") or ""
        if len(code.strip()) >= 100:
            add(
                r.get("cve_id"), r.get("cwe_id"),
                "Patchwork", code,
                {"repo": r.get("repo"), "source_file": str(path)}
            )


# 2. Zenodo, exact baseline filters
path = BASE / "raw_downloads" / "Zenodo_Python" / "data_Python.csv"
df = pd.read_csv(path).fillna("")
df = df[
    df["programming_language"].str.lower().eq("python")
    & df["is_vulnerable"].eq(True)
]

test_mask = (
    df["file_name"].str.lower().str.contains(
        r"test|spec", regex=True, na=False
    )
    | df["method_name"].str.lower().str.startswith(
        "test_", na=False
    )
)
df = df[(~test_mask) & (df["vul_code"].str.len() >= 100)]

for r in df.to_dict("records"):
    cwe = str(r.get("cwe_id", "")).strip().upper()
    if cwe in TARGETS:
        add(
            r.get("cve_id"), cwe, "Zenodo", r.get("vul_code"),
            {
                "file_name": clean(r.get("file_name")),
                "method_name": clean(r.get("method_name")),
                "source_file": str(path)
            }
        )


# 3. CEVuD, exact baseline filters
path = BASE / "raw_downloads" / "CEVuD" / "train.json"
with path.open(encoding="utf-8") as f:
    projects = json.load(f)

for project in projects:
    for r in project.get("samples", []):
        code = r.get("source_code") or ""
        cwe = str(r.get("vulnerability_type") or "").upper()
        if (
            cwe in TARGETS and r.get("cve_id")
            and r.get("label") == 1 and len(code.strip()) >= 100
        ):
            add(
                r.get("cve_id"), cwe, "CEVuD", code,
                {
                    "project": project.get("project_name"),
                    "sample_subtype": r.get("sample_subtype"),
                    "source_file": str(path)
                }
            )


# 4. RealVuln, exact baseline filters
findings_path = BASE / "raw_downloads" / "RealVuln-v2" / "findings.jsonl"
finding_to_cve = {}

with findings_path.open(encoding="utf-8") as f:
    for line in f:
        r = json.loads(line)
        if r.get("finding_id") and r.get("cve_id"):
            finding_to_cve[r["finding_id"]] = r["cve_id"].strip()

path = BASE / "realvuln_extracted.jsonl"
with path.open(encoding="utf-8") as f:
    for line in f:
        r = json.loads(line)
        code = r.get("vulnerable_code") or ""
        cwe = str(r.get("cwe") or "").upper()
        cve = finding_to_cve.get(r.get("finding_id"))

        if (
            cwe in TARGETS and cve
            and r.get("manually_verified") is True
            and r.get("authorship") == "human_authored"
            and len(code.strip()) >= 100
        ):
            add(
                cve, cwe, "RealVuln", code,
                {
                    "finding_id": r.get("finding_id"),
                    "repo_url": r.get("repo_url"),
                    "file": r.get("file"),
                    "source_file": str(path)
                }
            )


# 5. CyberSet additions verified against exact baseline
path = BASE / "processed" / "cyberset" / "cyberset_new_exact_baseline.csv"
df = pd.read_csv(path).fillna("")

for r in df.to_dict("records"):
    cwe = str(r.get("cwe_id", "")).upper()
    add(
        r.get("cve_id"), cwe, "CyberSet",
        r.get("code"),
        {
            "sample_id": clean(r.get("sample_id")),
            "project": clean(r.get("project")),
            "repo_url": clean(r.get("repo_url")),
            "file_path": clean(r.get("file_path")),
            "code_sha256": clean(r.get("code_sha256")),
            "label_confidence": clean(r.get("label_confidence")),
            "source_license": clean(r.get("source_license")),
            "primary_source": clean(r.get("primary_source")),
            "original_split": clean(r.get("original_split")),
            "source_file": str(path)
        }
    )


# 6. Patchwork additions, previously checked against exact baseline
path = BASE / "processed" / "patchwork_additions" / "patchwork_unique_additions.jsonl"

with path.open(encoding="utf-8") as f:
    for line in f:
        if not line.strip():
            continue
        r = json.loads(line)
        add(
            r.get("cve"), r.get("cwe_final"),
            "Patchwork_addition", None,
            {**r, "source_file": str(path)}
        )


# 7. Save one row per unique CVE-CWE association
records = sorted(
    inventory.values(),
    key=lambda r: (r["cwe"], r["cve"])
)

master_path = OUT / "master_candidate_inventory.jsonl"
with master_path.open("w", encoding="utf-8") as f:
    for r in records:
        f.write(json.dumps(r, ensure_ascii=False, default=str) + "\n")


# 8. Save counts and source summary
cwe_counts = Counter(r["cwe"] for r in records)
source_counts = Counter()

for r in records:
    for source_record in r["source_records"]:
        source_counts[source_record["source"]] += 1

report = {
    "unique_cve_cwe_associations": len(records),
    "cwe_counts": dict(sorted(cwe_counts.items())),
    "source_record_counts": dict(sorted(source_counts.items())),
    "targets": {cwe: 200 for cwe in sorted(TARGETS)},
    "status": "candidate inventory; not yet manually validated",
    "master_file": str(master_path)
}

report_path = OUT / "master_candidate_inventory_report.json"
report_path.write_text(
    json.dumps(report, indent=2),
    encoding="utf-8"
)

print("\nCONSOLIDATED INVENTORY SAVED")
print("Unique CVE-CWE associations:", len(records))
print("CWE COUNTS:")
for cwe in sorted(TARGETS):
    print(f"  {cwe}: {cwe_counts.get(cwe, 0)} / 200")

print("\nSOURCE RECORD COUNTS:")
for source, count in sorted(source_counts.items()):
    print(f"  {source}: {count}")

print("\nMASTER:", master_path)
print("REPORT:", report_path)