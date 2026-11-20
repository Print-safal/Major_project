import json
import re
import pandas as pd
from pathlib import Path

TARGETS = {"CWE-22", "CWE-78", "CWE-79", "CWE-89", "CWE-798"}
existing = {cwe: set() for cwe in TARGETS}

# Patchwork: same rules as audit_cross_source.py
with open("dataset/patchwork_python_enriched.jsonl", encoding="utf-8") as f:
    for line in f:
        r = json.loads(line)
        cwe = r.get("cwe_id")
        cve = r.get("cve_id")
        code = r.get("vulnerable_removed_lines") or ""
        if cwe in TARGETS and cve and len(code.strip()) >= 100:
            existing[cwe].add(cve.upper())

# Zenodo: exact baseline filters
df = pd.read_csv(
    "dataset/raw_downloads/Zenodo_Python/data_Python.csv"
).fillna("")

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

df = df[
    (~test_mask)
    & (df["vul_code"].str.len() >= 100)
]

for _, r in df.iterrows():
    cwe = str(r["cwe_id"]).strip().upper()
    cve = str(r["cve_id"]).strip().upper()
    if cwe in TARGETS and cve:
        existing[cwe].add(cve)

# CEVuD: exact baseline filters
with open("dataset/raw_downloads/CEVuD/train.json", encoding="utf-8") as f:
    projects = json.load(f)

for project in projects:
    for r in project.get("samples", []):
        cwe = str(r.get("vulnerability_type") or "").upper()
        cve = str(r.get("cve_id") or "").upper()
        code = r.get("source_code") or ""
        if (
            cwe in TARGETS
            and cve
            and r.get("label") == 1
            and len(code.strip()) >= 100
        ):
            existing[cwe].add(cve)

# RealVuln: exact baseline filters
finding_to_cve = {}

with open("dataset/raw_downloads/RealVuln-v2/findings.jsonl", encoding="utf-8") as f:
    for line in f:
        r = json.loads(line)
        if r.get("finding_id") and r.get("cve_id"):
            finding_to_cve[r["finding_id"]] = r["cve_id"].strip().upper()

with open("dataset/realvuln_extracted.jsonl", encoding="utf-8") as f:
    for line in f:
        r = json.loads(line)
        cwe = r.get("cwe")
        cve = finding_to_cve.get(r.get("finding_id"))
        code = r.get("vulnerable_code") or ""
        if (
            cwe in TARGETS
            and cve
            and r.get("manually_verified") is True
            and r.get("authorship") == "human_authored"
            and len(code.strip()) >= 100
        ):
            existing[cwe].add(cve)

# Compare all CyberSet candidates, not the previously filtered 165
cyber = pd.read_csv(
    "dataset/processed/cyberset/cyberset_cve_candidates.csv"
).fillna("")

new_rows = []
overlap_rows = []

for _, r in cyber.iterrows():
    cwe = str(r["cwe_id"]).strip().upper()
    cve = str(r["cve_id"]).strip().upper()

    if cwe not in TARGETS or not cve:
        continue

    if cve in existing[cwe]:
        overlap_rows.append(r.to_dict())
    else:
        new_rows.append(r.to_dict())

out = Path("dataset/processed/cyberset")
pd.DataFrame(new_rows).to_csv(
    out / "cyberset_new_exact_baseline.csv", index=False
)
pd.DataFrame(overlap_rows).to_csv(
    out / "cyberset_overlap_exact_baseline.csv", index=False
)

print("\nEXACT BASELINE COMPARISON")
print("=" * 55)
for cwe in sorted(TARGETS):
    n = sum(str(r["cwe_id"]).upper() == cwe for r in new_rows)
    o = sum(str(r["cwe_id"]).upper() == cwe for r in overlap_rows)
    print(f"{cwe}: New={n} | Overlap={o}")

print("-" * 55)
print("Existing baseline associations:", sum(len(v) for v in existing.values()))
print("CyberSet new records:", len(new_rows))
print("CyberSet overlapping records:", len(overlap_rows))
print("CyberSet total checked:", len(new_rows) + len(overlap_rows))
print("\nSaved separate validation files.")
# Check Patchwork additions against the exact baseline
patchwork_path = "dataset/processed/patchwork_additions/patchwork_unique_additions.jsonl"

patchwork_new = 0
patchwork_overlap = 0

with open(patchwork_path, encoding="utf-8") as f:
    for line in f:
        r = json.loads(line)
        cwe = str(r.get("cwe_final") or r.get("cwe") or "").upper()
        cve = str(r.get("cve") or r.get("cve_id") or "").upper()

        if cwe in TARGETS and cve:
            if cve in existing[cwe]:
                patchwork_overlap += 1
            else:
                patchwork_new += 1

print("\nPATCHWORK ADDITIONS CHECK")
print("New against exact baseline:", patchwork_new)
print("Overlapping exact baseline:", patchwork_overlap)