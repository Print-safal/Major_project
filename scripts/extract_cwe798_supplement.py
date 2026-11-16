import polars as pl
import hashlib
import json
from pathlib import Path

folder = Path("dataset/raw_downloads/Code-Security-Vulnerability")
output = Path("dataset/processed/cwe798_supplement")
output.mkdir(parents=True, exist_ok=True)

files = list(folder.glob("*.parquet"))
records = []
seen = set()

for path in files:
    print("\nReading:", path.name)
    df = pl.read_parquet(path)

    selected = df.filter(
        (pl.col("language").cast(pl.Utf8).str.to_lowercase() == "python")
        & (pl.col("is_vulnerable") == True)
        & (pl.col("cwe_id").cast(pl.Utf8).str.to_uppercase() == "CWE-798")
    )

    print("Matching rows:", selected.height)

    for row in selected.iter_rows(named=True):
        code = str(row.get("code") or "").strip()

        if len(code) < 100:
            continue

        digest = hashlib.sha256(code.encode("utf-8")).hexdigest()

        if digest in seen:
            continue

        seen.add(digest)

        records.append({
            "sample_id": f"CSS_CWE798_{len(records)+1:04d}",
            "ground_truth_cwe": "CWE-798",
            "language": "Python",
            "code": code,
            "code_fixed": row.get("code_fixed"),
            "source_dataset": row.get("source"),
            "original_split": path.name,
            "code_sha256": digest,
            "code_length": len(code),
            "cve_id": None,
            "review_status": "candidate_pending_validation"
        })

out_file = output / "cwe798_python_candidates.jsonl"

with out_file.open("w", encoding="utf-8") as f:
    for row in records:
        f.write(json.dumps(row, ensure_ascii=False) + "\n")

print("\nEXTRACTION COMPLETE")
print("Unique CWE-798 candidates:", len(records))
print("Saved:", out_file)