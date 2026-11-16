import ast
import hashlib
import json
import re
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / "dataset" / "exclusion_manifest.json"

SOURCES = [
    {
        "path": ROOT / "llm" / "final_150_cases.json",
        "reason": "Previously evaluated V1 dataset",
        "kind": "evaluation",
    },
    {
        "path": ROOT / "llm" / "llm_evaluation_set_v2.json",
        "reason": "Previously evaluated V2 dataset",
        "kind": "evaluation",
    },
]

def sha256(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()

def normalize(code):
    code = code.replace("\r\n", "\n").replace("\r", "\n")
    return re.sub(r"\s+", " ", code).strip()

def load_json(path):
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)

def load_rag_fixtures(path):
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source)

    for node in tree.body:
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = (
                node.targets if isinstance(node, ast.Assign)
                else [node.target]
            )

            if any(
                isinstance(t, ast.Name) and t.id == "TEST_CASES"
                for t in targets
            ):
                return ast.literal_eval(node.value)

    raise ValueError("TEST_CASES assignment not found")

records = []

# Historical LLM evaluation datasets
for source in SOURCES:
    if not source["path"].exists():
        print(f"WARNING: Missing {source['path']}")
        continue

    for item in load_json(source["path"]):
        code = item.get("code", "")
        if not code.strip():
            continue

        records.append({
            "source_file": str(source["path"].relative_to(ROOT)),
            "source_type": source["kind"],
            "test_id": item.get("test_id"),
            "cwe": item.get("ground_truth_cwe"),
            "reason": source["reason"],
            "exact_sha256": sha256(code),
            "normalized_sha256": sha256(normalize(code)),
        })

# Historical RAG integration fixtures
rag_path = ROOT / "rag_int" / "test_rag_llm.py"

if rag_path.exists():
    for index, item in enumerate(load_rag_fixtures(rag_path), 1):
        code = item.get("code", "")
        if not code.strip():
            continue

        records.append({
            "source_file": "rag_int/test_rag_llm.py",
            "source_type": "rag_integration",
            "test_id": f"RAG_FIXTURE_{index}",
            "cwe": item.get("expected"),
            "reason": "Previously used RAG integration fixture",
            "exact_sha256": sha256(code),
            "normalized_sha256": sha256(normalize(code)),
        })

# Identify duplicate fingerprints across historical sources
exact_groups = defaultdict(list)
normalized_groups = defaultdict(list)

for record in records:
    exact_groups[record["exact_sha256"]].append(record)
    normalized_groups[record["normalized_sha256"]].append(record)

exact_duplicates = [
    group for group in exact_groups.values() if len(group) > 1
]

normalized_duplicates = [
    group for group in normalized_groups.values() if len(group) > 1
]

manifest = {
    "manifest_version": "1.0",
    "purpose": "Historical evaluation exclusion and leakage prevention",
    "records": records,
    "summary": {
        "total_records": len(records),
        "unique_exact_code_samples": len(exact_groups),
        "unique_normalized_code_samples": len(normalized_groups),
        "exact_duplicate_groups": len(exact_duplicates),
        "normalized_duplicate_groups": len(normalized_duplicates),
        "source_counts": {
            source: sum(
                r["source_file"] == source for r in records
            )
            for source in sorted({r["source_file"] for r in records})
        },
    },
    "exact_duplicate_groups": exact_duplicates,
    "normalized_duplicate_groups": normalized_duplicates,
}

OUTPUT.parent.mkdir(parents=True, exist_ok=True)

with OUTPUT.open("w", encoding="utf-8") as f:
    json.dump(manifest, f, indent=2, ensure_ascii=False)

print("=" * 55)
print("EXCLUSION MANIFEST GENERATED")
print("=" * 55)
print("Total records:", len(records))
print("Unique exact samples:", len(exact_groups))
print("Exact duplicate groups:", len(exact_duplicates))
print("Normalized duplicate groups:", len(normalized_duplicates))
print("Output:", OUTPUT)