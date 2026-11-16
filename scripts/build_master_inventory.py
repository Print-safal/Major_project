import json
from pathlib import Path
from collections import Counter
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parent.parent
DATASET = ROOT / "dataset"

ADDITIONS = (
    DATASET
    / "processed"
    / "patchwork_additions"
    / "patchwork_unique_additions.jsonl"
)

OUTPUT = DATASET / "master_candidate_inventory.jsonl"
REPORT = DATASET / "master_inventory_report.json"

BASELINE = {
    "CWE-22": 219,
    "CWE-78": 74,
    "CWE-79": 176,
    "CWE-89": 65,
    "CWE-798": 5,
}

TARGET = 200

def read_jsonl(path):
    with path.open("r", encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]

def main():
    if not ADDITIONS.exists():
        raise FileNotFoundError(f"Missing additions file: {ADDITIONS}")

    additions = read_jsonl(ADDITIONS)

    inventory = []
    seen = set()

    for record in additions:
        cve = record.get("cve") or record.get("cve_id")

        if not cve:
            raise ValueError("A Patchwork addition has no CVE identifier.")

        if cve in seen:
            raise ValueError(f"Duplicate CVE in additions: {cve}")

        seen.add(cve)

        item = dict(record)
        item["inventory_group"] = "new_patchwork_addition"
        item["review_status"] = "candidate_pending_validation"
        item["source_file"] = str(ADDITIONS.relative_to(ROOT))
        inventory.append(item)

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)

    with OUTPUT.open("w", encoding="utf-8") as f:
        for item in inventory:
            f.write(json.dumps(item, ensure_ascii=False) + "\n")

    added_counts = Counter(
        item.get("cwe_final")
        or item.get("cwe")
        or item.get("cwe_id")
        for item in inventory
    )

    combined = {
        cwe: BASELINE[cwe] + added_counts.get(cwe, 0)
        for cwe in BASELINE
    }

    report = {
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "inventory_file": str(OUTPUT.relative_to(ROOT)),
        "inventory_records_saved": len(inventory),
        "inventory_scope": (
            "147 new Patchwork additions only; "
            "not the complete record-level baseline."
        ),
        "baseline_aggregate_counts": BASELINE,
        "new_patchwork_addition_counts": dict(added_counts),
        "provisional_combined_candidate_counts": combined,
        "target_per_cwe": TARGET,
        "remaining_candidate_gaps": {
            cwe: max(0, TARGET - count)
            for cwe, count in combined.items()
        },
        "validation_warning": (
            "Candidate counts are not validated benchmark counts. "
            "Review, provenance checks, and complete baseline "
            "reconstruction are still required."
        ),
        "llm_benchmark_kept_separate": True,
    }

    REPORT.write_text(
        json.dumps(report, indent=2, ensure_ascii=False),
        encoding="utf-8"
    )

    print("MASTER INVENTORY SAVED")
    print("Records:", len(inventory))
    print("Inventory:", OUTPUT)
    print("Report:", REPORT)
    print("\nPROVISIONAL COUNTS:")
    for cwe, count in combined.items():
        print(f"{cwe}: {count} / {TARGET}")

if __name__ == "__main__":
    main()