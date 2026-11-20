from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "dataset" / "FINAL_DATASETS"
CATEGORIES = ("CWE-22", "CWE-78", "CWE-79", "CWE-89", "CWE-798", "SAFE-PYTHON")
EXPECTED_LABELS = {c: (None if c == "SAFE-PYTHON" else c) for c in CATEGORIES}


@dataclass(frozen=True)
class Case:
    test_id: str
    code: str
    ground_truth_cwe: str | None
    vulnerability_name: str | None
    category: str

    def as_dict(self):
        return {"test_id": self.test_id, "code": self.code,
                "ground_truth_cwe": self.ground_truth_cwe,
                "vulnerability_name": self.vulnerability_name,
                "category": self.category}


def load_dataset(data_dir: Path = DATA_DIR) -> tuple[list[Case], dict[str, str]]:
    cases, hashes, seen = [], {}, set()
    issues = []
    for category in CATEGORIES:
        path = Path(data_dir) / category / "cases_benchmark.json"
        if not path.is_file():
            issues.append(f"{path}: missing required dataset file")
            continue
        raw_bytes = path.read_bytes()
        hashes[category] = hashlib.sha256(raw_bytes).hexdigest()
        try:
            records = json.loads(raw_bytes)
        except Exception as exc:
            issues.append(f"{path}: invalid JSON ({exc})")
            continue
        if not isinstance(records, list):
            issues.append(f"{path}: expected a JSON array")
            continue
        if len(records) != 200:
            issues.append(f"{path}: expected 200 records, found {len(records)}")
        for i, item in enumerate(records):
            where = f"{path}[{i}]"
            if not isinstance(item, dict):
                issues.append(f"{where}: expected an object")
                continue
            test_id, code = item.get("test_id"), item.get("code")
            label = item.get("ground_truth_cwe")
            if not isinstance(test_id, str) or not test_id.strip():
                issues.append(f"{where}: test_id must be a nonempty string")
                continue
            if test_id in seen:
                issues.append(f"{where}: duplicate test_id {test_id!r}")
                continue
            seen.add(test_id)
            if not isinstance(code, str) or not code.strip():
                issues.append(f"{where}: code must be a nonempty string")
                continue
            if label != EXPECTED_LABELS[category]:
                issues.append(f"{where}: ground_truth_cwe {label!r} does not match {category}")
                continue
            name = item.get("vulnerability_name")
            if name is not None and not isinstance(name, str):
                issues.append(f"{where}: vulnerability_name must be string or null")
                continue
            cases.append(Case(test_id, code, label, name, category))
    if issues:
        raise ValueError("Dataset validation failed:\n- " + "\n- ".join(issues))
    if len(cases) != 1200 or len(seen) != 1200:
        raise ValueError(f"Expected exactly 1200 unique valid cases; got {len(cases)}")
    return cases, hashes


def combined_dataset_hash(cases: list[Case]) -> str:
    payload = "\n".join(json.dumps(c.as_dict(), sort_keys=True, ensure_ascii=False) for c in cases)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()
