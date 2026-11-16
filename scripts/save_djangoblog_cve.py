import json
from pathlib import Path

root = Path.cwd()

repo = root / "dataset" / "raw_downloads" / "DjangoBlog_CVE_2026_6610"
source = repo / "djangoblog" / "settings.py"

if not source.exists():
    raise FileNotFoundError(source)

code = source.read_text(encoding="utf-8")

record = {
    "record_id": "CVE-2026-6610-DjangoBlog-settings",
    "cve": "CVE-2026-6610",
    "cwe": ["CWE-798", "CWE-259"],
    "primary_candidate_cwe": "CWE-798",
    "project": "DjangoBlog",
    "version": "2.1.0.0",
    "repository": "https://github.com/liangliangyy/DjangoBlog",
    "commit": "55655f236308841e0e83f5b383b1c2056a0fb48c",
    "file_path": "djangoblog/settings.py",
    "source_type": "real_world_cve_linked",
    "label_status": "candidate_requires_validation",
    "code": code,
    "evidence": [
        "DJANGO_SECRET_KEY has a hard-coded fallback",
        "DJANGO_MYSQL_PASSWORD has a hard-coded fallback",
        "WXADMIN has a hard-coded fallback"
    ],
    "is_real_world_cve_case": True,
    "benchmark_acceptance": "pending_review"
}

out = root / "dataset" / "processed" / "cwe798_supplement"
out.mkdir(parents=True, exist_ok=True)

target = out / "djangoblog_cve_2026_6610.jsonl"

with target.open("w", encoding="utf-8") as f:
    f.write(json.dumps(record, ensure_ascii=False) + "\n")

print("Saved:", target)
print("CVE:", record["cve"])
print("Commit:", record["commit"])
print("Code characters:", len(code))
print("Status:", record["label_status"])