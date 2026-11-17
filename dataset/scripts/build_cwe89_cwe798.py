import csv
import hashlib
import io
import json
import re
import urllib.request
import zipfile
from collections import defaultdict
from difflib import SequenceMatcher
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DATASET_DIR = ROOT / "dataset"
FINAL_DIR = DATASET_DIR / "FINAL_DATASETS"
PROCESSED_DIR = DATASET_DIR / "processed"
EXCLUSION_FILE = DATASET_DIR / "exclusion_manifest.json"
INVENTORY_FILE = DATASET_DIR / "master_candidate_inventory.jsonl"
COUNT_REPORT_FILE = FINAL_DIR / "COUNT_REPORT.txt"

TARGET_PER_CWE = 200
SIMILARITY_THRESHOLD = 0.85
OSV_PYPI_ZIP_URL = "https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip"


def sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def normalize_for_manifest(code: str) -> str:
    code = code.replace("\r\n", "\n").replace("\r", "\n")
    return re.sub(r"\s+", " ", code).strip()


def normalize_for_similarity(code: str) -> str:
    code = re.sub(r"#.*", "", code or "")
    code = re.sub(r"\s+", " ", code)
    return code.strip().lower()


def load_exclusions() -> tuple[set[str], set[str]]:
    exact_hashes, norm_hashes = set(), set()
    if not EXCLUSION_FILE.exists():
        return exact_hashes, norm_hashes
    data = json.loads(EXCLUSION_FILE.read_text(encoding="utf-8"))
    for rec in data.get("records", []):
        if rec.get("exact_sha256"):
            exact_hashes.add(rec["exact_sha256"])
        if rec.get("normalized_sha256"):
            norm_hashes.add(rec["normalized_sha256"])
    return exact_hashes, norm_hashes


def load_existing_cases(cwe_id: str) -> dict[str, dict]:
    path = FINAL_DIR / cwe_id / "cases.jsonl"
    cases = {}
    if path.exists():
        with path.open("r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    rec = json.loads(line)
                    cases[rec["cve"]] = rec
    return cases


def extract_pre_patch_python(owner: str, repo: str, sha: str) -> list[str]:
    """Fetches a GitHub commit .patch and reconstructs pre-patch vulnerable .py code blocks."""
    if not (owner and repo and sha):
        return []
    patch_url = f"https://github.com/{owner}/{repo}/commit/{sha}.patch"
    try:
        req = urllib.request.Request(patch_url, headers={"User-Agent": "MajorProject-DatasetBuilder"})
        with urllib.request.urlopen(req, timeout=12) as resp:
            patch_text = resp.read().decode("utf-8", errors="replace")
    except Exception:
        return []

    snippets = []
    current_file = None
    pre_patch_lines = []

    for line in patch_text.splitlines():
        if line.startswith("diff --git "):
            if current_file and current_file.endswith(".py") and len(pre_patch_lines) >= 4:
                snippets.append("\n".join(pre_patch_lines))
            current_file = None
            pre_patch_lines = []
        elif line.startswith("--- a/"):
            current_file = line[6:].strip()
        elif current_file and current_file.endswith(".py"):
            if line.startswith(("+++ ", "@@ ", "index ")):
                continue
            if line.startswith("-") or line.startswith(" "):
                pre_patch_lines.append(line[1:])

    if current_file and current_file.endswith(".py") and len(pre_patch_lines) >= 4:
        snippets.append("\n".join(pre_patch_lines))

    return [s for s in snippets if len(s.strip()) >= 40]


def iter_inventory_candidates():
    """Reads master_candidate_inventory.jsonl using cwe_final, repo_owner, repo_name, fix_sha."""
    if not INVENTORY_FILE.exists():
        return
    print("Hydrating existing candidates from master_candidate_inventory.jsonl...")
    with INVENTORY_FILE.open("r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            row = json.loads(line)
            cwe = str(row.get("cwe_final") or "").upper()
            if cwe not in {"CWE-89", "CWE-798"}:
                continue
            if row.get("analyzable") is False:
                continue

            cve = str(row.get("cve") or row.get("osv_id") or "").strip()
            owner = row.get("repo_owner")
            repo = row.get("repo_name")
            sha = row.get("fix_sha")

            for code in extract_pre_patch_python(owner, repo, sha):
                yield cwe, cve, code, "Patchwork", {
                    "repo": f"https://github.com/{owner}/{repo}" if owner and repo else None,
                    "source_file": row.get("source_file", "dataset\\master_candidate_inventory.jsonl"),
                }


def iter_osv_pypi_candidates(target_cwe89_total: int, target_cwe798_total: int, current_counts: dict[str, int]):
    """Downloads official OSV PyPI archive and harvests additional real Python CVEs."""
    print(f"Downloading OSV PyPI archive from {OSV_PYPI_ZIP_URL}...")
    req = urllib.request.Request(OSV_PYPI_ZIP_URL, headers={"User-Agent": "MajorProject-DatasetBuilder"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        zip_bytes = resp.read()

    harvested = {"CWE-89": 0, "CWE-798": 0}
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        for name in zf.namelist():
            if not name.endswith(".json"):
                continue
            if (
                current_counts["CWE-89"] + harvested["CWE-89"] >= target_cwe89_total + 50
                and current_counts["CWE-798"] + harvested["CWE-798"] >= target_cwe798_total + 50
            ):
                break

            adv = json.loads(zf.read(name).decode("utf-8"))
            cwes = [c.upper() for c in adv.get("database_specific", {}).get("cwe_ids", [])]
            target_cwe = "CWE-89" if "CWE-89" in cwes else ("CWE-798" if "CWE-798" in cwes else None)
            if not target_cwe:
                continue

            cves = [a for a in adv.get("aliases", []) if a.startswith("CVE-")]
            cve = sorted(cves)[0] if cves else adv.get("id", "")
            if not cve:
                continue

            fix_urls = [
                r["url"] for r in adv.get("references", [])
                if r.get("type") == "FIX" and "github.com/" in r.get("url", "") and "/commit/" in r.get("url", "")
            ]
            for url in fix_urls[:2]:
                m = re.match(r"https?://github\.com/([^/]+)/([^/]+)/commit/([0-9a-fA-F]{7,40})", url)
                if not m:
                    continue
                owner, repo, sha = m.group(1), m.group(2), m.group(3)
                snips = extract_pre_patch_python(owner, repo, sha)
                if snips:
                    harvested[target_cwe] += 1
                    for code in snips:
                        yield target_cwe, cve, code, "OSV-PyPI", {
                            "repo": f"https://github.com/{owner}/{repo}",
                            "source_file": url,
                        }


def is_near_duplicate(norm_sim_code: str, accepted_norm_codes: list[str]) -> bool:
    for existing_norm in accepted_norm_codes:
        len_a, len_b = len(norm_sim_code), len(existing_norm)
        if min(len_a, len_b) / max(len_a, len_b, 1) < SIMILARITY_THRESHOLD:
            continue
        if SequenceMatcher(None, norm_sim_code, existing_norm).ratio() >= SIMILARITY_THRESHOLD:
            return True
    return False


def main():
    exact_excl, norm_excl = load_exclusions()
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)

    cases_by_cwe = {
        "CWE-89": load_existing_cases("CWE-89"),
        "CWE-798": load_existing_cases("CWE-798"),
    }
    accepted_norms = {cwe: [] for cwe in cases_by_cwe}
    audit_rows = {cwe: [] for cwe in cases_by_cwe}

    for cwe, cve_map in cases_by_cwe.items():
        for cve, rec in cve_map.items():
            for sr in rec.get("source_records", []):
                accepted_norms[cwe].append(normalize_for_similarity(sr["code"]))
            audit_rows[cwe].append({"cve": cve, "status": "kept_baseline", "source": rec["source_records"][0]["source"]})

    grouped_candidates = {"CWE-89": defaultdict(list), "CWE-798": defaultdict(list)}

    def ingest_stream(stream):
        for cwe, cve, code, source, meta in stream:
            if not cve or cve in cases_by_cwe[cwe]:
                continue
            if sha256(code) in exact_excl or sha256(normalize_for_manifest(code)) in norm_excl:
                audit_rows[cwe].append({"cve": cve, "status": "rejected_exclusion_manifest", "source": source})
                continue
            grouped_candidates[cwe][cve].append({
                "source": source,
                "code": code,
                "metadata": meta,
            })

    ingest_stream(iter_inventory_candidates())
    current_totals = {
        "CWE-89": len(cases_by_cwe["CWE-89"]) + len(grouped_candidates["CWE-89"]),
        "CWE-798": len(cases_by_cwe["CWE-798"]) + len(grouped_candidates["CWE-798"]),
    }
    print(f"After inventory hydration -> CWE-89 candidates: {current_totals['CWE-89']}, CWE-798 candidates: {current_totals['CWE-798']}")

    ingest_stream(iter_osv_pypi_candidates(TARGET_PER_CWE, TARGET_PER_CWE, current_totals))

    for cwe in ["CWE-89", "CWE-798"]:
        ranked = sorted(
            grouped_candidates[cwe].items(),
            key=lambda kv: (len(kv[1]), len(kv[1][0]["code"])),
            reverse=True,
        )
        for cve, src_records in ranked:
            if len(cases_by_cwe[cwe]) >= TARGET_PER_CWE:
                break
            primary_norm = normalize_for_similarity(src_records[0]["code"])
            if is_near_duplicate(primary_norm, accepted_norms[cwe]):
                audit_rows[cwe].append({"cve": cve, "status": "rejected_near_duplicate", "source": src_records[0]["source"]})
                continue

            cases_by_cwe[cwe][cve] = {
                "cve": cve,
                "cwe": cwe,
                "source_records": src_records,
            }
            accepted_norms[cwe].append(primary_norm)
            audit_rows[cwe].append({"cve": cve, "status": "added_to_200", "source": src_records[0]["source"]})

        out_jsonl = FINAL_DIR / cwe / "cases.jsonl"
        with out_jsonl.open("w", encoding="utf-8") as f:
            for rec in cases_by_cwe[cwe].values():
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")

        audit_csv = PROCESSED_DIR / f"{cwe.lower().replace('-', '')}_selection_audit.csv"
        with audit_csv.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["cve", "status", "source"])
            writer.writeheader()
            writer.writerows(audit_rows[cwe])

        print(f"{cwe}: {len(cases_by_cwe[cwe])}/{TARGET_PER_CWE} saved -> {out_jsonl}")

    if COUNT_REPORT_FILE.exists():
        lines = COUNT_REPORT_FILE.read_text(encoding="utf-8").splitlines()
        updated = []
        for line in lines:
            if line.startswith("CWE-89:"):
                updated.append(f"CWE-89: {len(cases_by_cwe['CWE-89'])}/{TARGET_PER_CWE}")
            elif line.startswith("CWE-798:"):
                updated.append(f"CWE-798: {len(cases_by_cwe['CWE-798'])}/{TARGET_PER_CWE}")
            else:
                updated.append(line)
        COUNT_REPORT_FILE.write_text("\n".join(updated) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
    