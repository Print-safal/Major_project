import csv
import hashlib
import json
import re
import time
import urllib.parse
import urllib.request
from collections import defaultdict
from difflib import SequenceMatcher
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DATASET_DIR = ROOT / "dataset"
FINAL_DIR = DATASET_DIR / "FINAL_DATASETS"
PROCESSED_DIR = DATASET_DIR / "processed"
EXCLUSION_FILE = DATASET_DIR / "exclusion_manifest.json"
COUNT_REPORT_FILE = FINAL_DIR / "COUNT_REPORT.txt"

TARGET_PER_CWE = 200
SIMILARITY_THRESHOLD = 0.85
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


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


def is_near_duplicate(norm_sim_code: str, accepted_norm_codes: list[str]) -> bool:
    for existing_norm in accepted_norm_codes:
        len_a, len_b = len(norm_sim_code), len(existing_norm)
        if min(len_a, len_b) / max(len_a, len_b, 1) < SIMILARITY_THRESHOLD:
            continue
        if SequenceMatcher(None, norm_sim_code, existing_norm).ratio() >= SIMILARITY_THRESHOLD:
            return True
    return False


def fetch_github_py_patch(commit_url: str) -> list[tuple[str, str]]:
    """Fetches GitHub commit .patch and extracts pre-patch vulnerable .py hunks."""
    m = re.match(r"https?://github\.com/([^/]+/[^/]+)/commit/([0-9a-fA-F]{7,40})", commit_url)
    if not m:
        return []
    repo, sha = m.group(1), m.group(2)
    patch_url = f"https://github.com/{repo}/commit/{sha}.patch"
    try:
        req = urllib.request.Request(patch_url, headers={"User-Agent": "MajorProject-CVE-Harvester"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            patch_text = resp.read().decode("utf-8", errors="replace")
    except Exception:
        return []

    results = []
    current_file = None
    pre_lines = []

    for line in patch_text.splitlines():
        if line.startswith("diff --git "):
            if current_file and current_file.endswith(".py") and len(pre_lines) >= 4:
                code = "\n".join(pre_lines).strip()
                if len(code) >= 45:
                    results.append((f"https://github.com/{repo}", code))
            current_file = None
            pre_lines = []
        elif line.startswith("--- a/"):
            current_file = line[6:].strip()
        elif current_file and current_file.endswith(".py"):
            if line.startswith(("+++ ", "@@ ", "index ")):
                continue
            if line.startswith("-") or line.startswith(" "):
                pre_lines.append(line[1:])

    if current_file and current_file.endswith(".py") and len(pre_lines) >= 4:
        code = "\n".join(pre_lines).strip()
        if len(code) >= 45:
            results.append((f"https://github.com/{repo}", code))

    return results


def harvest_cwe_from_nvd(
    cwe_id: str,
    existing_cases: dict[str, dict],
    accepted_norms: list[str],
    exact_excl: set[str],
    norm_excl: set[str],
    audit_rows: list[dict],
):
    start_index = 0
    results_per_page = 2000
    total_results = None

    while len(existing_cases) < TARGET_PER_CWE:
        if total_results is not None and start_index >= total_results:
            break

        params = urllib.parse.urlencode({
            "cweId": cwe_id,
            "startIndex": start_index,
            "resultsPerPage": results_per_page,
        })
        url = f"{NVD_API_URL}?{params}"
        print(f"[{cwe_id}] Querying NVD offset {start_index} (current: {len(existing_cases)}/{TARGET_PER_CWE})...")

        try:
            req = urllib.request.Request(url, headers={"User-Agent": "MajorProject-CVE-Harvester"})
            with urllib.request.urlopen(req, timeout=30) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
        except Exception as exc:
            print(f"[{cwe_id}] NVD request error at offset {start_index}: {exc}")
            break

        total_results = payload.get("totalResults", 0)
        vulns = payload.get("vulnerabilities", [])
        if not vulns:
            break

        # Process newest CVEs first within page
        for item in reversed(vulns):
            if len(existing_cases) >= TARGET_PER_CWE:
                break

            cve_obj = item.get("cve", {})
            cve_id = cve_obj.get("id", "").strip()
            if not cve_id or cve_id in existing_cases:
                continue

            commit_urls = []
            for ref in cve_obj.get("references", []):
                ref_url = ref.get("url", "")
                if "github.com/" in ref_url and "/commit/" in ref_url:
                    commit_urls.append(ref_url)

            if not commit_urls:
                continue

            src_records = []
            for curl in commit_urls[:2]:
                for repo_url, code in fetch_github_py_patch(curl):
                    if sha256(code) in exact_excl or sha256(normalize_for_manifest(code)) in norm_excl:
                        audit_rows.append({"cve": cve_id, "status": "rejected_exclusion_manifest", "source": "NVD-GitHub"})
                        continue
                    src_records.append({
                        "source": "NVD-GitHub",
                        "code": code,
                        "metadata": {
                            "repo": repo_url,
                            "source_file": curl,
                        },
                    })

            if not src_records:
                continue

            primary_norm = normalize_for_similarity(src_records[0]["code"])
            if is_near_duplicate(primary_norm, accepted_norms):
                audit_rows.append({"cve": cve_id, "status": "rejected_near_duplicate", "source": "NVD-GitHub"})
                continue

            existing_cases[cve_id] = {
                "cve": cve_id,
                "cwe": cwe_id,
                "source_records": src_records,
            }
            accepted_norms.append(primary_norm)
            audit_rows.append({"cve": cve_id, "status": "added_to_200", "source": "NVD-GitHub"})
            print(f"  + {cve_id} ({len(existing_cases)}/{TARGET_PER_CWE}) -> {src_records[0]['metadata']['repo']}")

        start_index += results_per_page
        time.sleep(6.5)  # Respect NVD public rate limit (5 req / 30s)


def main():
    exact_excl, norm_excl = load_exclusions()
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    final_counts = {}

    for cwe in ["CWE-89", "CWE-798"]:
        cases = load_existing_cases(cwe)
        accepted_norms = []
        audit_rows = []

        for cve, rec in cases.items():
            for sr in rec.get("source_records", []):
                accepted_norms.append(normalize_for_similarity(sr["code"]))
            audit_rows.append({"cve": cve, "status": "kept_existing", "source": rec["source_records"][0]["source"]})

        harvest_cwe_from_nvd(cwe, cases, accepted_norms, exact_excl, norm_excl, audit_rows)

        out_jsonl = FINAL_DIR / cwe / "cases.jsonl"
        with out_jsonl.open("w", encoding="utf-8") as f:
            for rec in cases.values():
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")

        audit_csv = PROCESSED_DIR / f"{cwe.lower().replace('-', '')}_selection_audit.csv"
        with audit_csv.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["cve", "status", "source"])
            writer.writeheader()
            writer.writerows(audit_rows)

        final_counts[cwe] = len(cases)
        print(f"DONE {cwe}: {len(cases)}/{TARGET_PER_CWE} saved -> {out_jsonl}")

    if COUNT_REPORT_FILE.exists():
        lines = COUNT_REPORT_FILE.read_text(encoding="utf-8").splitlines()
        updated = []
        for line in lines:
            if line.startswith("CWE-89:"):
                updated.append(f"CWE-89: {final_counts['CWE-89']}/{TARGET_PER_CWE}")
            elif line.startswith("CWE-798:"):
                updated.append(f"CWE-798: {final_counts['CWE-798']}/{TARGET_PER_CWE}")
            else:
                updated.append(line)
        COUNT_REPORT_FILE.write_text("\n".join(updated) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()