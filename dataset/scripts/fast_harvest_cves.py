import concurrent.futures
import csv
import hashlib
import json
import re
import time
import urllib.parse
import urllib.request
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


def save_cases(cwe_id: str, cases: dict[str, dict]):
    out_jsonl = FINAL_DIR / cwe_id / "cases.jsonl"
    with out_jsonl.open("w", encoding="utf-8") as f:
        for rec in cases.values():
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")


def is_near_duplicate(norm_sim_code: str, accepted_norm_codes: list[str]) -> bool:
    for existing_norm in accepted_norm_codes:
        len_a, len_b = len(norm_sim_code), len(existing_norm)
        if min(len_a, len_b) / max(len_a, len_b, 1) < SIMILARITY_THRESHOLD:
            continue
        if SequenceMatcher(None, norm_sim_code, existing_norm).ratio() >= SIMILARITY_THRESHOLD:
            return True
    return False


def fetch_github_py_patch(commit_url: str) -> list[tuple[str, str]]:
    m = re.match(r"https?://github\.com/([^/]+/[^/]+)/commit/([0-9a-fA-F]{7,40})", commit_url)
    if not m:
        return []
    repo, sha = m.group(1), m.group(2)
    patch_url = f"https://github.com/{repo}/commit/{sha}.patch"
    try:
        req = urllib.request.Request(patch_url, headers={"User-Agent": "MajorProject-FastHarvester"})
        with urllib.request.urlopen(req, timeout=8) as resp:
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


def fetch_nvd_page(cwe_id: str, start_index: int, results_per_page: int = 2000) -> dict:
    params = urllib.parse.urlencode({
        "cweId": cwe_id,
        "startIndex": start_index,
        "resultsPerPage": results_per_page,
    })
    url = f"{NVD_API_URL}?{params}"
    req = urllib.request.Request(url, headers={"User-Agent": "MajorProject-FastHarvester"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8"))


def process_candidate_cve(cve_id: str, commit_urls: list[str]):
    src_records = []
    for curl in commit_urls[:2]:
        for repo_url, code in fetch_github_py_patch(curl):
            src_records.append({
                "source": "NVD-GitHub",
                "code": code,
                "metadata": {"repo": repo_url, "source_file": curl},
            })
    return cve_id, src_records


def harvest_cwe_newest_first(
    cwe_id: str,
    cases: dict[str, dict],
    accepted_norms: list[str],
    exact_excl: set[str],
    norm_excl: set[str],
    audit_rows: list[dict],
):
    # Probe totalResults first (1 item) so we can jump straight to the newest pages
    probe = fetch_nvd_page(cwe_id, start_index=0, results_per_page=1)
    total_results = probe.get("totalResults", 0)
    print(f"[{cwe_id}] Total NVD CVEs: {total_results}. Jumping to newest pages first...")
    time.sleep(6.2)

    page_size = 2000
    last_offset = max(0, ((total_results - 1) // page_size) * page_size)

    for offset in range(last_offset, -1, -page_size):
        if len(cases) >= TARGET_PER_CWE:
            break

        print(f"[{cwe_id}] Fetching NVD offset {offset} (current: {len(cases)}/{TARGET_PER_CWE})...", flush=True)
        try:
            payload = fetch_nvd_page(cwe_id, start_index=offset, results_per_page=page_size)
        except Exception as exc:
            print(f"[{cwe_id}] Error at offset {offset}: {exc}")
            time.sleep(6.5)
            continue

        # Collect CVEs in this page that have GitHub commit URLs
        tasks = []
        for item in reversed(payload.get("vulnerabilities", [])):
            cve_obj = item.get("cve", {})
            cve_id = cve_obj.get("id", "").strip()
            if not cve_id or cve_id in cases:
                continue
            commits = [
                r["url"] for r in cve_obj.get("references", [])
                if "github.com/" in r.get("url", "") and "/commit/" in r.get("url", "")
            ]
            if commits:
                tasks.append((cve_id, commits))

        print(f"  Checking {len(tasks)} GitHub-linked CVEs in parallel...", flush=True)
        with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
            futures = [pool.submit(process_candidate_cve, cid, urls) for cid, urls in tasks]
            for fut in concurrent.futures.as_completed(futures):
                if len(cases) >= TARGET_PER_CWE:
                    break
                cve_id, src_records = fut.result()
                if not src_records:
                    continue

                valid_recs = [
                    sr for sr in src_records
                    if sha256(sr["code"]) not in exact_excl
                    and sha256(normalize_for_manifest(sr["code"])) not in norm_excl
                ]
                if not valid_recs:
                    audit_rows.append({"cve": cve_id, "status": "rejected_exclusion_manifest", "source": "NVD-GitHub"})
                    continue

                primary_norm = normalize_for_similarity(valid_recs[0]["code"])
                if is_near_duplicate(primary_norm, accepted_norms):
                    audit_rows.append({"cve": cve_id, "status": "rejected_near_duplicate", "source": "NVD-GitHub"})
                    continue

                cases[cve_id] = {"cve": cve_id, "cwe": cwe_id, "source_records": valid_recs}
                accepted_norms.append(primary_norm)
                audit_rows.append({"cve": cve_id, "status": "added_to_200", "source": "NVD-GitHub"})
                print(f"  + {cve_id} ({len(cases)}/{TARGET_PER_CWE}) -> {valid_recs[0]['metadata']['repo']}", flush=True)

        # Checkpoint after every page
        save_cases(cwe_id, cases)
        time.sleep(6.2)


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

        harvest_cwe_newest_first(cwe, cases, accepted_norms, exact_excl, norm_excl, audit_rows)
        save_cases(cwe, cases)

        audit_csv = PROCESSED_DIR / f"{cwe.lower().replace('-', '')}_selection_audit.csv"
        with audit_csv.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["cve", "status", "source"])
            writer.writeheader()
            writer.writerows(audit_rows)

        final_counts[cwe] = len(cases)
        print(f"DONE {cwe}: {len(cases)}/{TARGET_PER_CWE}")

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