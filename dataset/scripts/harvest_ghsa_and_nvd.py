import concurrent.futures
import csv
import hashlib
import io
import json
import os
import re
import subprocess
import time
import urllib.parse
import urllib.request
import zipfile
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
GHSA_ZIP_URL = "https://codeload.github.com/github/advisory-database/zip/refs/heads/main"
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Include MITRE child CWEs of CWE-798 (259 = Hard-coded Password, 321 = Hard-coded Crypto Key)
CWE_QUERY_MAP = {
    "CWE-89": ["CWE-89"],
    "CWE-798": ["CWE-798", "CWE-259", "CWE-321"],
}


def get_github_token() -> str | None:
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        return token.strip()
    try:
        out = subprocess.check_output(
            ["git", "credential", "fill"],
            input="protocol=https\nhost=github.com\n\n",
            text=True,
            stderr=subprocess.DEVNULL,
            timeout=5,
        )
        for line in out.splitlines():
            if line.startswith("password="):
                return line.split("=", 1)[1].strip()
    except Exception:
        pass
    return None


GITHUB_TOKEN = get_github_token()


def make_headers(is_github: bool = False) -> dict[str, str]:
    headers = {"User-Agent": "MajorProject-DatasetHarvester"}
    if is_github and GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"
    return headers


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


def to_patch_url(ref_url: str) -> tuple[str, str] | None:
    """Converts GitHub /commit/<sha> or /pull/<num> URLs to downloadable .patch URLs."""
    m = re.match(r"https?://github\.com/([^/]+/[^/]+)/(commit/[0-9a-fA-F]{7,40}|pull/\d+)", ref_url)
    if not m:
        return None
    repo, target = m.group(1), m.group(2)
    return f"https://github.com/{repo}", f"https://github.com/{repo}/{target}.patch"


def fetch_github_py_patch(ref_url: str) -> list[tuple[str, str]]:
    parsed = to_patch_url(ref_url)
    if not parsed:
        return []
    repo_url, patch_url = parsed
    try:
        req = urllib.request.Request(patch_url, headers=make_headers(is_github=True))
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
                    results.append((repo_url, code))
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
            results.append((repo_url, code))

    return results


def harvest_from_ghsa_zip(
    cases_by_cwe: dict[str, dict],
    accepted_norms: dict[str, list[str]],
    exact_excl: set[str],
    norm_excl: set[str],
    audit_rows: dict[str, list[dict]],
):
    print("Downloading GitHub Advisory Database (GHSA) archive...")
    req = urllib.request.Request(GHSA_ZIP_URL, headers=make_headers(is_github=True))
    with urllib.request.urlopen(req, timeout=90) as resp:
        zip_bytes = resp.read()

    tasks = {"CWE-89": [], "CWE-798": []}
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        for name in zf.namelist():
            if not name.endswith(".json") or "/advisories/" not in name:
                continue
            adv = json.loads(zf.read(name).decode("utf-8"))
            cwes = {c.upper() for c in adv.get("database_specific", {}).get("cwe_ids", [])}

            target = None
            for primary_cwe, aliases in CWE_QUERY_MAP.items():
                if cwes.intersection(aliases):
                    target = primary_cwe
                    break
            if not target:
                continue

            cves = [a for a in adv.get("aliases", []) if a.startswith("CVE-")]
            cve_id = sorted(cves)[0] if cves else adv.get("id", "")
            if not cve_id or cve_id in cases_by_cwe[target]:
                continue

            # Prioritize Python ecosystem or any GitHub commit/PR reference
            ecosystems = {p.get("package", {}).get("ecosystem", "") for p in adv.get("affected", [])}
            refs = [
                r["url"] for r in adv.get("references", [])
                if to_patch_url(r.get("url", "")) is not None
            ]
            if refs:
                is_pip = 0 if "PyPI" in ecosystems else 1
                tasks[target].append((is_pip, cve_id, refs))

    for target in ["CWE-89", "CWE-798"]:
        tasks[target].sort(key=lambda x: x[0])  # PyPI advisories first
        print(f"[GHSA-{target}] Found {len(tasks[target])} candidate advisories with commit/PR links...")
        workers = 10 if GITHUB_TOKEN else 4
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            future_map = {
                pool.submit(lambda urls: [item for u in urls[:2] for item in fetch_github_py_patch(u)], refs): cve_id
                for _, cve_id, refs in tasks[target]
            }
            for fut in concurrent.futures.as_completed(future_map):
                if len(cases_by_cwe[target]) >= TARGET_PER_CWE:
                    break
                cve_id = future_map[fut]
                if cve_id in cases_by_cwe[target]:
                    continue
                extracted = fut.result()
                if not extracted:
                    continue

                valid_recs = [
                    {
                        "source": "GHSA-GitHub",
                        "code": code,
                        "metadata": {"repo": repo_url, "source_file": f"GHSA:{cve_id}"},
                    }
                    for repo_url, code in extracted
                    if sha256(code) not in exact_excl
                    and sha256(normalize_for_manifest(code)) not in norm_excl
                ]
                if not valid_recs:
                    continue

                primary_norm = normalize_for_similarity(valid_recs[0]["code"])
                if is_near_duplicate(primary_norm, accepted_norms[target]):
                    audit_rows[target].append({"cve": cve_id, "status": "rejected_near_duplicate", "source": "GHSA-GitHub"})
                    continue

                cases_by_cwe[target][cve_id] = {"cve": cve_id, "cwe": target, "source_records": valid_recs}
                accepted_norms[target].append(primary_norm)
                audit_rows[target].append({"cve": cve_id, "status": "added_to_200", "source": "GHSA-GitHub"})
                print(f"  + [{target}] {cve_id} ({len(cases_by_cwe[target])}/{TARGET_PER_CWE}) -> {valid_recs[0]['metadata']['repo']}", flush=True)

        save_cases(target, cases_by_cwe[target])


def harvest_remaining_from_nvd(
    target_cwe: str,
    cases: dict[str, dict],
    accepted_norms: list[str],
    exact_excl: set[str],
    norm_excl: set[str],
    audit_rows: list[dict],
):
    for query_cwe in CWE_QUERY_MAP[target_cwe]:
        if len(cases) >= TARGET_PER_CWE:
            break
        params = urllib.parse.urlencode({"cweId": query_cwe, "startIndex": 0, "resultsPerPage": 1})
        req = urllib.request.Request(f"{NVD_API_URL}?{params}", headers=make_headers())
        with urllib.request.urlopen(req, timeout=30) as resp:
            total_results = json.loads(resp.read().decode("utf-8")).get("totalResults", 0)
        time.sleep(6.2)

        page_size = 2000
        last_offset = max(0, ((total_results - 1) // page_size) * page_size)
        for offset in range(last_offset, -1, -page_size):
            if len(cases) >= TARGET_PER_CWE:
                break
            print(f"[NVD-{query_cwe}] Offset {offset} ({len(cases)}/{TARGET_PER_CWE})...", flush=True)
            params = urllib.parse.urlencode({"cweId": query_cwe, "startIndex": offset, "resultsPerPage": page_size})
            req = urllib.request.Request(f"{NVD_API_URL}?{params}", headers=make_headers())
            with urllib.request.urlopen(req, timeout=30) as resp:
                vulns = json.loads(resp.read().decode("utf-8")).get("vulnerabilities", [])

            tasks = []
            for item in reversed(vulns):
                cve_obj = item.get("cve", {})
                cve_id = cve_obj.get("id", "").strip()
                if not cve_id or cve_id in cases:
                    continue
                urls = [
                    r["url"] for r in cve_obj.get("references", [])
                    if to_patch_url(r.get("url", "")) is not None
                ]
                if urls:
                    tasks.append((cve_id, urls))

            workers = 10 if GITHUB_TOKEN else 4
            with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
                future_map = {
                    pool.submit(lambda u_list: [x for u in u_list[:2] for x in fetch_github_py_patch(u)], urls): cid
                    for cid, urls in tasks
                }
                for fut in concurrent.futures.as_completed(future_map):
                    if len(cases) >= TARGET_PER_CWE:
                        break
                    cve_id = future_map[fut]
                    if cve_id in cases:
                        continue
                    extracted = fut.result()
                    if not extracted:
                        continue
                    valid_recs = [
                        {
                            "source": f"NVD-{query_cwe}",
                            "code": code,
                            "metadata": {"repo": repo_url, "source_file": f"NVD:{cve_id}"},
                        }
                        for repo_url, code in extracted
                        if sha256(code) not in exact_excl
                        and sha256(normalize_for_manifest(code)) not in norm_excl
                    ]
                    if not valid_recs:
                        continue
                    primary_norm = normalize_for_similarity(valid_recs[0]["code"])
                    if is_near_duplicate(primary_norm, accepted_norms):
                        continue
                    cases[cve_id] = {"cve": cve_id, "cwe": target_cwe, "source_records": valid_recs}
                    accepted_norms.append(primary_norm)
                    audit_rows.append({"cve": cve_id, "status": "added_to_200", "source": f"NVD-{query_cwe}"})
                    print(f"  + [{target_cwe}] {cve_id} ({len(cases)}/{TARGET_PER_CWE}) -> {valid_recs[0]['metadata']['repo']}", flush=True)

            save_cases(target_cwe, cases)
            time.sleep(6.2)


def main():
    print(f"GitHub Auth Token detected: {'YES (5,000 req/hr)' if GITHUB_TOKEN else 'NO (using low concurrency)'}")
    exact_excl, norm_excl = load_exclusions()
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)

    cases_by_cwe = {"CWE-89": load_existing_cases("CWE-89"), "CWE-798": load_existing_cases("CWE-798")}
    accepted_norms = {cwe: [] for cwe in cases_by_cwe}
    audit_rows = {cwe: [] for cwe in cases_by_cwe}

    for cwe, cve_map in cases_by_cwe.items():
        for cve, rec in cve_map.items():
            for sr in rec.get("source_records", []):
                accepted_norms[cwe].append(normalize_for_similarity(sr["code"]))
            audit_rows[cwe].append({"cve": cve, "status": "kept_existing", "source": rec["source_records"][0]["source"]})

    harvest_from_ghsa_zip(cases_by_cwe, accepted_norms, exact_excl, norm_excl, audit_rows)

    for cwe in ["CWE-89", "CWE-798"]:
        if len(cases_by_cwe[cwe]) < TARGET_PER_CWE:
            harvest_remaining_from_nvd(cwe, cases_by_cwe[cwe], accepted_norms[cwe], exact_excl, norm_excl, audit_rows[cwe])

        save_cases(cwe, cases_by_cwe[cwe])
        audit_csv = PROCESSED_DIR / f"{cwe.lower().replace('-', '')}_selection_audit.csv"
        with audit_csv.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["cve", "status", "source"])
            writer.writeheader()
            writer.writerows(audit_rows[cwe])
        print(f"FINAL {cwe}: {len(cases_by_cwe[cwe])}/{TARGET_PER_CWE}")

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