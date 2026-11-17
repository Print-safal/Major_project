import concurrent.futures
import csv
import hashlib
import json
import os
import re
import subprocess
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


def gh_headers(accept: str = "application/vnd.github+json") -> dict[str, str]:
    h = {"User-Agent": "MajorProject-TopupHarvester", "Accept": accept}
    if GITHUB_TOKEN:
        h["Authorization"] = f"Bearer {GITHUB_TOKEN}"
    return h


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


def fetch_patch_py_snippets(patch_url: str) -> list[str]:
    try:
        req = urllib.request.Request(patch_url, headers=gh_headers(accept="text/plain"))
        with urllib.request.urlopen(req, timeout=10) as resp:
            patch_text = resp.read().decode("utf-8", errors="replace")
    except Exception:
        return []

    snippets = []
    current_file = None
    pre_lines = []

    for line in patch_text.splitlines():
        if line.startswith("diff --git "):
            if current_file and current_file.endswith(".py") and len(pre_lines) >= 4:
                code = "\n".join(pre_lines).strip()
                if 45 <= len(code) <= 8000:
                    snippets.append(code)
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
        if 45 <= len(code) <= 8000:
            snippets.append(code)

    return snippets


def search_github_commits(query: str, per_page: int = 100, pages: int = 3) -> list[dict]:
    items = []
    for page in range(1, pages + 1):
        params = urllib.parse.urlencode({"q": query, "per_page": per_page, "page": page})
        url = f"https://api.github.com/search/commits?{params}"
        try:
            req = urllib.request.Request(url, headers=gh_headers())
            with urllib.request.urlopen(req, timeout=20) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                batch = data.get("items", [])
                items.extend(batch)
                if len(batch) < per_page:
                    break
        except Exception as exc:
            print(f"  GitHub search warning ({query}, p{page}): {exc}")
            break
        time.sleep(2.2)  # Stay safely under 30 search req/min
    return items


def topup_from_github_commits(
    cwe_id: str,
    queries: list[str],
    cases: dict[str, dict],
    accepted_norms: list[str],
    exact_excl: set[str],
    norm_excl: set[str],
    audit_rows: list[dict],
):
    seen_repos = {
        sr.get("metadata", {}).get("repo")
        for rec in cases.values()
        for sr in rec.get("source_records", [])
        if sr.get("metadata", {}).get("repo")
    }

    for q in queries:
        if len(cases) >= TARGET_PER_CWE:
            break
        print(f"[{cwe_id}] Searching GitHub commits: {q} ({len(cases)}/{TARGET_PER_CWE})...", flush=True)
        commits = search_github_commits(q, per_page=100, pages=3)

        candidates = []
        for item in commits:
            repo_full = item.get("repository", {}).get("full_name", "")
            sha = item.get("sha", "")
            if not repo_full or not sha:
                continue
            repo_url = f"https://github.com/{repo_full}"
            # Avoid flooding dataset from a single repo
            if repo_url in seen_repos:
                continue
            case_id = f"GH-COMMIT-{repo_full.replace('/', '_')}-{sha[:10]}"
            if case_id in cases:
                continue
            candidates.append((case_id, repo_url, f"https://github.com/{repo_full}/commit/{sha}.patch"))

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
            future_map = {
                pool.submit(fetch_patch_py_snippets, patch_url): (case_id, repo_url, patch_url)
                for case_id, repo_url, patch_url in candidates
            }
            for fut in concurrent.futures.as_completed(future_map):
                if len(cases) >= TARGET_PER_CWE:
                    break
                case_id, repo_url, patch_url = future_map[fut]
                if repo_url in seen_repos:
                    continue
                snips = fut.result()
                if not snips:
                    continue

                valid_recs = [
                    {
                        "source": "GitHub-CommitSearch",
                        "code": code,
                        "metadata": {"repo": repo_url, "source_file": patch_url},
                    }
                    for code in snips
                    if sha256(code) not in exact_excl
                    and sha256(normalize_for_manifest(code)) not in norm_excl
                ]
                if not valid_recs:
                    continue

                primary_norm = normalize_for_similarity(valid_recs[0]["code"])
                if is_near_duplicate(primary_norm, accepted_norms):
                    audit_rows.append({"cve": case_id, "status": "rejected_near_duplicate", "source": "GitHub-CommitSearch"})
                    continue

                cases[case_id] = {"cve": case_id, "cwe": cwe_id, "source_records": valid_recs}
                accepted_norms.append(primary_norm)
                seen_repos.add(repo_url)
                audit_rows.append({"cve": case_id, "status": "added_to_200", "source": "GitHub-CommitSearch"})
                print(f"  + [{cwe_id}] {case_id} ({len(cases)}/{TARGET_PER_CWE})", flush=True)

        save_cases(cwe_id, cases)


def main():
    exact_excl, norm_excl = load_exclusions()
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)

    search_queries = {
        "CWE-89": [
            '"CWE-89" python',
            '"fix SQL injection" python',
            '"prevent SQL injection" python',
            '"parameterized query" "SQL injection" python',
        ],
        "CWE-798": [
            '"CWE-798" python',
            '"CWE-259" python',
            '"hardcoded password" python',
            '"hardcoded secret" python',
            '"hardcoded credentials" python',
            '"remove hardcoded" token OR password python',
        ],
    }

    final_counts = {}
    for cwe in ["CWE-89", "CWE-798"]:
        cases = load_existing_cases(cwe)
        accepted_norms = []
        audit_rows = []

        for cve, rec in cases.items():
            for sr in rec.get("source_records", []):
                accepted_norms.append(normalize_for_similarity(sr["code"]))
            audit_rows.append({"cve": cve, "status": "kept_existing", "source": rec["source_records"][0]["source"]})

        if len(cases) < TARGET_PER_CWE:
            topup_from_github_commits(cwe, search_queries[cwe], cases, accepted_norms, exact_excl, norm_excl, audit_rows)

        save_cases(cwe, cases)
        audit_csv = PROCESSED_DIR / f"{cwe.lower().replace('-', '')}_selection_audit.csv"
        with audit_csv.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["cve", "status", "source"])
            writer.writeheader()
            writer.writerows(audit_rows)

        final_counts[cwe] = len(cases)
        print(f"FINAL {cwe}: {len(cases)}/{TARGET_PER_CWE}")

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