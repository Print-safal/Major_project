import json
import subprocess
import re
from pathlib import Path

INVENTORY = Path("dataset/processed/consolidated/master_candidate_inventory.jsonl")
REPO_ROOT = Path("dataset/raw_downloads/cwe79_batch_repos")
OUTPUT = Path("dataset/processed/cwe79_batch_recovered")
MANIFEST = OUTPUT / "recovery_manifest_batch.jsonl"

REPO_ROOT.mkdir(parents=True, exist_ok=True)
OUTPUT.mkdir(parents=True, exist_ok=True)

def run_git(repo, *args):
    p = subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True, text=True, timeout=240
    )
    if p.returncode:
        raise RuntimeError(p.stderr[-1000:])
    return p.stdout

rows = [json.loads(x) for x in INVENTORY.read_text(encoding="utf-8").splitlines() if x.strip()]
candidates = [
    r for r in rows
    if r["cwe"] == "CWE-79"
    and not any(s.get("code") for s in r["source_records"])
]

done = set()
if MANIFEST.exists():
    for line in MANIFEST.read_text(encoding="utf-8").splitlines():
        if line.strip():
            done.add(json.loads(line)["cve"])

print("Candidates:", len(candidates), flush=True)
print("Already processed:", len(done), flush=True)

for i, row in enumerate(candidates, 1):
    cve = row["cve"]
    if cve in done:
        print(f"[{i}/{len(candidates)}] {cve}: already processed", flush=True)
        continue

    print(f"\n[{i}/{len(candidates)}] Starting {cve}", flush=True)

    result = {"cve": cve, "status": "failed"}
    try:
        meta = next(
            s["metadata"] for s in row["source_records"]
            if s.get("metadata", {}).get("repo_owner")
            and s.get("metadata", {}).get("repo_name")
            and s.get("metadata", {}).get("fix_sha")
        )

        owner, name, sha = meta["repo_owner"], meta["repo_name"], meta["fix_sha"]
        repo_name = re.sub(r"[^A-Za-z0-9_.-]", "_", f"{owner}__{name}")
        repo = REPO_ROOT / repo_name

        if not (repo / ".git").exists():
            if repo.exists():
                raise RuntimeError("Repository folder exists but is not a Git clone")
            print("  Cloning repository...", flush=True)
            subprocess.run(
                ["git", "clone", "--filter=blob:none", "--no-checkout",
                 f"https://github.com/{owner}/{name}.git", str(repo)],
                check=True, timeout=600
            )

        print("  Fetching fix commit...", flush=True)
        run_git(repo, "fetch", "origin", sha)

        parent = run_git(repo, "rev-parse", f"{sha}^").strip()
        changed = run_git(
            repo, "diff-tree", "--no-commit-id", "--name-only", "-r", sha
        ).splitlines()
        py_files = [p for p in changed if p.lower().endswith(".py")]

        if not py_files:
            result.update(status="no_python_changes", changed_files=changed)
        else:
            case_dir = OUTPUT / cve
            saved = []

            for file_path in py_files:
                try:
                    content = run_git(repo, "show", f"{parent}:{file_path}")
                    destination = case_dir / file_path
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    destination.write_text(content, encoding="utf-8")
                    saved.append(str(destination).replace("\\", "/"))
                except Exception as e:
                    print("  Could not extract", file_path, str(e)[:150], flush=True)

            case_dir.mkdir(parents=True, exist_ok=True)
            patch = run_git(repo, "show", "--format=fuller", sha)
            (case_dir / "fix.patch").write_text(patch, encoding="utf-8")

            result.update(
                status="recovered_candidate" if saved else "python_file_unavailable",
                repository=f"https://github.com/{owner}/{name}",
                fix_commit=sha,
                vulnerable_commit=parent,
                python_files=py_files,
                recovered_files=saved,
                patch_file=str(case_dir / "fix.patch").replace("\\", "/")
            )

    except Exception as e:
        result["reason"] = str(e)[:1000]

    with MANIFEST.open("a", encoding="utf-8") as f:
        f.write(json.dumps(result) + "\n")

    print(f"  Result: {result['status']}", flush=True)

print("\nBATCH COMPLETE", flush=True)
print("Manifest:", MANIFEST, flush=True)
print("Processed:", len(candidates), flush=True)
