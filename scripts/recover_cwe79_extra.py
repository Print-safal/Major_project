import subprocess
from pathlib import Path

items = [
    ("CVE-2025-27145", "9001", "copyparty", "438ea6ccb06f39d7cbb4b6ee7ad44606e21a63dd"),
    ("CVE-2025-28380", "OpenC3", "cosmos", "12e3e12307afd3dbfc306f20d60400989db89883"),
    ("CVE-2025-53865", "roundup-tracker", "roundup", "3b1f22f331d4798491bd4746dbaaa6cfbe972952"),
    ("CVE-2025-54423", "9001", "copyparty", "895880aeb0be0813ddf732487596633f8f9fc3a6"),
    ("CVE-2025-64187", "OctoPrint", "OctoPrint", "9112e07b1085f4c1ee9eefc67985809251057a44"),
    ("CVE-2025-7885", "huashengdun", "webssh", "a7a704f111391c82efc1bacf89693ff45bda7f5f"),
    ("CVE-2026-22033", "HumanSignal", "label-studio", "ea2462bf042bbf370b79445d02a205fbe547b505"),
]

root = Path("dataset/processed/cwe79_extra_recovered")
repos = Path("dataset/raw_downloads/cwe79_extra_repos")
root.mkdir(parents=True, exist_ok=True)
repos.mkdir(parents=True, exist_ok=True)

for cve, owner, name, sha in items:
    print(f"\n=== {cve} ===", flush=True)
    repo = repos / f"{owner}_{name}"
    out = root / cve
    out.mkdir(parents=True, exist_ok=True)

    if not repo.exists():
        r = subprocess.run([
            "git", "clone", "--filter=blob:none",
            f"https://github.com/{owner}/{name}.git", str(repo)
        ])
        if r.returncode:
            print("CLONE_FAILED")
            continue

    def git(*args):
        return subprocess.run(
            ["git", "-C", str(repo), *args],
            capture_output=True, text=True
        )

    r = git("show", "-s", "--format=%P", sha)
    if r.returncode or not r.stdout.strip():
        print("COMMIT_OR_PARENT_NOT_FOUND")
        continue

    parent = r.stdout.strip().split()[0]
    diff = git("diff", "--name-only", parent, sha)
    pyfiles = [x for x in diff.stdout.splitlines() if x.endswith(".py")]

    print("Python files:", len(pyfiles))
    patch = git("diff", parent, sha, "--", "*.py")
    (out / "python_fix.patch").write_text(patch.stdout, encoding="utf-8")

    recovered = 0
    for f in pyfiles:
        content = git("show", f"{parent}:{f}")
        if content.returncode == 0:
            dest = out / f
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(content.stdout, encoding="utf-8")
            recovered += 1

    print("Vulnerable parent:", parent)
    print("Recovered files:", recovered)