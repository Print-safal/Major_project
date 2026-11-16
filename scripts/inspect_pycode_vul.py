import urllib.request
from pathlib import Path
import pandas as pd
import re

out = Path("dataset/raw_downloads/PyCode-Vul")
out.mkdir(parents=True, exist_ok=True)

files = {
"train.csv": "https://huggingface.co/datasets/S-AIR-L/PyCode-Vul/resolve/main/PyCode_Vul-%20train-set.csv",
"test.csv": "https://huggingface.co/datasets/S-AIR-L/PyCode-Vul/resolve/main/PyCode_Vul%20test-set.csv",
}

for name, url in files.items():
    dest = out / name
    if not dest.exists():
        print("Downloading:", name)
        urllib.request.urlretrieve(url, dest)
    else:
        print("Already downloaded:", name)

targets = {"CWE-22", "CWE-78", "CWE-79", "CWE-89", "CWE-798"}

for name in files:
    path = out / name
    df = pd.read_csv(path).fillna("")
    print("\n", name)
    print("Rows:", len(df))
    print("Columns:", list(df.columns))

    cwe_col = "cwe_ids" if "cwe_ids" in df.columns else None
    code_cols = [
        c for c in [
            "vulnerable_function_source",
            "function_code"
        ] if c in df.columns
    ]

    counts = {cwe: 0 for cwe in sorted(targets)}
    eligible = 0

    if cwe_col:
        for _, row in df.iterrows():
            cwes = set(re.findall(r"CWE-\d+", str(row[cwe_col]).upper()))
            code = max(
                [str(row[c]).strip() for c in code_cols],
                key=len,
                default=""
            )
            cves = str(row.get("cve_ids", "")).strip()

            if not cves or len(code) < 100:
                continue

            label = row.get("label", row.get("class", ""))
            if str(label).strip() not in ("1", "1.0"):
                continue

            for cwe in cwes & targets:
                counts[cwe] += 1
                eligible += 1

    print("Eligible target-CWE records:", eligible)
    print("CWE counts:", counts)