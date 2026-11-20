import pandas as pd
from pathlib import Path

folder = Path("dataset/raw_downloads/PyCode-Vul")

for filename in ["train.csv", "test.csv"]:
    df = pd.read_csv(folder / filename).fillna("")

    label_col = "label" if "label" in df.columns else "class"
    code_col = (
        "vulnerable_function_source"
        if "vulnerable_function_source" in df.columns
        else "function_code"
    )

    print("\nFILE:", filename)
    print("ROWS:", len(df))
    print("LABEL VALUES:")
    print(df[label_col].value_counts().head(10).to_dict())

    print("\nCWE EXAMPLES:")
    print(df["cwe_ids"].value_counts().head(15).to_dict())

    print("\nPREDICTED CWE EXAMPLES:")
    print(df["predicted_cwe_ids"].value_counts().head(10).to_dict())

    print("\nCODE LENGTHS:")
    print(df[code_col].astype(str).str.len().describe())