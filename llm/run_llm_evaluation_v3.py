import json
import os
from typing import List
from groq import Groq
from pydantic import BaseModel, ConfigDict

class Vulnerability(BaseModel):
    model_config = ConfigDict(extra="forbid")
    cwe: str
    vulnerability_name: str
    location: str
    explanation: str
    remediation: str

class SecurityReview(BaseModel):
    model_config = ConfigDict(extra="forbid")
    vulnerable: bool
    vulnerabilities: List[Vulnerability]

api_key = os.getenv("GROQ_API_KEY")
if not api_key:
    raise RuntimeError("GROQ_API_KEY is not set. Set it in PowerShell before running.")

client = Groq(api_key=api_key)
MODEL = "openai/gpt-oss-120b"
INPUT_FILE = "llm_evaluation_set_v2.json"
OUTPUT_FILE = "groq_llm_prompt_v3_results.json"

SYSTEM_PROMPT = """You are a security-focused Python code reviewer.

Analyze Python source code for real security vulnerabilities.

Evaluate ONLY these five CWE categories:
1. CWE-89 — SQL Injection
2. CWE-78 — OS Command Injection
3. CWE-79 — Cross-Site Scripting (XSS)
4. CWE-22 — Path Traversal
5. CWE-798 — Use of Hard-coded Credentials

DECISION PROCESS:
1. First determine whether the code is actually vulnerable.
2. Trace untrusted input from source to security-sensitive sink.
3. Then check ALL FIVE target CWEs independently.
4. Use the most specific applicable CWE.
5. Do not invent vulnerabilities or rely on assumptions not shown in the code.
6. An explicit exploit payload is not required when the dangerous data flow is clear.

CWE-89 SQL INJECTION:
Report when untrusted input is incorporated into SQL through string
concatenation, f-strings, %-formatting, .format(), or other dynamic SQL.
Correctly parameterized queries are generally safe.

CWE-78 OS COMMAND INJECTION:
Report when untrusted input reaches OS command execution such as os.system(),
subprocess with shell=True, or dynamically constructed shell commands.
subprocess with a list of arguments and shell=False is normally safe.

CWE-79 XSS:
Report when untrusted input is inserted into HTML or browser-rendered output
without appropriate escaping or sanitization. Properly escaped output is safe.

CWE-22 PATH TRAVERSAL:
Report when untrusted input controls a filesystem path and can access outside
the intended directory. A variable filename alone is not sufficient evidence.

CWE-798 HARD-CODED CREDENTIALS:
Report credentials or authentication secrets directly embedded in source code,
including API keys, passwords, database passwords, tokens, secret keys, or
access credentials. If a credential is directly hard-coded, prefer CWE-798.
Environment variables and secret managers are not CWE-798.

MULTIPLE VULNERABILITIES:
Report multiple independent vulnerabilities when each is supported by code.
Do not add multiple CWEs for the same issue merely because several labels
could theoretically apply.

SAFE CODE:
If none of the five target vulnerabilities is present, set vulnerable=false
and vulnerabilities=[].

OUTPUT:
For each vulnerability provide the exact CWE identifier, vulnerability name,
affected location, concise explanation, and practical remediation.

CWE identifiers MUST be exactly one of:
CWE-89, CWE-78, CWE-79, CWE-22, CWE-798

Never return only the numeric CWE.
Return only the requested structured output.
"""

with open(INPUT_FILE, "r", encoding="utf-8") as f:
    test_cases = json.load(f)

TP = TN = FP = FN = 0
exact_cwe_matches = 0
vulnerable_case_count = 0
results = []

print("=" * 60)
print("LLM PROMPT V3 EVALUATION")
print("=" * 60)
print(f"Total test cases: {len(test_cases)}")
print(f"Model: Groq - {MODEL}")
print("Prompt: Security Review Prompt V3")
print()

for case in test_cases:
    test_id = case["test_id"]
    code = case["code"]
    ground_truth_cwe = case.get("ground_truth_cwe")
    print(f"Running {test_id}...", end=" ", flush=True)

    user_prompt = f"""Analyze the following Python code for security vulnerabilities.

Python code:

```python
{code}
```
"""

    try:
        response = client.chat.completions.create(
            model=MODEL,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            temperature=0,
            response_format={
                "type": "json_schema",
                "json_schema": {
                    "name": "security_review",
                    "schema": SecurityReview.model_json_schema(),
                    "strict": True,
                },
            },
        )

        parsed = SecurityReview.model_validate_json(
            response.choices[0].message.content
        )

        predicted_cwes = []
        for vulnerability in parsed.vulnerabilities:
            cwe = vulnerability.cwe.strip()
            if cwe.isdigit():
                cwe = f"CWE-{cwe}"
            if cwe.startswith("CWE-"):
                predicted_cwes.append(cwe)

        predicted_vulnerable = parsed.vulnerable
        predicted_detected = len(predicted_cwes) > 0
        actual_vulnerable = ground_truth_cwe is not None

        if actual_vulnerable and predicted_detected:
            TP += 1
        elif not actual_vulnerable and not predicted_detected:
            TN += 1
        elif not actual_vulnerable and predicted_detected:
            FP += 1
        elif actual_vulnerable and not predicted_detected:
            FN += 1

        exact_match = False
        if actual_vulnerable:
            vulnerable_case_count += 1
            if ground_truth_cwe in predicted_cwes:
                exact_cwe_matches += 1
                exact_match = True

        print(f"GT={ground_truth_cwe} -> Predicted={predicted_cwes}")

        results.append({
            "test_id": test_id,
            "ground_truth_cwe": ground_truth_cwe,
            "predicted_cwes": predicted_cwes,
            "predicted_vulnerable": predicted_vulnerable,
            "exact_cwe_match": exact_match,
            "model": MODEL,
            "prompt_version": "V3",
            "raw_response": parsed.model_dump(),
        })

    except Exception as e:
        print(f"ERROR: {e}")
        results.append({
            "test_id": test_id,
            "ground_truth_cwe": ground_truth_cwe,
            "predicted_cwes": [],
            "predicted_vulnerable": False,
            "exact_cwe_match": False,
            "model": MODEL,
            "prompt_version": "V3",
            "error": str(e),
        })

precision = TP / (TP + FP) if TP + FP else 0
recall = TP / (TP + FN) if TP + FN else 0
f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0
exact_cwe_accuracy = exact_cwe_matches / vulnerable_case_count if vulnerable_case_count else 0

metrics = {
    "TP": TP,
    "TN": TN,
    "FP": FP,
    "FN": FN,
    "precision": precision,
    "recall": recall,
    "f1": f1,
    "exact_cwe_matches": exact_cwe_matches,
    "exact_cwe_accuracy": exact_cwe_accuracy,
}

output = {
    "experiment": {
        "model": MODEL,
        "prompt_version": "V3",
        "evaluation_set": INPUT_FILE,
        "total_cases": len(test_cases),
    },
    "metrics": metrics,
    "results": results,
}

with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
    json.dump(output, f, indent=2, ensure_ascii=False)

print()
print("=" * 60)
print("PROMPT V3 RESULTS")
print("=" * 60)
print(f"TP: {TP}")
print(f"TN: {TN}")
print(f"FP: {FP}")
print(f"FN: {FN}")
print(f"Precision: {precision * 100:.2f}%")
print(f"Recall:    {recall * 100:.2f}%")
print(f"F1-score:  {f1 * 100:.2f}%")
print(f"Exact CWE matches: {exact_cwe_matches}/{vulnerable_case_count}")
print(f"Exact CWE accuracy: {exact_cwe_accuracy * 100:.2f}%")
print()
print(f"Results saved to: {OUTPUT_FILE}")
