import argparse
import json
import os
import time
from collections import defaultdict
from typing import Dict, List

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


TARGET_CWES = [
    "CWE-89",
    "CWE-78",
    "CWE-79",
    "CWE-22",
    "CWE-798",
]

MODEL = "openai/gpt-oss-120b"
PROMPT_VERSION = "V3"
DEFAULT_INPUT_FILE = "final_150_cases.json"
DEFAULT_OUTPUT_FILE = "groq_llm_v3_150_results.json"

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


def load_cases(path: str) -> List[dict]:
    with open(path, "r", encoding="utf-8") as f:
        cases = json.load(f)

    if not isinstance(cases, list):
        raise ValueError("Evaluation file must contain a JSON list.")

    required = {"test_id", "code", "ground_truth_cwe"}
    for case in cases:
        missing = required - set(case.keys())
        if missing:
            raise ValueError(
                f"Case {case.get('test_id', '<unknown>')} is missing: {sorted(missing)}"
            )

        if case["ground_truth_cwe"] is not None:
            if case["ground_truth_cwe"] not in TARGET_CWES:
                raise ValueError(
                    f"Invalid ground_truth_cwe in {case['test_id']}: "
                    f"{case['ground_truth_cwe']}"
                )

    return cases


def normalize_cwe(value: str) -> str:
    cwe = value.strip().upper()
    if cwe.isdigit():
        cwe = f"CWE-{cwe}"
    return cwe


def extract_predicted_cwes(review: SecurityReview) -> List[str]:
    predicted = []
    for vulnerability in review.vulnerabilities:
        cwe = normalize_cwe(vulnerability.cwe)
        if cwe in TARGET_CWES and cwe not in predicted:
            predicted.append(cwe)
    return predicted


def call_model(client: Groq, code: str, max_retries: int = 3) -> SecurityReview:
    user_prompt = f"""Analyze the following Python code for security vulnerabilities.

Python code:

```python
{code}
```
"""

    last_error = None

    for attempt in range(1, max_retries + 1):
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

            content = response.choices[0].message.content
            return SecurityReview.model_validate_json(content)

        except Exception as e:
            last_error = e
            if attempt < max_retries:
                wait_seconds = 2 ** (attempt - 1)
                print(
                    f"\n  Retry {attempt}/{max_retries - 1} after error: {e}"
                )
                time.sleep(wait_seconds)

    raise RuntimeError(str(last_error))


def binary_metrics(tp: int, tn: int, fp: int, fn: int) -> Dict[str, float]:
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (
        2 * precision * recall / (precision + recall)
        if (precision + recall)
        else 0.0
    )

    return {
        "TP": tp,
        "TN": tn,
        "FP": fp,
        "FN": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
    }


def per_cwe_metrics(cases: List[dict], results: List[dict]) -> Dict[str, dict]:
    result_by_id = {r["test_id"]: r for r in results if "error" not in r}
    metrics = {}

    for cwe in TARGET_CWES:
        tp = tn = fp = fn = 0

        for case in cases:
            result = result_by_id.get(case["test_id"])
            if result is None:
                continue

            expected = case["ground_truth_cwe"] == cwe
            predicted = cwe in result["predicted_cwes"]

            if expected and predicted:
                tp += 1
            elif expected and not predicted:
                fn += 1
            elif not expected and predicted:
                fp += 1
            else:
                tn += 1

        metrics[cwe] = binary_metrics(tp, tn, fp, fn)

    return metrics


def main():
    parser = argparse.ArgumentParser(
        description="Run frozen LLM V3 on the 150-case controlled benchmark."
    )
    parser.add_argument(
        "--input",
        default=DEFAULT_INPUT_FILE,
        help=f"Path to evaluation JSON (default: {DEFAULT_INPUT_FILE})",
    )
    parser.add_argument(
        "--output",
        default=DEFAULT_OUTPUT_FILE,
        help=f"Path for results JSON (default: {DEFAULT_OUTPUT_FILE})",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0.0,
        help="Optional delay in seconds between successful API calls.",
    )
    parser.add_argument(
        "--retries",
        type=int,
        default=3,
        help="Maximum model-call attempts per case.",
    )
    args = parser.parse_args()

    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        raise RuntimeError(
            "GROQ_API_KEY is not set. Set it in PowerShell before running."
        )

    test_cases = load_cases(args.input)
    client = Groq(api_key=api_key)

    TP = TN = FP = FN = 0
    exact_cwe_matches = 0
    vulnerable_case_count = 0
    successful_cases = 0
    failed_cases = 0

    results = []

    print("=" * 70)
    print("LLM PROMPT V3 — 150-CASE EVALUATION")
    print("=" * 70)
    print(f"Total test cases: {len(test_cases)}")
    print(f"Model: Groq - {MODEL}")
    print(f"Prompt: Security Review Prompt {PROMPT_VERSION}")
    print(f"Input: {args.input}")
    print()

    for index, case in enumerate(test_cases, start=1):
        test_id = case["test_id"]
        code = case["code"]
        ground_truth_cwe = case["ground_truth_cwe"]

        print(
            f"[{index:03d}/{len(test_cases):03d}] "
            f"Running {test_id}...",
            end=" ",
            flush=True,
        )

        try:
            parsed = call_model(
                client=client,
                code=code,
                max_retries=args.retries,
            )

            predicted_cwes = extract_predicted_cwes(parsed)
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

            successful_cases += 1

            print(f"GT={ground_truth_cwe} -> Predicted={predicted_cwes}")

            results.append(
                {
                    "test_id": test_id,
                    "ground_truth_cwe": ground_truth_cwe,
                    "predicted_cwes": predicted_cwes,
                    "predicted_vulnerable": parsed.vulnerable,
                    "exact_cwe_match": exact_match,
                    "model": MODEL,
                    "prompt_version": PROMPT_VERSION,
                    "raw_response": parsed.model_dump(),
                }
            )

        except Exception as e:
            failed_cases += 1
            print(f"ERROR: {e}")

            results.append(
                {
                    "test_id": test_id,
                    "ground_truth_cwe": ground_truth_cwe,
                    "predicted_cwes": [],
                    "predicted_vulnerable": None,
                    "exact_cwe_match": False,
                    "model": MODEL,
                    "prompt_version": PROMPT_VERSION,
                    "error": str(e),
                }
            )

        if args.delay > 0 and index < len(test_cases):
            time.sleep(args.delay)

    metrics = binary_metrics(TP, TN, FP, FN)

    exact_cwe_accuracy = (
        exact_cwe_matches / vulnerable_case_count
        if vulnerable_case_count
        else 0.0
    )

    successful_results = [
        r for r in results
        if "error" not in r
    ]

    cwe_metrics = per_cwe_metrics(test_cases, successful_results)

    output = {
        "experiment": {
            "model": MODEL,
            "prompt_version": PROMPT_VERSION,
            "evaluation_set": args.input,
            "total_cases": len(test_cases),
            "successful_cases": successful_cases,
            "failed_cases": failed_cases,
            "target_cwes": TARGET_CWES,
            "rag_used": False,
        },
        "metrics": {
            **metrics,
            "exact_cwe_matches": exact_cwe_matches,
            "vulnerable_cases_evaluated": vulnerable_case_count,
            "exact_cwe_accuracy": exact_cwe_accuracy,
            "per_cwe": cwe_metrics,
        },
        "results": results,
    }

    output_dir = os.path.dirname(args.output)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    print()
    print("=" * 70)
    print("PROMPT V3 — FINAL RESULTS")
    print("=" * 70)
    print(f"Successful cases: {successful_cases}/{len(test_cases)}")
    print(f"Failed cases:     {failed_cases}")
    print(f"TP: {TP}")
    print(f"TN: {TN}")
    print(f"FP: {FP}")
    print(f"FN: {FN}")
    print(f"Precision: {metrics['precision'] * 100:.2f}%")
    print(f"Recall:    {metrics['recall'] * 100:.2f}%")
    print(f"F1-score:  {metrics['f1'] * 100:.2f}%")
    print(
        f"Exact CWE matches: "
        f"{exact_cwe_matches}/{vulnerable_case_count}"
    )
    print(
        f"Exact CWE accuracy: "
        f"{exact_cwe_accuracy * 100:.2f}%"
    )

    print()
    print("Per-CWE metrics:")
    for cwe in TARGET_CWES:
        m = cwe_metrics[cwe]
        print(
            f"  {cwe}: "
            f"P={m['precision'] * 100:.2f}% "
            f"R={m['recall'] * 100:.2f}% "
            f"F1={m['f1'] * 100:.2f}% "
            f"(TP={m['TP']}, FP={m['FP']}, FN={m['FN']})"
        )

    print()
    print(f"Results saved to: {args.output}")


if __name__ == "__main__":
    main()
