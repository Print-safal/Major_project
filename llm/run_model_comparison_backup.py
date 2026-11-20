import argparse
import json
import os
import re
import time
from datetime import datetime, timezone
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


TARGET_CWES = ["CWE-89", "CWE-78", "CWE-79", "CWE-22", "CWE-798"]

# Use the exact model IDs returned by your Groq /models request.
ALLOWED_MODELS = [
    "openai/gpt-oss-20b",
    "qwen/qwen3.8-27b",
]

PROMPT_VERSION = "V3"

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
    with open(path, "r", encoding="utf-8") as handle:
        cases = json.load(handle)

    if not isinstance(cases, list):
        raise ValueError("Evaluation file must contain a JSON list.")

    required = {"test_id", "code", "ground_truth_cwe"}
    seen = set()
    for case in cases:
        missing = required - set(case)
        if missing:
            raise ValueError(
                f"Case {case.get('test_id', '<unknown>')} is missing: {sorted(missing)}"
            )
        if case["test_id"] in seen:
            raise ValueError(f"Duplicate test_id: {case['test_id']}")
        seen.add(case["test_id"])
        if case["ground_truth_cwe"] is not None and case["ground_truth_cwe"] not in TARGET_CWES:
            raise ValueError(
                f"Invalid ground_truth_cwe in {case['test_id']}: "
                f"{case['ground_truth_cwe']}"
            )
    return cases


def normalize_cwe(value: str) -> str:
    cwe = value.strip().upper()
    return f"CWE-{cwe}" if cwe.isdigit() else cwe


def extract_predicted_cwes(review: SecurityReview) -> List[str]:
    predicted = []
    for item in review.vulnerabilities:
        cwe = normalize_cwe(item.cwe)
        if cwe in TARGET_CWES and cwe not in predicted:
            predicted.append(cwe)
    return predicted


def call_model(client: Groq, model: str, code: str, retries: int):
    user_prompt = (
        "Analyze the following Python code for security vulnerabilities.\n\n"
        "Python code:\n\n```python\n"
        f"{code}\n"
        "```\n"
    )
    last_error = None

    for attempt in range(1, retries + 1):
        started = time.perf_counter()
        try:
            response = client.chat.completions.create(
                model=model,
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
            elapsed = time.perf_counter() - started
            parsed = SecurityReview.model_validate_json(
                response.choices[0].message.content
            )
            usage = getattr(response, "usage", None)
            return parsed, elapsed, {
                "prompt_tokens": getattr(usage, "prompt_tokens", None),
                "completion_tokens": getattr(usage, "completion_tokens", None),
                "total_tokens": getattr(usage, "total_tokens", None),
            }
        except Exception as exc:
            elapsed = time.perf_counter() - started
            last_error = exc
            if attempt < retries:
                time.sleep(min(2 ** (attempt - 1), 8))

    raise RuntimeError(str(last_error))


def binary_metrics(tp: int, tn: int, fp: int, fn: int) -> Dict[str, float]:
    total = tp + tn + fp + fn
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    accuracy = (tp + tn) / total if total else 0.0
    denominator = ((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn)) ** 0.5
    mcc = ((tp * tn) - (fp * fn)) / denominator if denominator else 0.0
    return {
        "TP": tp, "TN": tn, "FP": fp, "FN": fn,
        "accuracy": accuracy, "precision": precision,
        "recall": recall, "f1": f1, "mcc": mcc,
    }


def per_cwe_metrics(cases: List[dict], results: List[dict]) -> Dict[str, dict]:
    result_by_id = {r["test_id"]: r for r in results if "error" not in r}
    output = {}
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
            elif expected:
                fn += 1
            elif predicted:
                fp += 1
            else:
                tn += 1
        output[cwe] = binary_metrics(tp, tn, fp, fn)
    return output


def safe_model_filename(model: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_-]+", "_", model).strip("_").lower()


def main():
    parser = argparse.ArgumentParser(
        description="Compare a Groq model on the frozen 150-case Prompt V3 benchmark."
    )
    parser.add_argument("--model", required=True, choices=ALLOWED_MODELS)
    parser.add_argument("--input", default="llm/final_150_cases.json")
    parser.add_argument("--output", default=None)
    parser.add_argument("--limit", type=int, default=0,
                        help="Run only the first N cases; use 1 for the initial smoke test.")
    parser.add_argument("--delay", type=float, default=2.0)
    parser.add_argument("--retries", type=int, default=3)
    args = parser.parse_args()

    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        raise RuntimeError("GROQ_API_KEY is not set in this PowerShell session.")

    cases = load_cases(args.input)
    if args.limit:
        if args.limit < 1:
            raise ValueError("--limit must be >= 1")
        cases = cases[:args.limit]

    client = Groq(api_key=api_key)
    results = []
    total_latency = 0.0
    total_prompt_tokens = 0
    total_completion_tokens = 0
    token_counts_available = 0

    print(f"Model: {args.model}")
    print(f"Prompt: Security Review Prompt {PROMPT_VERSION}")
    print(f"Cases: {len(cases)}")
    print("Starting evaluation...")

    for index, case in enumerate(cases, start=1):
        test_id = case["test_id"]
        print(f"[{index}/{len(cases)}] {test_id}: ", end="", flush=True)
        try:
            review, latency, usage = call_model(
                client, args.model, case["code"], args.retries
            )
            predicted = extract_predicted_cwes(review)
            exact_match = (
                case["ground_truth_cwe"] is not None
                and case["ground_truth_cwe"] in predicted
            )
            total_latency += latency
            if usage["prompt_tokens"] is not None and usage["completion_tokens"] is not None:
                total_prompt_tokens += usage["prompt_tokens"]
                total_completion_tokens += usage["completion_tokens"]
                token_counts_available += 1

            results.append({
                "test_id": test_id,
                "ground_truth_cwe": case["ground_truth_cwe"],
                "predicted_cwes": predicted,
                "predicted_vulnerable": review.vulnerable,
                "exact_cwe_match": exact_match,
                "latency_seconds": round(latency, 4),
                "token_usage": usage,
                "raw_response": review.model_dump(),
            })
            print(f"OK | predicted={predicted} | {latency:.2f}s")
        except Exception as exc:
            results.append({
                "test_id": test_id,
                "ground_truth_cwe": case["ground_truth_cwe"],
                "predicted_cwes": [],
                "predicted_vulnerable": None,
                "exact_cwe_match": False,
                "error": str(exc),
            })
            print(f"FAILED | {type(exc).__name__}: {exc}")

        if args.delay > 0 and index < len(cases):
            time.sleep(args.delay)

    successful = [r for r in results if "error" not in r]
    failed = len(results) - len(successful)

    tp = tn = fp = fn = 0
    exact_matches = 0
    vulnerable_evaluated = 0
    for case, result in zip(cases, results):
        if "error" in result:
            continue
        actual = case["ground_truth_cwe"] is not None
        predicted = len(result["predicted_cwes"]) > 0
        if actual and predicted:
            tp += 1
        elif actual and not predicted:
            fn += 1
        elif not actual and predicted:
            fp += 1
        else:
            tn += 1
        if actual:
            vulnerable_evaluated += 1
            exact_matches += int(result["exact_cwe_match"])

    metrics = binary_metrics(tp, tn, fp, fn)
    metrics["exact_cwe_matches"] = exact_matches
    metrics["vulnerable_cases_evaluated"] = vulnerable_evaluated
    metrics["exact_cwe_accuracy"] = (
        exact_matches / vulnerable_evaluated if vulnerable_evaluated else 0.0
    )
    metrics["per_cwe"] = per_cwe_metrics(cases, successful)

    latencies = [r["latency_seconds"] for r in successful]
    experiment = {
        "model": args.model,
        "prompt_version": PROMPT_VERSION,
        "input_file": args.input,
        "total_cases": len(cases),
        "successful_cases": len(successful),
        "failed_cases": failed,
        "rag_used": False,
        "temperature": 0,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "average_latency_seconds": (
            sum(latencies) / len(latencies) if latencies else None
        ),
        "total_prompt_tokens": total_prompt_tokens if token_counts_available else None,
        "total_completion_tokens": total_completion_tokens if token_counts_available else None,
        "token_usage_cases": token_counts_available,
    }

    output = {
        "experiment": experiment,
        "metrics": metrics,
        "results": results,
    }

    output_path = args.output or (
        f"llm/results/{safe_model_filename(args.model)}_prompt_v3_results.json"
    )
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as handle:
        json.dump(output, handle, indent=2, ensure_ascii=False)

    print("\n--- SUMMARY ---")
    print(f"Successful: {len(successful)}/{len(cases)} | Failed: {failed}")
    for key in ["accuracy", "precision", "recall", "f1", "mcc", "exact_cwe_accuracy"]:
        print(f"{key}: {metrics[key] * 100:.2f}%" if key != "mcc"
              else f"{key}: {metrics[key]:.4f}")
    print(f"Average latency: {experiment['average_latency_seconds']}")
    print(f"Results saved: {output_path}")


if __name__ == "__main__":
    main()
