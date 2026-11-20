import argparse
import json
import os
import tempfile
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional

from google import genai
from google.genai import types
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
GEMINI_MODEL = "gemini-3.5-flash-lite"
PROMPT_VERSION = "V3"

# Keep this prompt identical to the Groq evaluation script for comparability.
SYSTEM_PROMPT = """
You are a security-focused Python code reviewer.
Analyze Python source code for real security vulnerabilities.

Return ONLY one valid JSON object. Do not return Markdown, code fences,
or text outside the JSON object.

Use exactly this structure:
{
  "vulnerable": true,
  "vulnerabilities": [
    {
      "cwe": "CWE-89",
      "vulnerability_name": "SQL Injection",
      "location": "Affected code location",
      "explanation": "Explanation",
      "remediation": "Practical remediation"
    }
  ]
}

Use exactly these field names: cwe, vulnerability_name, location,
explanation, remediation. Never use "name" instead of
"vulnerability_name". Do not add extra fields. All vulnerability fields
must be strings. The top-level vulnerable field must be a boolean.

For safe code return:
{"vulnerable": false, "vulnerabilities": []}

Evaluate ONLY:
1. CWE-89 — SQL Injection
2. CWE-78 — OS Command Injection
3. CWE-79 — Cross-Site Scripting (XSS)
4. CWE-22 — Path Traversal
5. CWE-798 — Use of Hard-coded Credentials

DECISION PROCESS:
1. Determine whether the code is actually vulnerable.
2. Trace untrusted input from source to security-sensitive sink.
3. Check all five target CWEs independently.
4. Use the most specific applicable CWE.
5. Do not invent vulnerabilities or rely on assumptions not shown in code.
6. An explicit exploit payload is not required when dangerous data flow is clear.

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

CWE identifiers MUST be exactly one of:
CWE-89, CWE-78, CWE-79, CWE-22, CWE-798

Never return only the numeric CWE. Return only the requested JSON object.
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
        truth = case["ground_truth_cwe"]
        if truth is not None and truth not in TARGET_CWES:
            raise ValueError(f"Invalid ground_truth_cwe in {case['test_id']}: {truth}")
    return cases


def atomic_save_json(path: str, data: dict) -> None:
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    fd, temp_path = tempfile.mkstemp(
        prefix=".gemini_checkpoint_", suffix=".tmp", dir=directory, text=True
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2, ensure_ascii=False)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, path)
    except Exception:
        try:
            os.remove(temp_path)
        except OSError:
            pass
        raise


def normalize_cwe(value: str) -> str:
    cwe = value.strip().upper()
    return f"CWE-{cwe}" if cwe.isdigit() else cwe


def extract_predicted_cwes(review: SecurityReview) -> List[str]:
    predicted = []
    for item in review.vulnerabilities:
        cwe = normalize_cwe(item.cwe)
        if cwe not in TARGET_CWES:
            raise ValueError(f"Invalid CWE returned by model: {cwe}")
        if cwe not in predicted:
            predicted.append(cwe)
    return predicted


def call_model(
    client: genai.Client, model: str, code: str, retries: int, retry_wait: float
):
    user_prompt = f"""
Analyze the following Python code for security vulnerabilities.
Return a valid JSON object only. Use the exact schema in the system prompt.
Do not use "name"; use "vulnerability_name".

Python code:
```python
{code}
```
"""
    last_error = None
    for attempt in range(1, retries + 1):
        started = time.perf_counter()
        try:
            response = client.models.generate_content(
                model=model,
                contents=user_prompt,
                config=types.GenerateContentConfig(
                    system_instruction=SYSTEM_PROMPT,
                    temperature=0,
                    response_mime_type="application/json",
                ),
            )
            elapsed = time.perf_counter() - started
            content = response.text
            if not content:
                raise ValueError("Model returned an empty response.")
            parsed = SecurityReview.model_validate_json(content)
            extract_predicted_cwes(parsed)

            usage = getattr(response, "usage_metadata", None)
            return parsed, elapsed, {
                "prompt_tokens": getattr(usage, "prompt_token_count", None),
                "completion_tokens": getattr(usage, "candidates_token_count", None),
                "total_tokens": getattr(usage, "total_token_count", None),
            }

        except Exception as exc:
            last_error = exc
            if attempt >= retries:
                break
            message = str(exc).lower()
            is_rate_or_capacity = (
                "429" in message or "503" in message
                or "resource_exhausted" in message
                or "unavailable" in message
            )
            wait_seconds = min(retry_wait * (2 ** (attempt - 1)), 300)
            if is_rate_or_capacity:
                print(
                    f"\n  Gemini rate/capacity limit. Waiting {wait_seconds}s "
                    f"before retry {attempt + 1}/{retries}."
                )
            else:
                wait_seconds = min(2 ** (attempt - 1), 30)
                print(
                    f"\n  {type(exc).__name__}: retrying in {wait_seconds}s "
                    f"({attempt + 1}/{retries})."
                )
            time.sleep(wait_seconds)

    raise RuntimeError(f"{type(last_error).__name__}: {last_error}")


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


def calculate_metrics(cases: List[dict], results: List[dict]) -> dict:
    result_by_id = {r["test_id"]: r for r in results}
    tp = tn = fp = fn = 0
    exact_matches = 0
    vulnerable_evaluated = 0

    for case in cases:
        result = result_by_id.get(case["test_id"])
        if not result or result.get("status") != "success":
            continue
        actual = case["ground_truth_cwe"] is not None
        predicted = bool(result["predicted_vulnerable"])
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
            if case["ground_truth_cwe"] in result["predicted_cwes"]:
                exact_matches += 1

    metrics = binary_metrics(tp, tn, fp, fn)
    metrics["exact_cwe_matches"] = exact_matches
    metrics["vulnerable_cases_evaluated"] = vulnerable_evaluated
    metrics["exact_cwe_accuracy"] = (
        exact_matches / vulnerable_evaluated if vulnerable_evaluated else 0.0
    )

    per_cwe = {}
    for cwe in TARGET_CWES:
        c_tp = c_tn = c_fp = c_fn = 0
        for case in cases:
            result = result_by_id.get(case["test_id"])
            if not result or result.get("status") != "success":
                continue
            expected = case["ground_truth_cwe"] == cwe
            predicted = cwe in result["predicted_cwes"]
            if expected and predicted:
                c_tp += 1
            elif expected:
                c_fn += 1
            elif predicted:
                c_fp += 1
            else:
                c_tn += 1
        per_cwe[cwe] = binary_metrics(c_tp, c_tn, c_fp, c_fn)
    metrics["per_cwe"] = per_cwe
    return metrics


def build_output(model: str, input_path: str, cases: List[dict], results: List[dict]) -> dict:
    successful = [r for r in results if r.get("status") == "success"]
    failed = [r for r in results if r.get("status") == "failed"]
    latencies = [r["latency_seconds"] for r in successful]
    token_results = [
        r for r in successful
        if (r.get("token_usage") or {}).get("total_tokens") is not None
    ]
    prompt_tokens = sum((r["token_usage"].get("prompt_tokens") or 0) for r in token_results)
    completion_tokens = sum((r["token_usage"].get("completion_tokens") or 0) for r in token_results)

    return {
        "experiment": {
            "provider": "Google Gemini",
            "model": model,
            "prompt_version": PROMPT_VERSION,
            "input_file": input_path,
            "total_cases": len(cases),
            "successful_cases": len(successful),
            "failed_cases": len(failed),
            "pending_cases": len(cases) - len(successful) - len(failed),
            "rag_used": False,
            "temperature": 0,
            "response_format": "application/json with SecurityReview schema",
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "average_latency_seconds": sum(latencies) / len(latencies) if latencies else None,
            "total_prompt_tokens": prompt_tokens if token_results else None,
            "total_completion_tokens": completion_tokens if token_results else None,
            "token_usage_cases": len(token_results),
        },
        "metrics": calculate_metrics(cases, results),
        "results": results,
    }


def load_checkpoint(path: str) -> List[dict]:
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict) or not isinstance(data.get("results"), list):
        raise ValueError(f"{path} is not a compatible checkpoint.")
    return data["results"]


def main():
    parser = argparse.ArgumentParser(
        description="Resumable Gemini evaluation on the Security Review Prompt V3 benchmark."
    )
    parser.add_argument("--model", default=GEMINI_MODEL)
    parser.add_argument("--input", default="llm/final_150_cases.json")
    parser.add_argument("--output", default=None)
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--delay", type=float, default=2.0)
    parser.add_argument("--retries", type=int, default=4)
    parser.add_argument("--retry-wait", type=float, default=30.0)
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()

    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        raise RuntimeError("GEMINI_API_KEY is not set in this PowerShell session.")

    cases = load_cases(args.input)
    if args.limit:
        if args.limit < 1:
            raise ValueError("--limit must be >= 1")
        cases = cases[:args.limit]

    safe_name = args.model.replace("/", "_").replace(".", "_").replace(":", "_")
    output_path = args.output or (
        f"llm/results/gemini_{safe_name}_prompt_v3_resumable.json"
    )

    if os.path.exists(output_path) and not args.resume:
        raise FileExistsError(
            f"{output_path} already exists. Use --resume or choose another --output."
        )

    results = load_checkpoint(output_path) if args.resume else []
    valid_ids = {case["test_id"] for case in cases}
    for result in results:
        if result.get("test_id") not in valid_ids:
            raise ValueError("Checkpoint contains test IDs outside this benchmark.")

    successful_ids = {
        r["test_id"] for r in results if r.get("status") == "success"
    }

    client = genai.Client(api_key=api_key)
    print(f"Model: {args.model}")
    print(f"Prompt: Security Review Prompt {PROMPT_VERSION}")
    print(f"Cases: {len(cases)}")
    print(f"Already successful: {len(successful_ids)}")
    print(f"Checkpoint: {output_path}\n")

    try:
        for index, case in enumerate(cases, start=1):
            test_id = case["test_id"]
            if test_id in successful_ids:
                print(f"[{index}/{len(cases)}] {test_id}: SKIPPED (saved)")
                continue

            print(f"[{index}/{len(cases)}] {test_id}: ", end="", flush=True)
            try:
                review, latency, usage = call_model(
                    client, args.model, case["code"], args.retries, args.retry_wait
                )
                predicted = extract_predicted_cwes(review)
                result = {
                    "test_id": test_id,
                    "ground_truth_cwe": case["ground_truth_cwe"],
                    "predicted_cwes": predicted,
                    "predicted_vulnerable": review.vulnerable,
                    "exact_cwe_match": (
                        case["ground_truth_cwe"] is not None
                        and case["ground_truth_cwe"] in predicted
                    ),
                    "latency_seconds": round(latency, 4),
                    "token_usage": usage,
                    "raw_response": review.model_dump(),
                    "status": "success",
                }
                print(f"OK | predicted={predicted} | {latency:.2f}s")
            except KeyboardInterrupt:
                raise
            except Exception as exc:
                result = {
                    "test_id": test_id,
                    "ground_truth_cwe": case["ground_truth_cwe"],
                    "predicted_cwes": [],
                    "predicted_vulnerable": None,
                    "exact_cwe_match": False,
                    "status": "failed",
                    "error": f"{type(exc).__name__}: {exc}",
                }
                print(f"FAILED | {result['error']}")

            results = [r for r in results if r.get("test_id") != test_id]
            results.append(result)
            atomic_save_json(
                output_path, build_output(args.model, args.input, cases, results)
            )
            if args.delay > 0:
                time.sleep(args.delay)

    except KeyboardInterrupt:
        print("\nInterrupted. Saving progress...")

    output = build_output(args.model, args.input, cases, results)
    atomic_save_json(output_path, output)
    exp = output["experiment"]
    metrics = output["metrics"]

    print("\n--- CHECKPOINT SUMMARY ---")
    print(f"Successful: {exp['successful_cases']}/{exp['total_cases']}")
    print(f"Failed: {exp['failed_cases']}")
    print(f"Pending: {exp['pending_cases']}")
    for key in ["accuracy", "precision", "recall", "f1", "mcc", "exact_cwe_accuracy"]:
        value = metrics[key]
        print(f"{key}: {value:.4f}" if key == "mcc" else f"{key}: {value * 100:.2f}%")
    print(f"Average latency: {exp['average_latency_seconds']}")
    print(f"Saved checkpoint: {output_path}")
    if exp["pending_cases"] or exp["failed_cases"]:
        print("\nResume later using the same command plus --resume.")


if __name__ == "__main__":
    main()