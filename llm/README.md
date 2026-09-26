# LLM Security Analysis — Prompt V3

This directory contains the LLM-only security analysis implementation and evaluation results for the project:

**RAG-Based AI Code Review for Detecting Security Vulnerabilities in Python Programs**

The LLM component performs security analysis of Python source code and classifies vulnerabilities using the five target CWE categories used in the project.

## Model

- Provider: Groq
- Model: `openai/gpt-oss-120b`
- Prompt: Security Review Prompt V3

The API key is supplied through the `GROQ_API_KEY` environment variable and is not stored in this repository.

---

## 150-Case Evaluation

The current frozen LLM-only baseline was evaluated on 150 controlled Python security test cases:

| Category | Cases |
|---|---:|
| CWE-89 — SQL Injection | 25 |
| CWE-78 — OS Command Injection | 25 |
| CWE-79 — Cross-Site Scripting | 25 |
| CWE-22 — Path Traversal | 25 |
| CWE-798 — Hard-coded Credentials | 25 |
| Safe cases | 25 |
| **Total** | **150** |

The same 150-case benchmark is intended to be used for the subsequent RAG + LLM evaluation so that the two approaches can be compared under the same test conditions.

---

## LLM-Only Baseline Results

| Metric | Result |
|---|---:|
| True Positives (TP) | 124 |
| True Negatives (TN) | 24 |
| False Positives (FP) | 1 |
| False Negatives (FN) | 1 |
| Precision | 99.20% |
| Recall | 99.20% |
| F1-score | 99.20% |
| CWE matches | 124/125 |
| CWE accuracy | 99.20% |

### Per-CWE Results

| CWE | Precision | Recall | F1-score |
|---|---:|---:|---:|
| CWE-89 | 100.00% | 100.00% | 100.00% |
| CWE-78 | 100.00% | 100.00% | 100.00% |
| CWE-79 | 100.00% | 96.00% | 97.96% |
| CWE-22 | 92.59% | 100.00% | 96.15% |
| CWE-798 | 100.00% | 100.00% | 100.00% |

---

## Files

### `run_llm_evaluation_v3.py`

Original LLM evaluation script used for the earlier evaluation set.

### `llm_evaluation_set_v2.json`

Earlier 34-case evaluation dataset containing vulnerable cases and controlled safe cases.

### `groq_llm_prompt_v3_results.json`

Results from the earlier LLM Prompt V3 evaluation.

### `run_llm_evaluation_v3_150.py`

Evaluation script for running Security Review Prompt V3 on the 150-case benchmark.

### `final_150_cases.json`

The 150-case controlled evaluation benchmark.

### `groq_llm_v3_150_results.json`

Completed results from the 150-case LLM-only evaluation.

---

## Evaluation Purpose

This evaluation establishes the **LLM-only baseline** before retrieval-augmented generation is introduced.

The planned comparison is:

```text
Python Code
    |
    +----------------------+
    |                      |
    v                      v
LLM Only               RAG + LLM
    |                      |
    +----------+-----------+
               |
               v
       Compare Evaluation
