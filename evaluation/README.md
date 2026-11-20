# Resumable 1,200-case evaluation

The evaluator reads the immutable `cases_benchmark.json` file in each of the six folders under `dataset/FINAL_DATASETS`. It validates 200 cases per category, labels, required fields, and globally unique IDs before a run. The resulting dataset hash and per-file hashes are recorded; no evaluation cases are added to RAG indexes.

## Configure Groq

The project uses Groq’s Python SDK, model `openai/gpt-oss-120b`, and the existing strict `SecurityReview` JSON schema and system prompt. Set either `GROQ_API_KEY` or `GROQ_EVAL_KEY_1`, `GROQ_EVAL_KEY_2`, etc. in the process environment or copy `.env.example` to `evaluation/.env.local`. Optional `GROQ_EVAL_KEY_n_ENABLED=false` disables a key. Keys are never included in result files; records contain aliases only.

## Commands

Run all cases in each mode, using stable run IDs so an interrupted run can be resumed:

```powershell
python -m evaluation.cli --mode llm-only --run-id llm-1200
python -m evaluation.cli --mode rag-llm --run-id rag-1200
```

Rerun the same command and run ID to continue; completed cases are skipped. Failed and invalid-response cases remain visible and are retried only with `--retry-failed`:

```powershell
python -m evaluation.cli --mode llm-only --run-id llm-1200 --retry-failed
```

Generate reports without API calls, or run a first-10-case batch:

```powershell
python -m evaluation.cli --mode rag-llm --run-id rag-1200 --metrics-only
python -m evaluation.cli --mode llm-only --run-id llm-smoke-10 --limit 10
```

RPM, retry limits, and concurrency can be configured. Sequential execution is the default. For concurrent runs, each finished case is checkpointed as soon as its worker completes:

```powershell
python -m evaluation.cli --mode rag-llm --run-id rag-1200 --max-rpm 20 --max-retries 5
```

Outputs are under `evaluation/results/{llm_only,rag_llm}/<run-id>/`: `raw_results.jsonl`, `run_config.json`, `predictions.csv`, `metrics.json`, `confusion_matrix.csv`, and `report.md`. The JSONL is atomically replaced after each case, with one record per known test ID. Each record stores the key alias used on each request attempt. A successful structured response is `completed`; invalid responses are `invalid_response`; API or processing failures are `failed`. Failed/invalid cases are excluded from metrics and are not safe predictions.

## API key retry policy

The runner handles Groq SDK errors without exposing exception credential text. It observes `Retry-After`, retries transient connection/server errors with exponential backoff, and disables rejected keys. Rotation occurs only when the response explicitly describes a per-key limit or an authorization failure. An ambiguous 429 is retried on the same key; explicit billing, organization, or account quota errors stop the run. If all keys are temporarily limited, the runner waits. It does not rotate keys to evade a shared account restriction.

## Metrics

Overall binary vulnerability metrics count any finding as vulnerable. Per-CWE values are one-vs-rest. Safe-code accuracy and false-positive rate use only safe ground-truth cases. Multiclass confusion uses the exact CWE for one finding, `SAFE-PYTHON` for zero findings, and `MULTIPLE` for more than one distinct CWE. Macro averages weight represented classes equally, weighted averages use class support, and micro averages aggregate binary decisions. Failed calls and invalid JSON are excluded from every predictive metric; coverage reports evaluated cases / planned cases.

The existing project response schema requires a boolean `vulnerable` value and has no explicit uncertainty field. Accordingly, it produces safe/vulnerable structured predictions; malformed or missing structured responses are recorded as `invalid_response`, never as safe. Expanding the model-facing schema would change the evaluation prompt contract, so this pipeline keeps the project schema unchanged.

## Mock-only verification

```powershell
python -m unittest discover -s evaluation/tests -v
python -m unittest rag_int.test_llm_service_reliability rag_int.test_rag_llm_150_case_eval
```

These tests mock Groq and do not consume API credits. No live API test is run by the test suite.
