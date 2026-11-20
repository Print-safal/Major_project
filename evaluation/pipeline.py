from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv

from evaluation.dataset import ROOT, combined_dataset_hash, load_dataset
from evaluation.key_manager import GroqKeyPool, ProviderFailure, load_keys, redact
from evaluation.metrics import calculate_metrics, write_reports

# Local evaluation environment is optional and remains untracked by .env.* ignore rules.
load_dotenv(ROOT / ".env", override=False)
load_dotenv(ROOT / "evaluation" / ".env.local", override=False)

from rag_int import llm_service
from rag_int.rag_llm_integration import review_code_with_rag


def _atomic_bytes(path: Path, contents: bytes):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(contents); stream.flush(); os.fsync(stream.fileno())
        os.replace(temp_name, path)
    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)


def _atomic_json(path: Path, value):
    _atomic_bytes(path, (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode())


def _checkpoint(path, records):
    content = "".join(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n" for r in records)
    _atomic_bytes(path, content.encode("utf-8"))


def _read_records(path):
    records = {}
    if not path.exists():
        return records
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        try:
            record = json.loads(line)
            case_id = record["test_id"]
            if case_id in records:
                raise ValueError(f"duplicate id {case_id}")
            records[case_id] = record
        except Exception as exc:
            raise ValueError(f"Invalid checkpoint line {line_no}: {exc}") from exc
    return records


def _safe_run_id(value):
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}", value):
        raise ValueError("run ID may contain letters, digits, dot, underscore and hyphen")
    return value


def _normal_prediction(review):
    if review is None:
        return None
    vulnerabilities = getattr(review, "vulnerabilities", []) or []
    cwes = sorted({v.cwe for v in vulnerabilities})
    return {"predicted_vulnerable": bool(cwes), "predicted_cwes": cwes,
            "structured_prediction": review.model_dump(mode="json")}


def _redact_values(value, secrets):
    if isinstance(value, str):
        return redact(value, secrets)
    if isinstance(value, list):
        return [_redact_values(item, secrets) for item in value]
    if isinstance(value, dict):
        return {key: _redact_values(item, secrets) for key, item in value.items()}
    return value


def _config(mode, run_id, case_limit, source_hashes, data_hash, max_rpm, max_retries, concurrency, aliases):
    prompt = llm_service.SYSTEM_PROMPT
    return {
        "run_id": run_id, "created_at": datetime.now(timezone.utc).isoformat(),
        "provider": "Groq", "model": llm_service.MODEL, "mode": mode,
        "dataset_files": source_hashes, "dataset_sha256": data_hash,
        "case_limit": case_limit, "cases_planned": case_limit or 1200,
        "prompt_sha256": hashlib.sha256(prompt.encode()).hexdigest(),
        "prompt_version": "rag_int.llm_service.SYSTEM_PROMPT",
        "temperature": 0, "response_schema": "SecurityReview (strict Pydantic JSON schema)",
        "retrieval": ({"top_k": 30, "candidate_k": 30, "aggregate_top_k": 5,
                       "shadow_ranking_enabled": __import__("rag_int.rag_llm_integration", fromlist=["USE_SHADOW_RANKING"]).USE_SHADOW_RANKING,
                       "contextual_evidence_enabled": __import__("rag_int.rag_llm_integration", fromlist=["USE_CONTEXTUAL_EVIDENCE"]).USE_CONTEXTUAL_EVIDENCE} if mode == "rag-llm" else None),
        "request_settings": {"max_rpm": max_rpm, "max_retries": max_retries,
                             "concurrency": concurrency, "effective_concurrency": concurrency,
                             "key_aliases_configured": aliases},
    }


def _invoke(mode, code, pool):
    def request(client):
        if mode == "llm-only":
            return llm_service.review_code(code, client=client, llm_only=True, return_raw=True)
        return review_code_with_rag(code, client=client, return_metadata=True)
    (review, raw, details, parse_error), alias, retries, aliases_used = pool.call(request)
    if mode == "llm-only":
        metadata = {"llm": details}
    else:
        metadata = details
    return review, raw, metadata, parse_error, alias, retries, aliases_used


def execute(mode: str, *, run_id=None, limit=None, retry_failed=False, max_rpm=30,
            max_retries=5, concurrency=1, metrics_only=False, results_root=None):
    if mode not in ("llm-only", "rag-llm"):
        raise ValueError("mode must be llm-only or rag-llm")
    if concurrency < 1:
        raise ValueError("concurrency must be at least 1")
    cases, source_hashes = load_dataset()
    if limit is not None:
        if limit < 1 or limit > 1200:
            raise ValueError("limit must be between 1 and 1200")
        cases = cases[:limit]
    data_hash = combined_dataset_hash(cases)
    run_id = _safe_run_id(run_id or datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"))
    output_root = Path(results_root or ROOT / "evaluation" / "results")
    run_dir = output_root / ("llm_only" if mode == "llm-only" else "rag_llm") / run_id
    raw_path = run_dir / "raw_results.jsonl"
    keys = load_keys()
    aliases = [key.alias for key in keys]
    config_path = run_dir / "run_config.json"
    config = _config(mode, run_id, limit, source_hashes, data_hash, max_rpm, max_retries, concurrency, aliases)
    signature_fields = ("provider", "model", "mode", "dataset_sha256", "case_limit", "prompt_sha256", "temperature", "response_schema", "retrieval")
    if metrics_only and not config_path.exists():
        raise ValueError("Metrics-only mode requires an existing run checkpoint")
    if config_path.exists():
        existing = json.loads(config_path.read_text(encoding="utf-8"))
        if any(existing.get(k) != config.get(k) for k in signature_fields):
            raise ValueError("Run ID already exists with different mode, dataset, prompt, or settings")
        config = existing
    else:
        _atomic_json(config_path, config)
    old = _read_records(raw_path)
    known_ids = {case.test_id for case in cases}
    extra_ids = set(old) - known_ids
    if extra_ids:
        raise ValueError(f"Checkpoint includes IDs outside current case selection: {sorted(extra_ids)[:5]}")

    if metrics_only:
        records = [old[c.test_id] for c in cases if c.test_id in old]
        metrics = calculate_metrics(records, len(cases))
        write_reports(run_dir, records, metrics)
        return run_dir

    if not keys:
        raise ValueError("No Groq API key configured. Set GROQ_EVAL_KEY_1 (or GROQ_API_KEY) in environment/evaluation/.env.local")
    pool = GroqKeyPool(keys, max_retries=max_retries, max_rpm=max_rpm)
    session = {"started_at": datetime.now(timezone.utc).isoformat(), "max_rpm": max_rpm,
               "max_retries": max_retries, "concurrency": concurrency,
               "key_aliases_configured": aliases}
    config.setdefault("execution_sessions", []).append(session)
    config["request_settings"].update({"max_rpm": max_rpm, "max_retries": max_retries,
                                       "concurrency": concurrency,
                                       "effective_concurrency": concurrency,
                                       "key_aliases_configured": aliases})
    _atomic_json(config_path, config)
    records = dict(old)
    start = time.perf_counter()
    elapsed_before_resume = float(config.get("elapsed_seconds", 0.0))
    pending = [case for case in cases
               if not (records.get(case.test_id) and records[case.test_id].get("status") == "completed")
               and not (records.get(case.test_id) and not retry_failed)]

    def process_case(case):
        previous = records.get(case.test_id)
        started = time.perf_counter()
        base = {"test_id": case.test_id, "execution_mode": mode,
                "ground_truth_cwe": case.ground_truth_cwe, "category": case.category,
                "predicted_cwes": None, "predicted_vulnerable": None,
                "structured_prediction": None, "raw_response": None,
                "status": "failed", "parsing_status": "not_attempted",
                "latency_seconds": None, "retry_count": 0, "key_alias": None,
                "key_aliases_used": [],
                "retrieval_metadata": None, "llm_metadata": None, "error": None}
        if previous:
            base["retry_count"] = int(previous.get("retry_count", 0))
            base["key_aliases_used"] = list(previous.get("key_aliases_used", []))
        try:
            review, raw, metadata, parse_error, alias, retries, aliases_used = _invoke(mode, case.code, pool)
            base.update({"raw_response": redact(raw, [k.secret for k in keys]),
                         "latency_seconds": time.perf_counter() - started,
                         "retry_count": int(base.get("retry_count", 0)) + retries,
                         "key_alias": alias,
                         "key_aliases_used": list(base.get("key_aliases_used", [])) + aliases_used})
            if mode == "rag-llm":
                base["retrieval_metadata"] = metadata.get("retrieval")
                base["llm_metadata"] = metadata.get("llm")
            else:
                base["llm_metadata"] = metadata.get("llm")
            if parse_error is not None or review is None:
                base.update({"status": "invalid_response", "parsing_status": "invalid",
                             "error": redact(parse_error or "empty model response", [k.secret for k in keys])})
            else:
                base.update(_normal_prediction(review))
                base.update({"status": "completed", "parsing_status": "valid"})
        except ProviderFailure as exc:
            base.update({"status": "failed", "parsing_status": "not_attempted",
                         "latency_seconds": time.perf_counter() - started,
                         "retry_count": int(base.get("retry_count", 0)) + exc.attempts, "key_alias": exc.alias,
                         "key_aliases_used": list(base.get("key_aliases_used", [])) + exc.aliases_used,
                         "error": redact(exc, [k.secret for k in keys])})
        except Exception as exc:
            base.update({"status": "failed", "parsing_status": "not_attempted",
                         "latency_seconds": time.perf_counter() - started,
                         "error": redact(f"{type(exc).__name__}: {exc}", [k.secret for k in keys])})
        return case, _redact_values(base, [k.secret for k in keys])

    def persist(case, base):
        records[case.test_id] = base
        ordered = [records[c.test_id] for c in cases if c.test_id in records]
        _checkpoint(raw_path, ordered)
        config.update({"last_checkpoint_at": datetime.now(timezone.utc).isoformat(),
                       "completed_cases": sum(r.get("status") == "completed" for r in ordered),
                       "failed_cases": sum(r.get("status") != "completed" for r in ordered),
                       "total_retry_count": sum(int(r.get("retry_count", 0)) for r in ordered),
                       "elapsed_seconds": elapsed_before_resume + time.perf_counter() - start,
                       "average_latency_seconds": (sum(r.get("latency_seconds") or 0 for r in ordered) / len(ordered) if ordered else 0)})
        _atomic_json(config_path, config)

    if concurrency == 1:
        completed = (process_case(case) for case in pending)
        for case, result in completed:
            persist(case, result)
    else:
        with ThreadPoolExecutor(max_workers=concurrency) as executor:
            futures = [executor.submit(process_case, case) for case in pending]
            for future in as_completed(futures):
                case, result = future.result()
                persist(case, result)

    ordered = [records[c.test_id] for c in cases if c.test_id in records]
    metrics = calculate_metrics(ordered, len(cases))
    write_reports(run_dir, ordered, metrics)
    return run_dir
