from __future__ import annotations

import json
import shutil
import threading
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import httpx
from groq import APIConnectionError, APITimeoutError, AuthenticationError, RateLimitError

from evaluation.dataset import CATEGORIES, Case, load_dataset
from evaluation.key_manager import GroqKeyPool, KeyState, ProviderFailure
from evaluation.metrics import calculate_metrics
from evaluation.pipeline import _checkpoint, _invoke, _read_records, execute
from rag_int import llm_service
from rag_int.llm_service import SecurityReview


def _cases():
    return [Case("one", "print('one')", None, None, "SAFE-PYTHON"),
            Case("two", "print('two')", "CWE-78", "Command injection", "CWE-78")]


class DatasetTests(unittest.TestCase):
    def test_real_dataset_is_1200_unique(self):
        cases, hashes = load_dataset()
        self.assertEqual(len(cases), 1200)
        self.assertEqual(len({c.test_id for c in cases}), 1200)
        self.assertEqual(set(hashes), set(CATEGORIES))

    def test_duplicate_ids_are_rejected(self):
        root = Path(__file__).resolve().parent / "_test_workspace" / "duplicate-dataset"
        shutil.rmtree(root, ignore_errors=True)
        try:
            for category in CATEGORIES:
                folder = root / category
                folder.mkdir(parents=True)
                label = None if category == "SAFE-PYTHON" else category
                records = [{"test_id": f"{category}-{i}", "code": "pass", "ground_truth_cwe": label,
                            "vulnerability_name": None} for i in range(200)]
                if category == "CWE-22":
                    records[1]["test_id"] = records[0]["test_id"]
                (folder / "cases_benchmark.json").write_text(json.dumps(records))
            with self.assertRaisesRegex(ValueError, "duplicate test_id"):
                load_dataset(root)
        finally:
            shutil.rmtree(root, ignore_errors=True)


class MetricsTests(unittest.TestCase):
    def test_binary_safe_cwe_and_invalid_exclusion(self):
        records = [
            {"test_id": "a", "ground_truth_cwe": None, "predicted_cwes": [], "status": "completed", "parsing_status": "valid"},
            {"test_id": "b", "ground_truth_cwe": "CWE-78", "predicted_cwes": ["CWE-78"], "status": "completed", "parsing_status": "valid"},
            {"test_id": "c", "ground_truth_cwe": None, "predicted_cwes": ["CWE-89"], "status": "completed", "parsing_status": "valid"},
            {"test_id": "d", "ground_truth_cwe": "CWE-22", "predicted_cwes": None, "status": "invalid_response", "parsing_status": "invalid"},
        ]
        result = calculate_metrics(records, 4)
        self.assertEqual(result["overall"]["successfully_evaluated"], 3)
        self.assertEqual(result["overall"]["tp"], 1)
        self.assertEqual(result["overall"]["fp"], 1)
        self.assertEqual(result["overall"]["fn"], 0)
        self.assertEqual(result["safe_code"]["false_positive_rate"], 0.5)
        self.assertEqual(result["classification"]["confusion_matrix"]["CWE-78"]["CWE-78"], 1)


class ProviderTests(unittest.TestCase):
    @staticmethod
    def rate_limit(body, retry_after="0"):
        req = httpx.Request("POST", "https://example.invalid")
        resp = httpx.Response(429, request=req, headers={"retry-after": retry_after})
        message = str(body)
        return RateLimitError(message, response=resp, body=body)

    def test_explicit_per_key_limit_switches_alias(self):
        keys = [KeyState("KEY_1", "secret-one"), KeyState("KEY_2", "secret-two")]
        pool = GroqKeyPool(keys, max_retries=2, sleep=lambda _: None,
                           client_factory=lambda api_key: SimpleNamespace(key=api_key))
        seen = []
        def request(client):
            seen.append(client.key)
            if client.key == "secret-one":
                raise self.rate_limit({"error": {"message": "rate limit for this key"}})
            return "ok"
        result, alias, retries, aliases = pool.call(request)
        self.assertEqual((result, alias, retries), ("ok", "KEY_2", 1))
        self.assertEqual(aliases, ["KEY_1", "KEY_2"])
        self.assertEqual(seen, ["secret-one", "secret-two"])

    def test_ambiguous_limit_does_not_rotate_and_account_limit_stops(self):
        keys = [KeyState("KEY_1", "secret-one"), KeyState("KEY_2", "secret-two")]
        sleeps = []
        pool = GroqKeyPool(keys, max_retries=1, sleep=sleeps.append,
                           client_factory=lambda api_key: SimpleNamespace(key=api_key))
        seen = []
        with self.assertRaises(ProviderFailure):
            pool.call(lambda client: (seen.append(client.key), (_ for _ in ()).throw(self.rate_limit({"error": {"message": "rate limit"}}, retry_after="2.5")))[1])
        self.assertEqual(seen, ["secret-one", "secret-one"])
        self.assertEqual(sleeps, [2.5])
        with self.assertRaisesRegex(ProviderFailure, "Account-wide"):
            pool.call(lambda client: (_ for _ in ()).throw(self.rate_limit({"error": {"message": "organization quota exceeded"}})))

    def test_retry_after_auth_key_switch_and_connection_retry(self):
        sleeps = []
        keys = [KeyState("KEY_1", "secret-one"), KeyState("KEY_2", "secret-two")]
        pool = GroqKeyPool(keys, max_retries=3, sleep=sleeps.append,
                           client_factory=lambda api_key: SimpleNamespace(key=api_key))
        seen = []
        def per_key(client):
            seen.append(client.key)
            if client.key == "secret-one":
                raise self.rate_limit({"error": {"message": "rate limit for this key"}}, retry_after="3")
            return "ok"
        result, alias, _, aliases = pool.call(per_key)
        self.assertEqual((result, alias), ("ok", "KEY_2"))
        self.assertEqual(aliases, ["KEY_1", "KEY_2"])
        self.assertEqual(sleeps, [])  # KEY_2 was available, so the blocked key's wait is concurrent.

        # Rejected credentials disable that alias and permit another configured key.
        bad_resp = httpx.Response(401, request=httpx.Request("POST", "https://example.invalid"))
        auth = AuthenticationError("invalid API key", response=bad_resp, body={"error": "invalid API key"})
        pool = GroqKeyPool([KeyState("KEY_1", "secret-one"), KeyState("KEY_2", "secret-two")],
                           max_retries=2, sleep=lambda _: None,
                           client_factory=lambda api_key: SimpleNamespace(key=api_key))
        result, alias, _, aliases = pool.call(lambda client: (_ for _ in ()).throw(auth) if client.key == "secret-one" else "ok")
        self.assertEqual((result, alias), ("ok", "KEY_2"))
        self.assertEqual(aliases, ["KEY_1", "KEY_2"])

        # Connection failures retry the same authorized key with exponential backoff.
        sleeps = []
        request = httpx.Request("GET", "https://example.invalid")
        pool = GroqKeyPool([KeyState("KEY_1", "secret-one")], max_retries=2,
                           sleep=sleeps.append, client_factory=lambda api_key: SimpleNamespace(key=api_key))
        attempts = []
        def flaky(client):
            attempts.append(1)
            if len(attempts) == 1:
                raise APIConnectionError(request=request)
            return "connected"
        self.assertEqual(pool.call(flaky)[0], "connected")
        self.assertEqual(sleeps, [1.0])

        # The SDK's timeout exception follows the same bounded backoff path.
        sleeps = []
        pool = GroqKeyPool([KeyState("KEY_1", "secret-one")], max_retries=1,
                           sleep=sleeps.append, client_factory=lambda api_key: SimpleNamespace(key=api_key))
        timeout_attempts = []
        def timed_out_once(client):
            timeout_attempts.append(1)
            if len(timeout_attempts) == 1:
                raise APITimeoutError(request=request)
            return "done"
        self.assertEqual(pool.call(timed_out_once)[0], "done")
        self.assertEqual(sleeps, [1.0])

    def test_account_quota_error_does_not_rotate(self):
        keys = [KeyState("KEY_1", "secret-one"), KeyState("KEY_2", "secret-two")]
        pool = GroqKeyPool(keys, max_retries=3, client_factory=lambda api_key: SimpleNamespace(key=api_key))
        seen = []
        with self.assertRaisesRegex(ProviderFailure, "Account-wide"):
            pool.call(lambda client: (seen.append(client.key), (_ for _ in ()).throw(self.rate_limit({"error": {"message": "billing quota exceeded"}})))[1])
        self.assertEqual(seen, ["secret-one"])

    def test_secret_redacted_from_error(self):
        key = KeyState("KEY_1", "SENTINEL_SECRET")
        pool = GroqKeyPool([key], max_retries=0, client_factory=lambda api_key: SimpleNamespace(key=api_key))
        with self.assertRaises(ProviderFailure) as caught:
            pool.call(lambda client: (_ for _ in ()).throw(RuntimeError("token SENTINEL_SECRET")))
        self.assertNotIn("SENTINEL_SECRET", str(caught.exception))


class CheckpointTests(unittest.TestCase):
    def test_checkpoint_rewrites_unique_records_atomically(self):
        root = Path(__file__).resolve().parent / "_test_workspace" / "checkpoint"
        shutil.rmtree(root, ignore_errors=True)
        root.mkdir(parents=True)
        try:
            path = root / "raw.jsonl"
            first = {"test_id": "a", "status": "completed"}
            _checkpoint(path, [first])
            _checkpoint(path, [first, {"test_id": "b", "status": "failed"}])
            records = _read_records(path)
            self.assertEqual(list(records), ["a", "b"])
            self.assertEqual(len(path.read_text().splitlines()), 2)
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def test_resume_skips_success_and_retries_failure_only_on_request(self):
        cases = _cases()
        fake_key = KeyState("KEY_1", "SENTINEL_SECRET")
        valid = SecurityReview.model_validate({"vulnerable": False, "vulnerabilities": []})
        root = Path(__file__).resolve().parent / "_test_workspace" / "resume"
        shutil.rmtree(root, ignore_errors=True)
        root.mkdir(parents=True)
        try:
            temp = str(root)
            mocked_pool = Mock()
            mocked_pool.call.side_effect = [ProviderFailure("temporary", alias="KEY_1", retryable=True, attempts=1),
                                            ((valid, "{\"vulnerable\":false,\"vulnerabilities\":[]}", {"llm_latency_seconds": .2}, None), "KEY_1", 0, ["KEY_1"])]
            with patch("evaluation.pipeline.load_dataset", return_value=(cases, {"source": "hash"})), \
                 patch("evaluation.pipeline.load_keys", return_value=[fake_key]), \
                 patch("evaluation.pipeline.GroqKeyPool", return_value=mocked_pool):
                execute("llm-only", run_id="test-run", limit=2, results_root=temp)
                self.assertEqual(mocked_pool.call.call_count, 2)
                mocked_pool.call.reset_mock()
                execute("llm-only", run_id="test-run", limit=2, results_root=temp)
                self.assertEqual(mocked_pool.call.call_count, 0)
                mocked_pool.call.side_effect = [((valid, "{}", {"llm_latency_seconds": .1}, None), "KEY_1", 0, ["KEY_1"])]
                execute("llm-only", run_id="test-run", limit=2, retry_failed=True, results_root=temp)
                self.assertEqual(mocked_pool.call.call_count, 1)
            raw = next(Path(temp).rglob("raw_results.jsonl"))
            text = raw.read_text()
            self.assertNotIn("SENTINEL_SECRET", text)
            self.assertEqual(len(text.splitlines()), 2)
            results = [json.loads(line) for line in text.splitlines()]
            self.assertEqual(sum(r["status"] == "completed" for r in results), 2)
            self.assertTrue(all("key_aliases_used" in r for r in results))
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def test_configured_concurrency_runs_workers_and_checkpoints(self):
        cases = _cases()
        valid = SecurityReview.model_validate({"vulnerable": False, "vulnerabilities": []})
        root = Path(__file__).resolve().parent / "_test_workspace" / "concurrent"
        shutil.rmtree(root, ignore_errors=True)
        root.mkdir(parents=True)
        barrier = threading.Barrier(2)
        def review(*args, **kwargs):
            barrier.wait(timeout=3)
            return valid, "{}", {"llm_latency_seconds": .1}, None
        try:
            with patch("evaluation.pipeline.load_dataset", return_value=(cases, {"source": "hash"})), \
                 patch("evaluation.pipeline.load_keys", return_value=[KeyState("KEY_1", "secret")]), \
                 patch("evaluation.pipeline.GroqKeyPool") as pool_class, \
                 patch("evaluation.pipeline.llm_service.review_code", side_effect=review):
                pool = pool_class.return_value
                pool.call.side_effect = lambda request: (request(SimpleNamespace()), "KEY_1", 0, ["KEY_1"])
                execute("llm-only", run_id="concurrent", limit=2, concurrency=2, results_root=str(root))
            run_dir = root / "llm_only" / "concurrent"
            self.assertEqual(len((run_dir / "raw_results.jsonl").read_text().splitlines()), 2)
            config = json.loads((run_dir / "run_config.json").read_text())
            self.assertEqual(config["request_settings"]["effective_concurrency"], 2)
        finally:
            shutil.rmtree(root, ignore_errors=True)


class ModeTests(unittest.TestCase):
    def test_invalid_json_is_returned_as_unparseable_not_safe(self):
        response = SimpleNamespace(
            usage=None,
            choices=[SimpleNamespace(message=SimpleNamespace(content='{"vulnerable": "maybe"}'))],
        )
        client = SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(
            create=Mock(return_value=response),
        )))
        review, raw, _stats, parse_error = llm_service.review_code(
            "pass", client=client, llm_only=True, return_raw=True,
        )
        self.assertIsNone(review)
        self.assertIn("maybe", raw)
        self.assertIsNotNone(parse_error)

    def test_llm_and_rag_modes_use_separate_entry_points(self):
        review = SecurityReview.model_validate({"vulnerable": False, "vulnerabilities": []})
        pool = Mock()
        pool.call.side_effect = lambda request: (request(SimpleNamespace()), "KEY_1", 0, ["KEY_1"])
        with patch("evaluation.pipeline.llm_service.review_code") as llm, \
             patch("evaluation.pipeline.review_code_with_rag") as rag:
            llm.return_value = (review, "raw", {"llm_latency_seconds": 1}, None)
            _invoke("llm-only", "pass", pool)
            llm.assert_called_once()
            rag.assert_not_called()
        pool.call.side_effect = lambda request: (request(SimpleNamespace()), "KEY_1", 0, ["KEY_1"])
        with patch("evaluation.pipeline.review_code_with_rag") as rag:
            rag.return_value = (review, "raw", {"retrieval": {}, "llm": {}}, None)
            _invoke("rag-llm", "pass", pool)
            rag.assert_called_once()


if __name__ == "__main__":
    unittest.main()
