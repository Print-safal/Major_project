import json
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from pydantic import ValidationError

from rag_int import llm_service


def vulnerable_payload():
    return {
        "vulnerable": True,
        "vulnerabilities": [{
            "cwe": "CWE-89",
            "vulnerability_name": "SQL injection",
            "location": "query construction",
            "explanation": "Untrusted data is interpolated into SQL.",
            "remediation": "Use a parameterized query.",
        }],
    }


class SecurityReviewSchemaTests(unittest.TestCase):
    def test_valid_vulnerable_response(self):
        result = llm_service.SecurityReview.model_validate(vulnerable_payload())
        self.assertTrue(result.vulnerable)
        self.assertEqual(result.vulnerabilities[0].cwe, "CWE-89")

    def test_valid_safe_response(self):
        result = llm_service.SecurityReview.model_validate({
            "vulnerable": False,
            "vulnerabilities": [],
        })
        self.assertFalse(result.vulnerable)

    def test_invalid_cwe_identifier(self):
        payload = vulnerable_payload()
        payload["vulnerabilities"][0]["cwe"] = "CWE-999"
        with self.assertRaises(ValidationError):
            llm_service.SecurityReview.model_validate(payload)

    def test_non_boolean_vulnerability_flag(self):
        payload = {"vulnerable": 1, "vulnerabilities": []}
        with self.assertRaises(ValidationError):
            llm_service.SecurityReview.model_validate(payload)

    def test_inconsistent_flag_and_findings(self):
        payload = vulnerable_payload()
        payload["vulnerable"] = False
        with self.assertRaises(ValidationError):
            llm_service.SecurityReview.model_validate(payload)

    def test_extra_unexpected_fields_are_rejected(self):
        payload = vulnerable_payload()
        payload["confidence"] = 0.9
        with self.assertRaises(ValidationError):
            llm_service.SecurityReview.model_validate(payload)

    def test_enriched_api_schema_rejects_invalid_confidence(self):
        payload = {
            "vulnerable": False,
            "vulnerabilities": [],
            "assessment_confidence": {
                "vulnerable": False,
                "score": None,
                "level": "Undetermined",
                "components": [],
                "finding_confidences": [],
                "supporting_evidence": [],
                "conflicting_evidence": [],
                "explanation": "insufficient",
            },
        }
        valid = llm_service.EnrichedSecurityReview.model_validate(payload)
        self.assertIsNone(valid.assessment_confidence.score)

        bad_score = {**payload, "assessment_confidence": {
            **payload["assessment_confidence"], "score": 101,
        }}
        with self.assertRaises(ValidationError):
            llm_service.EnrichedSecurityReview.model_validate(bad_score)

        bad_level = {**payload, "assessment_confidence": {
            **payload["assessment_confidence"], "level": "High",
        }}
        with self.assertRaises(ValidationError):
            llm_service.EnrichedSecurityReview.model_validate(bad_level)


class ReviewCodeReliabilityTests(unittest.TestCase):
    def test_context_and_stats_are_preserved(self):
        usage = SimpleNamespace(prompt_tokens=11, completion_tokens=7, total_tokens=18)
        message = SimpleNamespace(content=json.dumps({
            "vulnerable": False,
            "vulnerabilities": [],
        }))
        response = SimpleNamespace(usage=usage, choices=[SimpleNamespace(message=message)])
        client = SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(
            create=unittest.mock.Mock(return_value=response),
        )))

        with patch.object(llm_service, "get_groq_client", return_value=client), \
             patch.object(llm_service.time, "perf_counter", side_effect=[10.0, 12.5]):
            result = llm_service.review_code("print('hello')", "Retrieved CWE evidence")

        self.assertFalse(result.vulnerable)
        call = client.chat.completions.create.call_args.kwargs
        self.assertEqual(call["model"], "openai/gpt-oss-120b")
        self.assertEqual(call["response_format"]["type"], "json_schema")
        user_message = call["messages"][1]["content"]
        self.assertIn("Retrieved CWE evidence", user_message)
        self.assertIn("supporting context, not proof", user_message)
        self.assertEqual(llm_service.LAST_CALL_STATS, {
            "llm_latency_seconds": 2.5,
            "prompt_tokens": 11,
            "completion_tokens": 7,
            "total_tokens": 18,
        })

    def test_stats_remain_available_when_validation_fails(self):
        usage = SimpleNamespace(prompt_tokens=3, completion_tokens=4, total_tokens=7)
        message = SimpleNamespace(content='{"vulnerable": "yes", "vulnerabilities": []}')
        response = SimpleNamespace(usage=usage, choices=[SimpleNamespace(message=message)])
        client = SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(
            create=unittest.mock.Mock(return_value=response),
        )))

        with patch.object(llm_service, "get_groq_client", return_value=client), \
             patch.object(llm_service.time, "perf_counter", side_effect=[1.0, 1.25]):
            with self.assertRaises(ValidationError):
                llm_service.review_code("pass")

        self.assertEqual(llm_service.LAST_CALL_STATS["total_tokens"], 7)
        self.assertEqual(llm_service.LAST_CALL_STATS["llm_latency_seconds"], 0.25)


if __name__ == "__main__":
    unittest.main()
