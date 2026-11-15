import unittest
from unittest.mock import patch

from rag_int import llm_service
from rag_int import rag_llm_integration


SOURCE = "query = f\"SELECT * FROM users WHERE id = {user_id}\"\n"


def retrieved_result(cwe_id, cwe_name, chunk_text):
    return {
        "cwe_id": cwe_id,
        "cwe_name": cwe_name,
        "score": 0.91,
        "security_score": 0.83,
        "vulnerable_evidence_count": 2,
        "supporting_chunks": [
            {"section": "Mitigation", "text": chunk_text},
        ],
    }


class RagLlmIntegrationTests(unittest.TestCase):
    def setUp(self):
        rag_llm_integration.LAST_RAG_STATS.clear()

    @patch("rag_int.rag_llm_integration.review_code")
    @patch("rag_int.rag_llm_integration.aggregate_cwe_results")
    def test_retrieved_context_and_review_are_forwarded(self, aggregate, review):
        result = retrieved_result("CWE-89", "SQL Injection", "Use parameters")
        aggregate.return_value = [result]
        expected_review = llm_service.SecurityReview.model_validate({
            "vulnerable": False,
            "vulnerabilities": [],
        })
        review.return_value = expected_review

        returned = rag_llm_integration.review_code_with_rag(SOURCE)

        aggregate.assert_called_once_with(SOURCE, candidate_k=30, top_k=5)
        review.assert_called_once()
        kwargs = review.call_args.kwargs
        self.assertEqual(kwargs["code"], SOURCE)
        context = kwargs["security_context"]
        self.assertIn("CWE: CWE-89 - SQL Injection", context)
        self.assertIn("Evidence: Use parameters", context)
        self.assertIs(returned, expected_review)

    @patch("rag_int.rag_llm_integration.review_code")
    @patch("rag_int.rag_llm_integration.aggregate_cwe_results", return_value=[])
    def test_empty_retrieval_still_calls_llm_with_empty_context_message(
        self, aggregate, review,
    ):
        expected_review = object()
        review.return_value = expected_review

        returned = rag_llm_integration.review_code_with_rag(SOURCE)

        aggregate.assert_called_once_with(SOURCE, candidate_k=30, top_k=5)
        review.assert_called_once_with(
            code=SOURCE,
            security_context="No relevant security evidence was retrieved.",
        )
        self.assertIs(returned, expected_review)

    @patch("rag_int.rag_llm_integration.review_code")
    @patch("rag_int.rag_llm_integration.aggregate_cwe_results")
    def test_context_uses_only_first_two_results_and_first_chunk(
        self, aggregate, review,
    ):
        aggregate.return_value = [
            retrieved_result("CWE-89", "SQL Injection", "first chunk one") | {
                "supporting_chunks": [
                    {"section": "A", "text": "first chunk one"},
                    {"section": "B", "text": "first result extra chunk"},
                ],
            },
            retrieved_result("CWE-78", "OS Command Injection", "second chunk one") | {
                "supporting_chunks": [
                    {"section": "C", "text": "second chunk one"},
                    {"section": "D", "text": "second result extra chunk"},
                ],
            },
            retrieved_result("CWE-79", "Cross-Site Scripting", "third result") ,
        ]

        rag_llm_integration.review_code_with_rag(SOURCE)

        context = review.call_args.kwargs["security_context"]
        self.assertIn("CWE: CWE-89 - SQL Injection", context)
        self.assertIn("CWE: CWE-78 - OS Command Injection", context)
        self.assertNotIn("CWE: CWE-79", context)
        self.assertIn("first chunk one", context)
        self.assertIn("second chunk one", context)
        self.assertNotIn("first result extra chunk", context)
        self.assertNotIn("second result extra chunk", context)

    @patch("rag_int.rag_llm_integration.aggregate_cwe_results",
           side_effect=RuntimeError("private retrieval details"))
    def test_retrieval_failure_propagates_to_api_boundary(self, aggregate):
        with self.assertRaisesRegex(RuntimeError, "private retrieval details"):
            rag_llm_integration.review_code_with_rag(SOURCE)

        aggregate.assert_called_once_with(SOURCE, candidate_k=30, top_k=5)


if __name__ == "__main__":
    unittest.main()
