import unittest
from unittest.mock import patch

from rag_int import llm_service
from rag_int import rag_llm_integration


SOURCE = '''
def lookup(conn, user):
    query = f"SELECT * FROM users WHERE id = '{user}'"
    conn.execute(query)
'''


def retrieved_result(cwe_id, cwe_name, score=.91, text="CWE guidance"):
    return {
        "cwe_id": cwe_id,
        "cwe_name": cwe_name,
        "score": score,
        "security_score": 0.83,
        "vulnerable_evidence_count": 2,
        "supporting_chunks": [{"section": "Mitigation", "text": text}],
    }


def candidate(cwe_id, score=.8, text="reference guidance"):
    return {
        "cwe_id": cwe_id,
        "semantic_score": score,
        "source": f"{cwe_id}.json",
        "section": "description",
        "text": text,
    }


def llm_review(vulnerabilities=()):
    return llm_service.SecurityReview.model_validate({
        "vulnerable": bool(vulnerabilities),
        "vulnerabilities": list(vulnerabilities),
    })


def llm_vulnerability(cwe, location="line 3"):
    return {
        "cwe": cwe,
        "vulnerability_name": f"Finding {cwe}",
        "location": location,
        "explanation": "Synthetic finding for integration test.",
        "remediation": "Apply the appropriate safeguard.",
    }


class RagLlmIntegrationTests(unittest.TestCase):
    def setUp(self):
        rag_llm_integration.LAST_RAG_STATS.clear()

    @patch("rag_int.rag_llm_integration.review_code")
    @patch("rag_int.rag_llm_integration.aggregate_cwe_results")
    @patch("rag_int.rag_llm_integration.semantic_search", return_value=[candidate("CWE-89")])
    def test_vulnerable_pipeline_attaches_confidence_and_context(
        self, semantic, aggregate, review,
    ):
        aggregate.return_value = [retrieved_result("CWE-89", "SQL Injection", text="Use parameters")]
        review.return_value = llm_review([llm_vulnerability("CWE-89")])

        returned = rag_llm_integration.review_code_with_rag(SOURCE)

        aggregate.assert_called_once_with(
            SOURCE, candidate_k=30, top_k=5, semantic_candidates=semantic.return_value
        )
        kwargs = review.call_args.kwargs
        self.assertEqual(kwargs["code"], SOURCE)
        self.assertIn("CWE: CWE-89 - SQL Injection", kwargs["security_context"])
        self.assertIn("AST and indicator evidence", kwargs["security_context"])
        self.assertIn("candidate evidence only", kwargs["security_context"])
        payload = returned.model_dump()
        self.assertTrue(payload["vulnerable"])
        finding = payload["vulnerabilities"][0]
        self.assertEqual(finding["cwe"], "CWE-89")
        self.assertEqual(finding["vulnerability_name"], "Finding CWE-89")
        self.assertIsNotNone(finding["confidence"]["score"])
        self.assertEqual(payload["assessment_confidence"]["level"], "High")
        self.assertEqual(len(payload["assessment_confidence"]["finding_confidences"]), 1)

    @patch("rag_int.rag_llm_integration.review_code")
    @patch("rag_int.rag_llm_integration.aggregate_cwe_results", return_value=[])
    @patch("rag_int.rag_llm_integration.semantic_search", return_value=[])
    def test_safe_pipeline_has_coverage_based_assessment(self, semantic, aggregate, review):
        review.return_value = llm_review()
        returned = rag_llm_integration.review_code_with_rag("value = 1\n")

        aggregate.assert_called_once_with(
            "value = 1\n", candidate_k=30, top_k=5, semantic_candidates=[]
        )
        self.assertFalse(returned.vulnerable)
        self.assertEqual(returned.vulnerabilities, [])
        self.assertEqual(returned.assessment_confidence.level, "Medium")
        self.assertIsNotNone(returned.assessment_confidence.score)
        self.assertIn("all five supported CWEs", returned.assessment_confidence.explanation)

    @patch("rag_int.rag_llm_integration.review_code")
    @patch("rag_int.rag_llm_integration.aggregate_cwe_results", return_value=[])
    @patch("rag_int.rag_llm_integration.semantic_search", return_value=[candidate("CWE-89")])
    def test_multiple_findings_get_different_confidence(self, semantic, aggregate, review):
        review.return_value = llm_review([
            llm_vulnerability("CWE-89", "line 3"),
            llm_vulnerability("CWE-78", "line 4"),
        ])
        returned = rag_llm_integration.review_code_with_rag(SOURCE)
        first, second = returned.vulnerabilities
        self.assertEqual(first.cwe, "CWE-89")
        self.assertEqual(second.cwe, "CWE-78")
        self.assertNotEqual(first.confidence.level, second.confidence.level)
        self.assertEqual(returned.assessment_confidence.level, "Undetermined")

    @patch("rag_int.rag_llm_integration.review_code")
    @patch("rag_int.rag_llm_integration.aggregate_cwe_results", return_value=[])
    @patch("rag_int.rag_llm_integration.semantic_search", return_value=[
        candidate(cwe) for cwe in ("CWE-22", "CWE-78", "CWE-79", "CWE-798", "CWE-89")
    ])
    def test_all_five_supported_cwes_serialize(self, semantic, aggregate, review):
        cwes = ("CWE-22", "CWE-78", "CWE-79", "CWE-798", "CWE-89")
        review.return_value = llm_review([llm_vulnerability(cwe) for cwe in cwes])
        result = rag_llm_integration.review_code_with_rag(SOURCE)
        self.assertEqual([item.cwe for item in result.vulnerabilities], list(cwes))
        self.assertTrue(all(item.confidence.level in {"High", "Medium", "Low", "Undetermined"}
                            for item in result.vulnerabilities))

    @patch("rag_int.rag_llm_integration.review_code")
    @patch("rag_int.rag_llm_integration.aggregate_cwe_results")
    @patch("rag_int.rag_llm_integration.semantic_search", return_value=[
        candidate("CWE-89", .4), candidate("CWE-78", .9),
    ])
    def test_legacy_ranking_is_default_and_shadow_ranking_is_flagged(
        self, semantic, aggregate, review,
    ):
        aggregate.return_value = [
            retrieved_result("CWE-89", "SQL Injection"),
            retrieved_result("CWE-78", "OS Command Injection"),
        ]
        review.return_value = llm_review()
        with patch.object(rag_llm_integration, "USE_SHADOW_RANKING", False):
            rag_llm_integration.review_code_with_rag(SOURCE)
            self.assertEqual(rag_llm_integration.LAST_RAG_STATS["selected_candidate_order"],
                             ["CWE-89", "CWE-78"])
            self.assertEqual(rag_llm_integration.LAST_RAG_STATS["legacy_candidate_order"],
                             ["CWE-89", "CWE-78"])

        with patch.object(rag_llm_integration, "USE_SHADOW_RANKING", True):
            rag_llm_integration.review_code_with_rag(SOURCE)
            self.assertEqual(rag_llm_integration.LAST_RAG_STATS["shadow_candidate_order"][0],
                             "CWE-78")
            self.assertEqual(rag_llm_integration.LAST_RAG_STATS["selected_candidate_order"],
                             ["CWE-78", "CWE-89"])

    @patch("rag_int.rag_llm_integration.review_code")
    @patch("rag_int.rag_llm_integration.aggregate_cwe_results", return_value=[])
    @patch("rag_int.rag_llm_integration.semantic_search", return_value=[candidate("CWE-89")])
    def test_retrieval_failure_propagates_without_fabricating_confidence(
        self, semantic, aggregate, review,
    ):
        aggregate.side_effect = RuntimeError("private retrieval details")
        with self.assertRaisesRegex(RuntimeError, "private retrieval details"):
            rag_llm_integration.review_code_with_rag(SOURCE)
        review.assert_not_called()

    @patch("rag_int.rag_llm_integration.score_assessment_confidence",
           side_effect=RuntimeError("confidence engine failed"))
    @patch("rag_int.rag_llm_integration.review_code", return_value=llm_review())
    @patch("rag_int.rag_llm_integration.aggregate_cwe_results", return_value=[])
    @patch("rag_int.rag_llm_integration.semantic_search", return_value=[])
    def test_confidence_failure_propagates(self, semantic, aggregate, review, scorer):
        with self.assertRaisesRegex(RuntimeError, "confidence engine failed"):
            rag_llm_integration.review_code_with_rag("value = 1")

    def test_mismatched_context_is_rejected(self):
        from rag.analysis.ast_context import extract_code_context
        context = extract_code_context("value = 1")
        with self.assertRaisesRegex(ValueError, "does not match"):
            rag_llm_integration.review_code_with_rag("other = 2", context=context)

    def test_formatter_keeps_two_legacy_results_and_adds_location_evidence(self):
        context = rag_llm_integration.format_rag_context(
            [retrieved_result("CWE-89", "SQL Injection"),
             retrieved_result("CWE-78", "OS Command Injection"),
             retrieved_result("CWE-79", "XSS")],
            rag_llm_integration.match_context(
                __import__("rag.analysis.ast_context", fromlist=["extract_code_context"])
                .extract_code_context(SOURCE)
            ),
        )
        self.assertIn("CWE: CWE-89 - SQL Injection", context)
        self.assertIn("CWE: CWE-78 - OS Command Injection", context)
        self.assertNotIn("CWE: CWE-79 - XSS", context)
        self.assertIn("line 3", context)


if __name__ == "__main__":
    unittest.main()
