import unittest

from rag.retrieval.contextual_retrieval import EvidenceItem
from rag_int.confidence import (
    AssessmentConfidence,
    ConfidenceComponent,
    ConfidenceThresholds,
    ConfidenceWeights,
    FindingConfidence,
    ReviewCoverage,
    score_assessment_confidence,
    score_finding_confidence,
)


def evidence(cwe, kind, text, provenance, score=None):
    return EvidenceItem(cwe, kind, text, provenance, score=score,
                        explanation="synthetic test evidence")


def finding(cwe="CWE-89", location="line 4"):
    return {"cwe": cwe, "location": location}


class ConfidenceComponentTests(unittest.TestCase):
    def test_component_and_result_boundaries(self):
        component = ConfidenceComponent("test", 0, 1, "valid boundary")
        self.assertEqual(component.score, 0)
        self.assertEqual(component.level, "Low")
        with self.assertRaises(ValueError):
            ConfidenceComponent("test", 100.01, 1, "invalid")
        with self.assertRaises(ValueError):
            ConfidenceWeights(semantic_relevance=0, cwe_agreement=0,
                contextual_indicators=0, source_to_sink=0, safeguards=0,
                llm_consistency=0)
        with self.assertRaises(ValueError):
            ConfidenceThresholds(high=40, medium=50)
        with self.assertRaises(ValueError):
            FindingConfidence("CWE-89", "line 1", None, "High", (), (), (), "invalid")
        self.assertEqual(AssessmentConfidence(False, 100, "High", (), (), (), (), "ok").score, 100)


class FindingConfidenceTests(unittest.TestCase):
    def test_strong_evidence_produces_high_confidence(self):
        items = [
            evidence("CWE-89", "semantic", "SQL reference", "faiss:CWE-89#vuln", .92),
            evidence("CWE-89", "vulnerable", "dynamic SQL indicator", "security_profiles.patterns"),
            evidence("CWE-89", "contextual", "conn.execute", "ast.call"),
            evidence("CWE-89", "contextual", "parameter:user → conn.execute",
                     "ast.source_to_sink_candidate"),
        ]
        result = score_finding_confidence(finding(), items)
        self.assertEqual(result.level, "High")
        self.assertGreaterEqual(result.score, 75)
        self.assertEqual({c.name for c in result.components}, {
            "semantic_relevance", "cwe_agreement", "contextual_indicators",
            "source_to_sink", "safeguards", "llm_consistency",
        })
        self.assertIn("not a probability", result.explanation)

    def test_semantic_only_is_not_sufficient_or_proof(self):
        result = score_finding_confidence(finding(), [
            evidence("CWE-89", "semantic", "CWE document", "faiss:CWE-89#desc", .99),
        ])
        self.assertIsNone(result.score)
        self.assertEqual(result.level, "Undetermined")

    def test_potential_flow_has_limited_weight_and_is_not_confirmed(self):
        items = [
            evidence("CWE-78", "contextual", "subprocess.run", "ast.call"),
            evidence("CWE-78", "contextual", "parameter:cmd → subprocess.run",
                     "ast.source_to_sink_candidate"),
        ]
        result = score_finding_confidence(finding("CWE-78"), items)
        flow = next(c for c in result.components if c.name == "source_to_sink")
        self.assertEqual(flow.score, 55)
        self.assertEqual(result.level, "Medium")
        self.assertIn("unverified", result.explanation)

    def test_conflicting_secure_indicator_is_kept_and_reduces_score(self):
        vulnerable = evidence("CWE-89", "vulnerable", "execute pattern", "profile:vuln")
        flow = evidence("CWE-89", "contextual", "param → execute", "ast.source_to_sink_candidate")
        secure = evidence("CWE-89", "secure", "parameterized SQL", "ast.safeguard")
        without_conflict = score_finding_confidence(finding(), [vulnerable, flow])
        with_conflict = score_finding_confidence(finding(), [vulnerable, flow, secure])
        self.assertEqual(with_conflict.conflicting_evidence, (secure,))
        self.assertLess(with_conflict.score, without_conflict.score)

    def test_duplicate_evidence_does_not_change_score(self):
        items = [
            evidence("CWE-89", "vulnerable", "dynamic query", "profile:vuln"),
            evidence("CWE-89", "contextual", "execute call", "ast.call"),
        ]
        once = score_finding_confidence(finding(), items)
        twice = score_finding_confidence(finding(), items + items)
        self.assertEqual(once.score, twice.score)
        self.assertEqual(once.supporting_evidence, twice.supporting_evidence)

    def test_missing_evidence_and_weak_evidence(self):
        missing = score_finding_confidence(finding(), [])
        weak = score_finding_confidence(finding(), [
            evidence("CWE-89", "contextual", "execute", "ast.call"),
        ])
        self.assertIsNone(missing.score)
        self.assertIsNone(weak.score)

    def test_invalid_inputs_are_rejected(self):
        with self.assertRaises(ValueError):
            score_finding_confidence(finding("CWE-999"), [])
        with self.assertRaises(TypeError):
            score_finding_confidence(finding(), [object()])
        with self.assertRaises(ValueError):
            score_finding_confidence(finding(), [
                evidence("CWE-89", "semantic", "bad score", "faiss", 1.5),
            ])
        with self.assertRaises(ValueError):
            score_finding_confidence(finding(), [], weights=ConfidenceWeights(
                semantic_relevance=5, cwe_agreement=10, contextual_indicators=20,
                source_to_sink=20, safeguards=15, llm_consistency=25,
            ))


class AssessmentConfidenceTests(unittest.TestCase):
    def test_overall_vulnerable_review_accounts_for_each_finding(self):
        review = {"vulnerable": True, "vulnerabilities": [
            finding("CWE-89", "line 1"), finding("CWE-78", "line 8")
        ]}
        items = [
            evidence("CWE-89", "vulnerable", "SQL construction", "profile:vuln"),
            evidence("CWE-89", "contextual", "user → execute", "ast.source_to_sink_candidate"),
            evidence("CWE-78", "secure", "shell=False", "ast.safeguard"),
        ]
        result = score_assessment_confidence(review, items)
        self.assertEqual(len(result.finding_confidences), 2)
        self.assertLess(result.score, result.finding_confidences[0].score)
        self.assertIn("weakest finding", result.explanation)

    def test_safe_review_requires_explicit_complete_coverage(self):
        review = {"vulnerable": False, "vulnerabilities": []}
        items = [evidence(cwe, "semantic", "reference", f"faiss:{cwe}", .7)
                 for cwe in ("CWE-22", "CWE-78", "CWE-79", "CWE-798", "CWE-89")]
        result = score_assessment_confidence(review, items)
        self.assertIsNone(result.score)
        self.assertEqual(result.level, "Undetermined")

    def test_safe_review_with_full_coverage_gets_deterministic_assessment(self):
        review = {"vulnerable": False, "vulnerabilities": []}
        cwes = ("CWE-22", "CWE-78", "CWE-79", "CWE-798", "CWE-89")
        items = [evidence(cwe, "semantic", "reference", f"faiss:{cwe}", .65)
                 for cwe in cwes]
        items.append(evidence("CWE-89", "secure", "parameterized SQL", "ast.safeguard"))
        coverage = ReviewCoverage(cwes, True, True, True)
        first = score_assessment_confidence(review, items, coverage=coverage)
        second = score_assessment_confidence(review, items, coverage=coverage)
        self.assertEqual(first, second)
        self.assertEqual(first.level, "High")
        self.assertGreaterEqual(first.score, 75)

    def test_safe_review_with_vulnerable_indicator_is_undetermined(self):
        cwes = ("CWE-22", "CWE-78", "CWE-79", "CWE-798", "CWE-89")
        review = {"vulnerable": False, "vulnerabilities": []}
        coverage = ReviewCoverage(cwes, True, True, True)
        result = score_assessment_confidence(review, [
            evidence("CWE-89", "vulnerable", "dynamic SQL", "profile:vuln"),
        ], coverage=coverage)
        self.assertIsNone(result.score)
        self.assertTrue(result.conflicting_evidence)

    def test_review_consistency_and_coverage_inputs_are_validated(self):
        with self.assertRaises(ValueError):
            score_assessment_confidence({"vulnerable": False, "vulnerabilities": [finding()]}, [])
        with self.assertRaises(ValueError):
            score_assessment_confidence({"vulnerable": False, "vulnerabilities": []}, [],
                coverage=ReviewCoverage(("CWE-999",), True, True, True))
        with self.assertRaises(TypeError):
            score_assessment_confidence({"vulnerable": False, "vulnerabilities": []}, [],
                coverage={})


if __name__ == "__main__":
    unittest.main()
