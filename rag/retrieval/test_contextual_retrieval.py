import sys
import types
import unittest
from unittest.mock import patch

from rag.analysis.ast_context import extract_code_context
from rag.retrieval.contextual_retrieval import build_shadow_retrieval, match_context


class ContextualMatchingTests(unittest.TestCase):
    def test_all_supported_cwes_have_context_matches(self):
        code = '''
import os, subprocess, html
from flask import request
from pathlib import Path
def review(conn, user):
    raw = request.args.get("input")
    query = f"SELECT * FROM users WHERE name='{raw}'"
    conn.execute(query)
    subprocess.run("echo " + raw, shell=True)
    open("/tmp/" + raw)
    return html.escape(raw)
API_KEY = "placeholder-example"
'''
        matches = match_context(extract_code_context(code))
        cwes = {m.cwe_id for m in matches}
        self.assertEqual(cwes, {"CWE-22", "CWE-78", "CWE-79", "CWE-798", "CWE-89"})
        self.assertTrue(all(m.certainty == "syntactic_indicator" for m in matches))
        self.assertTrue(all(m.explanation for m in matches))

    def test_secure_and_vulnerable_indicators_remain_separate(self):
        code = '''
import subprocess
import html
def f(conn, user, args):
    conn.execute("SELECT * FROM users WHERE id = ?", (user,))
    subprocess.run(args, shell=False)
    html.escape(user)
    return "<b>" + user + "</b>"
'''
        matches = match_context(extract_code_context(code))
        pairs = {(m.cwe_id, m.indicator_type) for m in matches}
        self.assertIn(("CWE-89", "secure"), pairs)
        self.assertIn(("CWE-89", "vulnerable"), pairs)
        self.assertIn(("CWE-78", "secure"), pairs)
        self.assertIn(("CWE-79", "secure"), pairs)
        self.assertIn(("CWE-79", "vulnerable"), pairs)

    def test_ambiguous_and_missing_context_are_supported(self):
        ambiguous = match_context(extract_code_context("def f(value):\n    return value\n"))
        missing = match_context(extract_code_context(""))
        self.assertEqual(ambiguous, [])
        self.assertEqual(missing, [])

    def test_invalid_source_returns_no_matches(self):
        matches = match_context(extract_code_context("def broken(:"))
        self.assertEqual(matches, [])

    def test_source_sink_flow_is_contextual_candidate_not_proof(self):
        context = extract_code_context('''
def lookup(conn, user):
    query = f"SELECT * FROM users WHERE id={user}"
    conn.execute(query)
''')
        matches = match_context(context)
        candidate = next(m for m in matches if m.provenance == "ast.source_to_sink_candidate")
        self.assertEqual(candidate.indicator_type, "contextual")
        self.assertIn("unverified", candidate.explanation)


class ShadowRetrievalTests(unittest.TestCase):
    def test_shadow_results_preserve_provenance_locations_and_multiple_cwes(self):
        code = '''
def f(conn, user):
    query = f"SELECT * FROM users WHERE name='{user}'"
    conn.execute(query)
    os.system("echo " + user)
'''
        candidates = [
            {"cwe_id": "CWE-89", "semantic_score": 0.73, "source": "CWE-89.json",
             "section": "description", "text": "SQL reference text"},
            {"cwe_id": "CWE-78", "semantic_score": 0.64, "source": "CWE-78.json",
             "section": "detection", "text": "Command reference text"},
        ]
        results = build_shadow_retrieval(code, semantic_candidates=candidates)
        by_cwe = {r.cwe_id: r for r in results}
        self.assertEqual(by_cwe["CWE-89"].semantic_max_score, 0.73)
        self.assertEqual(by_cwe["CWE-78"].semantic_candidate_count, 1)
        semantic = next(e for e in by_cwe["CWE-89"].evidence if e.kind == "semantic")
        self.assertTrue(semantic.provenance.startswith("faiss:CWE-89.json#description"))
        self.assertIn("not proof", semantic.explanation)
        contextual = [e for e in by_cwe["CWE-89"].evidence if e.kind == "contextual"]
        self.assertTrue(contextual)
        self.assertIsNotNone(contextual[0].location)
        self.assertGreater(by_cwe["CWE-89"].vulnerable_match_count, 0)

    def test_duplicate_candidates_are_deduplicated(self):
        candidate = {"cwe_id": "CWE-89", "semantic_score": 0.8,
                     "source": "CWE-89.json", "section": "x", "text": "same"}
        results = build_shadow_retrieval("", semantic_candidates=[candidate, candidate])
        result = next(r for r in results if r.cwe_id == "CWE-89")
        self.assertEqual(sum(e.kind == "semantic" for e in result.evidence), 1)
        self.assertEqual(result.semantic_candidate_count, 2)

    def test_empty_contextual_evidence_does_not_remove_semantic_candidate(self):
        candidate = {"cwe_id": "CWE-89", "semantic_score": 0.4,
                     "source": "CWE-89.json", "section": "x", "text": "SQL docs"}
        results = build_shadow_retrieval("value = 1", semantic_candidates=[candidate])
        result = next(r for r in results if r.cwe_id == "CWE-89")
        self.assertEqual(result.contextual_match_count, 0)
        self.assertEqual(result.semantic_candidate_count, 1)

    def test_existing_semantic_search_interface_is_called_when_candidates_omitted(self):
        fake = types.ModuleType("rag.retrieval.hybrid_retriever")
        fake.semantic_search = unittest.mock.Mock(return_value=[{
            "cwe_id": "CWE-89", "semantic_score": 0.55,
            "source": "CWE-89.json", "section": "description", "text": "reference",
        }])
        with patch.dict(sys.modules, {"rag.retrieval.hybrid_retriever": fake}):
            results = build_shadow_retrieval("x = 1", query="SQL query")
        fake.semantic_search.assert_called_once_with("SQL query", top_k=20)
        self.assertEqual(next(r for r in results if r.cwe_id == "CWE-89").semantic_max_score, 0.55)


if __name__ == "__main__":
    unittest.main()
