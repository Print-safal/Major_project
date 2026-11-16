import unittest

from rag.analysis.ast_context import extract_code_context


class AstContextTests(unittest.TestCase):
    def test_extracts_all_five_cwe_categories(self):
        code = '''
from flask import request
import os
import subprocess
from pathlib import Path
from markupsafe import Markup
import sqlite3

def review():
    user = request.args.get("u")
    query = f"SELECT * FROM users WHERE name = '{user}'"
    cursor.execute(query)
    os.system("echo " + user)
    Path(user).read_text()
    return Markup("<b>" + user + "</b>")

API_KEY = "inert-placeholder"
'''
        context = extract_code_context(code)
        self.assertIsNone(context.parse_error)
        cwes = {cwe for call in context.sinks for cwe in call.cwe_categories}
        cwes.update(c for assignment in context.assignments for c in assignment.cwe_categories)
        self.assertEqual(cwes, {"CWE-22", "CWE-78", "CWE-79", "CWE-89", "CWE-798"})
        self.assertTrue(any(f.sink == "cursor.execute" for f in context.flows))
        self.assertTrue(any(f.sink == "os.system" for f in context.flows))

    def test_multiple_and_nested_functions_have_lexical_scopes_and_ranges(self):
        context = extract_code_context('''
def outer(first, *, flag=False):
    def inner(second):
        return input(second)
    return inner(first)

def another(value):
    return value
''')
        self.assertEqual([f.name for f in context.functions], ["outer", "inner", "another"])
        self.assertEqual(context.functions[0].parameters, ("first", "flag"))
        self.assertEqual(context.functions[1].qualified_name, "outer.inner")
        self.assertEqual(context.functions[1].scope, "<module>.outer")
        self.assertGreaterEqual(context.functions[0].line_end, context.functions[1].line_end)

    def test_imports_aliases_and_normalized_dotted_calls(self):
        context = extract_code_context('''
import subprocess as sp
from os import system as run_cmd
from pathlib import Path as P
def f(x):
    sp.run(["echo", x], shell=False)
    run_cmd(x)
    P(x).read_text()
''')
        self.assertEqual(context.imports[0].aliases, (("subprocess", "sp"),))
        self.assertEqual(context.imports[1].module, "os")
        self.assertIn("sp.run", {c.call_name for c in context.calls})
        self.assertIn("run_cmd", {c.call_name for c in context.calls})
        self.assertTrue(any("subprocess shell=False" in c.safeguards for c in context.safeguards))
        self.assertTrue(any("CWE-78" in c.cwe_categories for c in context.sinks))

    def test_multiline_expression_and_locations_are_preserved(self):
        context = extract_code_context('''
def f(value):
    query = (
        "SELECT * FROM users WHERE id = "
        + value
    )
    cursor.execute(
        query
    )
''')
        assignment = context.assignments[0]
        call = next(c for c in context.calls if c.call_name == "cursor.execute")
        self.assertEqual(assignment.span.line_start, 3)
        self.assertGreater(assignment.span.line_end, assignment.span.line_start)
        self.assertEqual(call.span.line_start, 7)
        self.assertEqual(call.span.line_end, 9)
        self.assertIn("value", assignment.identifiers)

    def test_direct_and_indirect_source_to_sink_relationships(self):
        context = extract_code_context('''
from flask import request
def f():
    raw = request.args.get("name")
    copied = raw
    cursor.execute("SELECT " + copied)
    os.system(request.args.get("cmd"))
''')
        self.assertEqual(len(context.flows), 2)
        sql_flow = next(flow for flow in context.flows if flow.sink == "cursor.execute")
        self.assertEqual(sql_flow.variables, ("copied",))
        self.assertFalse(sql_flow.complete)
        self.assertIn("unverified", sql_flow.uncertainty)
        direct_flow = next(flow for flow in context.flows if flow.sink == "os.system")
        self.assertTrue(direct_flow.source.startswith("request.args.get"))

    def test_safeguards_and_conflicting_indicators_are_both_retained(self):
        context = extract_code_context('''
import html
import subprocess
def f(user, args, conn):
    conn.execute("SELECT * FROM users WHERE id = ?", (user,))
    safe = html.escape(user)
    subprocess.run(args, shell=False)
    subprocess.run("echo " + user, shell=True)
''')
        safeguard_names = {s for call in context.safeguards for s in call.safeguards}
        self.assertIn("parameterized SQL arguments present", safeguard_names)
        self.assertIn("html escaping", safeguard_names)
        self.assertIn("subprocess shell=False", safeguard_names)
        self.assertTrue(any("CWE-78" in call.cwe_categories for call in context.sinks))
        self.assertTrue(any("subprocess shell=False" in call.safeguards for call in context.calls))

    def test_hardcoded_credential_candidate_is_assignment_evidence(self):
        context = extract_code_context('API_KEY = "example-only-value"')
        assignment = context.assignments[0]
        self.assertEqual(assignment.cwe_categories, ("CWE-798",))
        self.assertEqual(assignment.indicator, "credential-like literal assignment")

    def test_empty_source(self):
        context = extract_code_context("")
        self.assertIsNone(context.parse_error)
        self.assertEqual(context.functions, ())
        self.assertEqual(context.flows, ())

    def test_syntax_error_is_returned_as_diagnostic(self):
        context = extract_code_context("def broken(:\n    pass\n")
        self.assertIsNotNone(context.parse_error)
        self.assertEqual(context.parse_error.line, 1)
        self.assertEqual(context.functions, ())


if __name__ == "__main__":
    unittest.main()
