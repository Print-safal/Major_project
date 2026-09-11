from rag.retrieval.rag_retriever import retrieve_security_context
from rag_int.llm_service import review_code


TEST_CASES = [
    {
        "name": "CWE-89 SQL Injection",
        "expected": "CWE-89",
        "code": """
import sqlite3

user_id = input("Enter user ID: ")

connection = sqlite3.connect("users.db")
cursor = connection.cursor()

query = "SELECT * FROM users WHERE id = " + user_id
cursor.execute(query)

print(cursor.fetchall())
"""
    },
    {
        "name": "CWE-78 OS Command Injection",
        "expected": "CWE-78",
        "code": """
import os

user_input = input("Enter command: ")
os.system(user_input)
"""
    },
    {
        "name": "CWE-79 Cross-Site Scripting",
        "expected": "CWE-79",
        "code": """
from flask import Flask, request

app = Flask(__name__)

@app.route("/")
def index():
    name = request.args.get("name")
    return "<h1>Hello " + name + "</h1>"
"""
    },
    {
        "name": "CWE-22 Path Traversal",
        "expected": "CWE-22",
        "code": """
from flask import Flask, request

app = Flask(__name__)

@app.route("/download")
def download():
    filename = request.args.get("file")
    with open("/var/www/files/" + filename, "r") as f:
        return f.read()
"""
    },
    {
        "name": "CWE-798 Hard-coded Credentials",
        "expected": "CWE-798",
        "code": """
import sqlite3

DB_PASSWORD = "SuperSecret123"

connection = sqlite3.connect("users.db")
"""
    },
]


def main():
    passed = 0
    failed = 0

    print("=" * 70)
    print("RAG + LLM INTEGRATION TEST")
    print("=" * 70)
    print("Testing all 5 CWE categories")
    print()

    for number, case in enumerate(TEST_CASES, start=1):

        print("=" * 70)
        print(f"TEST {number}: {case['name']}")
        print(f"Expected CWE: {case['expected']}")
        print("=" * 70)

        try:
            # Step 1: Retrieve relevant CWE knowledge using RAG
            retrieved = retrieve_security_context(
                case["code"],
                top_k=5
            )

            # Step 2: Send code + retrieved knowledge to LLM
            review = review_code(
                code=case["code"],
                security_context=retrieved["context"]
            )

            predicted_cwes = [
                vulnerability.cwe
                for vulnerability in review.vulnerabilities
            ]

            print(f"Predicted CWEs: {predicted_cwes}")
            print(f"Vulnerable: {review.vulnerable}")

            if case["expected"] in predicted_cwes:
                print("RESULT: PASS")
                passed += 1
            else:
                print("RESULT: FAIL")
                failed += 1

            for vulnerability in review.vulnerabilities:
                print(
                    f"  {vulnerability.cwe}: "
                    f"{vulnerability.vulnerability_name}"
                )

        except Exception as e:
            print(f"ERROR: {e}")
            print("RESULT: FAIL")
            failed += 1

        print()

    print("=" * 70)
    print("FINAL RESULTS")
    print("=" * 70)
    print(f"Passed: {passed}/5")
    print(f"Failed: {failed}/5")

    if passed == 5:
        print("ALL 5 CWE INTEGRATION TESTS PASSED")
    else:
        print("Some CWE integration tests failed.")

    print("=" * 70)


if __name__ == "__main__":
    main()