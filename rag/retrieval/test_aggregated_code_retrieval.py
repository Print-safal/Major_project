from rag.retrieval.cwe_aggregator import aggregate_cwe_results


TEST_CASES = [
    {
        "name": "SQL Injection",
        "expected": "CWE-89",
        "code": '''
from flask import request
import sqlite3

@app.route("/user")
def get_user():
    username = request.args.get("username")

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    query = "SELECT * FROM users WHERE username='" + username + "'"
    cursor.execute(query)

    return str(cursor.fetchone())
'''
    },
    {
        "name": "OS Command Injection",
        "expected": "CWE-78",
        "code": '''
from flask import request
import os

@app.route("/ping")
def ping():
    hostname = request.args.get("host")
    command = "ping " + hostname
    os.system(command)

    return "Done"
'''
    },
    {
        "name": "Cross-Site Scripting",
        "expected": "CWE-79",
        "code": '''
from flask import request

@app.route("/search")
def search():
    query = request.args.get("q", "")
    return "<h1>Search results for: " + query + "</h1>"
'''
    },
    {
        "name": "Path Traversal",
        "expected": "CWE-22",
        "code": '''
from flask import request

@app.route("/download")
def download():
    filename = request.args.get("file")

    with open("/var/www/files/" + filename, "r") as f:
        content = f.read()

    return content
'''
    },
    {
        "name": "Hard-coded Credentials",
        "expected": "CWE-798",
        "code": '''
import mysql.connector

connection = mysql.connector.connect(
    host="db.example.com",
    user="admin",
    password="admin123"
)
'''
    },
]


def main():
    print("=" * 70)
    print("AGGREGATED CWE CODE RETRIEVAL TEST")
    print("=" * 70)

    correct = 0

    for test_case in TEST_CASES:

        print("\n" + "-" * 70)
        print(f"Test: {test_case['name']}")
        print(f"Expected: {test_case['expected']}")

        results = aggregate_cwe_results(
            test_case["code"],
            candidate_k=30,
            top_k=5
        )

        if not results:
            print("Result: NO RESULTS")
            continue

        top_result = results[0]

        print(
            f"Retrieved: "
            f"{top_result['cwe_id']} - "
            f"{top_result['cwe_name']}"
        )

        print(
            f"Score: "
            f"{top_result['score']:.4f}"
        )

        print(
            f"Security signal: "
            f"{top_result['security_score']:.4f}"
        )

        print(
            f"Vulnerability evidence: "
            f"{top_result['vulnerable_evidence_count']}"
        )

        print("\nTop 3 supporting evidence:")

        for chunk in top_result[
            "supporting_chunks"
        ][:3]:

            print(
                f"  - {chunk['section']} "
                f"(score="
                f"{chunk['combined_score']:.4f})"
            )

        if top_result["cwe_id"] == test_case["expected"]:
            print("PASS")
            correct += 1
        else:
            print("FAIL")

    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)

    total = len(TEST_CASES)

    print(
        f"Top-1: {correct}/{total}"
    )

    print(
        f"Top-1 accuracy on this diagnostic "
        f"set: {correct / total:.2%}"
    )


if __name__ == "__main__":
    main()