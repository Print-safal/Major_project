from rag.retrieval.hybrid_retriever import hybrid_search


TEST_CASES = [
    {
        "name": "SQL Injection",
        "expected": "CWE-89",
        "code": """
from flask import request

username = request.args.get("username")

query = "SELECT * FROM users WHERE username = '" + username + "'"

cursor.execute(query)
"""
    },
    {
        "name": "OS Command Injection",
        "expected": "CWE-78",
        "code": """
from flask import request
import os

filename = request.args.get("filename")

os.system("cat " + filename)
"""
    },
    {
        "name": "XSS",
        "expected": "CWE-79",
        "code": """
from flask import request
from flask import Response

name = request.args.get("name")

return Response(
    "<html><body>Hello " + name + "</body></html>",
    mimetype="text/html"
)
"""
    },
    {
        "name": "Path Traversal",
        "expected": "CWE-22",
        "code": """
from flask import request

filename = request.args.get("file")

with open("/var/www/files/" + filename, "r") as f:
    content = f.read()
"""
    },
    {
        "name": "Hard-coded Credentials",
        "expected": "CWE-798",
        "code": """
API_KEY = "sk-example-secret-key"

DATABASE_PASSWORD = "admin123"

client = SomeClient(api_key=API_KEY)
"""
    }
]


print("=" * 70)
print("HYBRID RAG CODE RETRIEVAL TEST")
print("=" * 70)

correct = 0

for case in TEST_CASES:

    print("\n" + "=" * 70)
    print(f"TEST: {case['name']}")
    print(f"EXPECTED: {case['expected']}")
    print("=" * 70)

    results = hybrid_search(
        case["code"],
        top_k=5
    )

    for rank, result in enumerate(
        results,
        start=1
    ):
        print(
            f"Rank {rank}: "
            f"{result['cwe_id']} | "
            f"semantic={result['semantic_score']:.4f} | "
            f"security={result['security_score']:.4f} | "
            f"combined={result['combined_score']:.4f} | "
            f"section={result['section']}"
        )

    if results:

        top_cwe = results[0]["cwe_id"]

        if top_cwe == case["expected"]:
            print("RESULT: CORRECT")
            correct += 1
        else:
            print(
                f"RESULT: INCORRECT "
                f"(got {top_cwe})"
            )

    else:
        print("RESULT: NO RESULTS")


print("\n" + "=" * 70)
print(
    f"HYBRID TOP-1 RESULT: "
    f"{correct}/{len(TEST_CASES)} correct"
)
print("=" * 70)