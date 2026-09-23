from rag.retrieval.security_profiles import calculate_security_signal


tests = [
    (
        "SQL",
        "query = \"SELECT * FROM users WHERE name = '\" + username; cursor.execute(query)",
        "CWE-89"
    ),
    (
        "CMD",
        "os.system(\"cat \" + filename)",
        "CWE-78"
    ),
    (
        "XSS",
        "return Response(\"<html>\" + name)",
        "CWE-79"
    ),
    (
        "PATH",
        "open(\"/files/\" + filename)",
        "CWE-22"
    ),
    (
        "CREDS",
        "API_KEY = \"secret123\"",
        "CWE-798"
    ),
]


print("=" * 60)
print("SECURITY PROFILE TEST")
print("=" * 60)

for name, code, cwe in tests:

    score = calculate_security_signal(
        code,
        cwe
    )

    print(
        f"{name}: {cwe} -> {score:.4f}"
    )

print("=" * 60)