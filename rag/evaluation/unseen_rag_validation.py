
from rag.retrieval.cwe_aggregator import aggregate_cwe_results


TEST_CASES = [
    # CWE-89: SQL Injection
    ("U89_01", "CWE-89",
     '''query = "SELECT * FROM users WHERE id = " + user_id
cursor.execute(query)'''),

    ("U89_02", "CWE-89",
     '''query = f"SELECT * FROM accounts WHERE name='{name}'"
conn.execute(query)'''),

    ("U89_03", "CWE-89",
     '''sql = "DELETE FROM users WHERE id = '%s'" % user_id
cursor.execute(sql)'''),

    # CWE-78: OS Command Injection
    ("U78_01", "CWE-78",
     '''import os
os.system("ping " + hostname)'''),

    ("U78_02", "CWE-78",
     '''import subprocess
subprocess.run("cat " + filename, shell=True)'''),

    ("U78_03", "CWE-78",
     '''import os
os.popen("grep " + search_term + " data.txt")'''),

    # CWE-79: XSS
    ("U79_01", "CWE-79",
     '''return "<p>" + request.args.get("name") + "</p>"'''),

    ("U79_02", "CWE-79",
     '''response = "<div>" + username + "</div>"
return response'''),

    ("U79_03", "CWE-79",
     '''element.innerHTML = user_input'''),

    # CWE-22: Path Traversal
    ("U22_01", "CWE-22",
     '''path = "/data/" + filename
open(path, "r")'''),

    ("U22_02", "CWE-22",
     '''from pathlib import Path
file_path = Path("/uploads") / user_filename
file_path.read_text()'''),

    ("U22_03", "CWE-22",
     '''import os
path = os.path.join("/var/data", request.args.get("file"))
open(path, "rb")'''),

    # CWE-798: Hard-coded Credentials
    ("U798_01", "CWE-798",
     '''DATABASE_PASSWORD = "admin123"'''),

    ("U798_02", "CWE-798",
     '''API_KEY = "TEST_SECRET_KEY_123456"'''),

    ("U798_03", "CWE-798",
     '''PRIVATE_KEY = "dummy-private-key-value"'''),

    # Safe examples
    ("SAFE_U01", None,
     '''query = "SELECT * FROM users WHERE id = ?"
conn.execute(query, (user_id,))'''),

    ("SAFE_U02", None,
     '''import subprocess
subprocess.run(["ping", hostname], shell=False, check=True)'''),

    ("SAFE_U03", None,
     '''import html
return "<p>" + html.escape(username) + "</p>"'''),

    ("SAFE_U04", None,
     '''allowed = {"report.pdf", "summary.pdf"}
if filename not in allowed:
    raise ValueError("Invalid filename")
open("/reports/" + filename, "rb")'''),

    ("SAFE_U05", None,
     '''import os
password = os.environ.get("DATABASE_PASSWORD")'''),

    ("SAFE_U06", None,
     '''from flask import render_template
return render_template("profile.html", name=username)'''),

    ("SAFE_U07", None,
     '''from pathlib import Path
base = Path("/data").resolve()
target = (base / filename).resolve()
if target.is_relative_to(base):
    target.read_text()'''),

    ("SAFE_U08", None,
     '''import subprocess
subprocess.run(["ls", "-l"], check=True)'''),

    ("SAFE_U09", None,
     '''import html
safe_name = html.escape(name)
return f"<h1>{safe_name}</h1>"'''),

    ("SAFE_U10", None,
     '''query = "INSERT INTO users(name) VALUES (?)"
cursor.execute(query, (username,))'''),
]


def main():
    total = len(TEST_CASES)
    vulnerable_total = 0
    vulnerable_correct = 0
    safe_total = 0
    safe_false_positives = 0

    print("=" * 75)
    print("SUPPLEMENTAL UNSEEN RAG VALIDATION")
    print("=" * 75)
    print("Total cases:", total)

    for test_id, expected, code in TEST_CASES:
        results = aggregate_cwe_results(
            code,
            candidate_k=30,
            top_k=5
        )

        predicted = (
            results[0]["cwe_id"]
            if results else None
        )
        if results:
            print("TOP RESULT DETAILS:", results[0])

        if expected is None:
            safe_total += 1
            passed = predicted is None

            if not passed:
                safe_false_positives += 1
        else:
            vulnerable_total += 1
            passed = predicted == expected

            if passed:
                vulnerable_correct += 1

        status = "PASS" if passed else "FAIL"

        print(
            f"{test_id:12} "
            f"Expected={str(expected):10} "
            f"Predicted={str(predicted):10} "
            f"{status}"
        )

    print("\n" + "=" * 75)
    print("SUPPLEMENTAL RESULTS")
    print("=" * 75)

    print(
        f"Vulnerable Top-1 accuracy: "
        f"{vulnerable_correct}/{vulnerable_total} "
        f"({vulnerable_correct / vulnerable_total * 100:.2f}%)"
    )

    print(
        f"Safe-code false positives: "
        f"{safe_false_positives}/{safe_total} "
        f"({safe_false_positives / safe_total * 100:.2f}%)"
    )

    print("=" * 75)


if __name__ == "__main__":
    main()
