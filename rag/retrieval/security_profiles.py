import re


SECURITY_PROFILES = {
    "CWE-89": {
        "name": "SQL Injection",

        "patterns": [
            r"\bexecute\s*\(",
            r"\bexecutemany\s*\(",
            r"\bcursor\s*\.\s*execute\s*\(",
            r"\bSELECT\b",
            r"\bINSERT\b",
            r"\bUPDATE\b",
            r"\bDELETE\b",
            r"\bFROM\b",
            r"\bWHERE\b",
            r"""['"].*\bSELECT\b.*['"]\s*\+""",
            r"""['"].*\bINSERT\b.*['"]\s*\+""",
            r"""['"].*\bUPDATE\b.*['"]\s*\+""",
            r"""['"].*\bDELETE\b.*['"]\s*\+""",
            r"""f['"].*\bSELECT\b""",
            r"""f['"].*\bINSERT\b""",
            r"""f['"].*\bUPDATE\b""",
            r"""f['"].*\bDELETE\b""",
            r"""\.format\s*\(""",
        ],

        "secure_patterns": [
            r"""\b(?:execute|executemany)\s*\(\s*["'][^"']*\?[^"']*["']\s*,""",
        ],

        "keywords": [
            "sql injection",
            "sql",
            "query",
            "execute",
            "executemany",
            "cursor",
            "select",
            "insert",
            "update",
            "delete",
            "where",
            "sqlite3",
            "mysql",
            "postgresql",
            "database",
        ],
    },

    "CWE-78": {
        "name": "OS Command Injection",

        "patterns": [
            r"\bos\.system\s*\(",
            r"\bos\.popen\s*\(",
            r"\bsubprocess\.call\s*\(",
            r"\bsubprocess\.run\s*\(",
            r"\bsubprocess\.Popen\s*\(",
            r"\bsubprocess\.check_output\s*\(",
            r"\bsubprocess\.check_call\s*\(",
            r"\bshell\s*=\s*True\b",
            r"\bshell\s*=\s*False\b",
            r"\beval\s*\(",
            r"\bexec\s*\(",
        ],

        "secure_patterns": [
            r"\bshell\s*=\s*False\b",
        ],

        "keywords": [
            "command injection",
            "os.system",
            "os.popen",
            "subprocess",
            "shell",
            "shell=true",
            "command",
            "system command",
            "exec",
            "eval",
        ],
    },

    "CWE-79": {
        "name": "Cross-Site Scripting (XSS)",

        "patterns": [
            r"\bResponse\s*\(",
            r"\brender_template_string\s*\(",
            r"\bMarkup\s*\(",
            r"\binnerHTML\b",
            r"\bouterHTML\b",
            r"<html",
            r"<script",
            r"<body",
            r"""mimetype\s*=\s*['"]text/html""",

            # Direct user-controlled HTML construction.
            r"""['"]<[^>]+>['"]\s*\+\s*[A-Za-z_]\w*""",
            r"""[A-Za-z_]\w*\s*\+\s*['"]</[^>]+>['"]""",

            # User-controlled data inserted into an HTML attribute.
            r"""data-[A-Za-z-]+\s*=\s*\\?["'].*\+\s*[A-Za-z_]\w*""",

            # Generic HTML attribute construction.
            r"""[A-Za-z-]+\s*=\s*\\?["'].*\+\s*[A-Za-z_]\w*""",
        ],

        "secure_patterns": [
            r"\bhtml\.escape\s*\(",
            r"\bescape\s*\(",
            r"\bsanitize\s*\(",
            r"\bsanitized\b",
        ],

        "keywords": [
            "xss",
            "cross-site scripting",
            "html",
            "html injection",
            "script",
            "innerhtml",
            "outerhtml",
            "render_template_string",
            "markup",
            "response",
            "escape",
            "sanitize",
            "user input",
        ],
    },

    "CWE-22": {
        "name": "Path Traversal",

        "patterns": [
            r"\.\./",
            r"\.\.\\",
            r"\.\.",
            r"\bos\.path\.join\s*\(",
            r"\bos\.path\.abspath\s*\(",
            r"\bos\.path\.realpath\s*\(",
            r"\bopen\s*\(",
            r"\bPath\s*\(",
            r"\.read_text\s*\(",
            r"\.read_bytes\s*\(",
            r"""/\s*\+\s*[A-Za-z_]\w*""",
            r"""['"][^'"]*/['"]\s*\+\s*[A-Za-z_]\w*""",
        ],

        "secure_patterns": [
            r"\bos\.path\.realpath\s*\(",
            r"\.resolve\s*\(",
            r"\bos\.path\.commonpath\s*\(",
            r"\bcommonpath\s*\(",
            r"\.parents\b",
            r"\bcommonpath\s*\([^)]*\)\s*!=\s*",
            r"\bin\s+path\.parents\b",
        ],

        "keywords": [
            "path traversal",
            "directory traversal",
            "../",
            "..\\",
            "filepath",
            "file path",
            "os.path",
            "realpath",
            "abspath",
            "commonpath",
            "pathlib",
            "open file",
        ],
    },

    "CWE-798": {
        "name": "Use of Hard-coded Credentials",

        "patterns": [
            r"\bpassword\s*=\s*['\"]",
            r"\bpasswd\s*=\s*['\"]",
            r"\bapi[_-]?key\s*=\s*['\"]",
            r"\baccess[_-]?token\s*=\s*['\"]",
            r"\bauth[_-]?token\s*=\s*['\"]",
            r"\bsecret\s*=\s*['\"]",
            r"\bsecret[_-]?key\s*=\s*['\"]",
            r"\bcredential[s]?\s*=\s*['\"]",
            r"\busername\s*=\s*['\"]",
            r"\bprivate[_-]?key\s*=\s*['\"]",
            r"\bencryption[_-]?key\s*=\s*['\"]",

            # Cloud/provider-specific credentials.
            r"\bAWS_ACCESS_KEY\s*=\s*['\"]",
            r"\bAWS_ACCESS_KEY_ID\s*=\s*['\"]",
            r"\bAWS_SECRET_ACCESS_KEY\s*=\s*['\"]",
            r"\bAZURE_CLIENT_SECRET\s*=\s*['\"]",
            r"\bGOOGLE_API_KEY\s*=\s*['\"]",

            # Generic credential-like variable names.
            r"\b[A-Z_]*(?:PASSWORD|PASSWD|API_KEY|ACCESS_TOKEN|AUTH_TOKEN|SECRET|SECRET_KEY|PRIVATE_KEY|ENCRYPTION_KEY)\s*=\s*['\"]",
        ],

        "secure_patterns": [],

        "keywords": [
            "CWE-798",
            "hard-coded credentials",
            "hardcoded credentials",
            "hard-coded password",
            "hardcoded password",
            "api key",
            "access token",
            "secret",
            "password",
            "credentials",
            "database credentials",
            "authentication",
            "private key",
            "encryption key",
            "AWS_ACCESS_KEY",
            "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY",
            "environment variable",
            "secret management",
        ],
    },
}


def calculate_security_signal(code, cwe_id):
    """
    Calculate a CWE-specific vulnerability signal between 0 and 1.

    Pattern matches provide stronger evidence than generic keywords.

    For CWE-798, credential-related keywords are only treated
    as meaningful when an actual hard-coded credential assignment
    is present.
    """

    profile = SECURITY_PROFILES[cwe_id]

    pattern_matches = 0
    keyword_matches = 0

    patterns = profile.get("patterns", [])
    keywords = profile.get("keywords", [])

    for pattern in patterns:
        if re.search(pattern, code, re.IGNORECASE):
            pattern_matches += 1

    code_lower = code.lower()

    for keyword in keywords:
        if keyword.lower() in code_lower:
            keyword_matches += 1

    # CWE-798 specifically requires an actual hard-coded
    # credential assignment.
    #
    # Example:
    #     PASSWORD = "secret123"
    #
    # should trigger CWE-798.
    #
    # But:
    #     def login(username, password):
    #
    # should NOT trigger CWE-798 merely because the word
    # "password" appears in the function parameter.
    if cwe_id == "CWE-798":

        hardcoded_patterns = [
    r"(?m)^\s*password\s*=\s*['\"]",
    r"(?m)^\s*passwd\s*=\s*['\"]",
    r"(?m)^\s*api[_-]?key\s*=\s*['\"]",
    r"(?m)^\s*access[_-]?token\s*=\s*['\"]",
    r"(?m)^\s*auth[_-]?token\s*=\s*['\"]",
    r"(?m)^\s*secret\s*=\s*['\"]",
    r"(?m)^\s*secret[_-]?key\s*=\s*['\"]",
    r"(?m)^\s*credential[s]?\s*=\s*['\"]",
    r"(?m)^\s*private[_-]?key\s*=\s*['\"]",
    r"(?m)^\s*encryption[_-]?key\s*=\s*['\"]",
    r"(?m)^\s*AWS_ACCESS_KEY\s*=\s*['\"]",
    r"(?m)^\s*AWS_ACCESS_KEY_ID\s*=\s*['\"]",
    r"(?m)^\s*AWS_SECRET_ACCESS_KEY\s*=\s*['\"]",
    r"(?m)^\s*AZURE_CLIENT_SECRET\s*=\s*['\"]",
    r"(?m)^\s*GOOGLE_API_KEY\s*=\s*['\"]",
]

        hardcoded_match = any(
            re.search(pattern, code, re.IGNORECASE)
            for pattern in hardcoded_patterns
        )

        if not hardcoded_match:
            return 0.0

    pattern_score = (
        min(pattern_matches / 3.0, 1.0)
        if patterns
        else 0.0
    )

    keyword_score = (
        min(keyword_matches / 3.0, 1.0)
        if keywords
        else 0.0
    )

    return min(
        0.7 * pattern_score + 0.3 * keyword_score,
        1.0,
    )


def calculate_secure_signal(code, cwe_id):
    """
    Calculate a security-mitigation signal between 0 and 1.

    A matching secure pattern provides strong evidence that
    the code uses a known mitigation for the given CWE.
    """

    profile = SECURITY_PROFILES[cwe_id]

    secure_patterns = profile.get("secure_patterns", [])

    if not secure_patterns:
        return 0.0

    for pattern in secure_patterns:
        if re.search(pattern, code, re.IGNORECASE):
            return 1.0

    return 0.0


if __name__ == "__main__":
    print("=" * 70)
    print("SECURITY PROFILE TEST")
    print("=" * 70)

    test_cases = {
        "SQL Injection": (
            "query = 'SELECT * FROM users WHERE name = ' + username"
        ),

        "OS Command Injection": (
            "subprocess.run(command, shell=True)"
        ),

        "XSS": (
            'return "<h1>" + username + "</h1>"'
        ),

        "XSS Attribute Injection": (
            'return "<div data-name=\\"" + name + "\\">User</div>"'
        ),

        "Path Traversal": (
            'path = os.path.join("/data", filename)'
        ),

        "Hard-coded Password": (
            'PASSWORD = "secret123"'
        ),

        "AWS Access Key": (
            'AWS_ACCESS_KEY = "TEST_ACCESS_KEY_001"'
        ),

        "Private Key": (
            'PRIVATE_KEY = "TEST_PRIVATE_KEY_001"'
        ),

        "Encryption Key": (
            'ENCRYPTION_KEY = "dummy-encryption-key-001"'
        ),

        "Safe SQL": (
            'conn.execute("SELECT * FROM users WHERE id = ?", (user_id,))'
        ),

        "Safe XSS": (
            'return "<h1>" + html.escape(name) + "</h1>"'
        ),

        "Safe Command": (
            'subprocess.run(args, shell=False, check=True)'
        ),

        "SQL Injection with Password Parameter": (
            '''def login(conn, username, password):
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    return conn.execute(query)'''
        ),
    }

    for name, code in test_cases.items():
        print(f"\n{name}")
        print("-" * 50)

        for cwe_id in SECURITY_PROFILES:
            vulnerable = calculate_security_signal(code, cwe_id)
            secure = calculate_secure_signal(code, cwe_id)

            if vulnerable > 0 or secure > 0:
                print(
                    f"{cwe_id}: "
                    f"vulnerable={vulnerable:.4f}, "
                    f"secure={secure:.4f}"
                )