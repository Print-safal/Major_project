import re


SECURITY_PROFILES = {
    "CWE-89": {
        "name": "SQL Injection",

        "patterns": [
            r"\bSELECT\b",
            r"\bINSERT\b",
            r"\bUPDATE\b",
            r"\bDELETE\b",
            r"\bFROM\b",
            r"\bWHERE\b",
            r"\bSQL\b",
            r"\bquery\b",
            r"\bcursor\.execute\b",
            r"\bexecutemany\b",
            r"\bexecute\(",
            r"f[\"'].*SELECT",
            r"[\"'].*SELECT.*[\"']\s*\+",
        ],

        "apis": [
            "cursor.execute",
            "cursor.executemany",
            "execute",
        ],

        "keywords": [
            "sql",
            "query",
            "select",
            "insert",
            "update",
            "delete",
            "where",
            "database",
        ],
    },

    "CWE-78": {
        "name": "OS Command Injection",

        "patterns": [
            r"\bos\.system\s*\(",
            r"\bos\.popen\s*\(",
            r"\bsubprocess\.run\s*\(",
            r"\bsubprocess\.call\s*\(",
            r"\bsubprocess\.Popen\s*\(",
            r"\bsubprocess\.check_output\s*\(",
            r"\bshell\s*=\s*True\b",
            r"\bcommand\b",
            r"\bos\.system",
        ],

        "apis": [
            "os.system",
            "os.popen",
            "subprocess.run",
            "subprocess.call",
            "subprocess.Popen",
            "subprocess.check_output",
        ],

        "keywords": [
            "command",
            "shell",
            "subprocess",
            "os.system",
            "execute command",
        ],
    },

    "CWE-79": {
        "name": "Cross-Site Scripting",

        "patterns": [
            r"\bResponse\s*\(",
            r"\brender_template_string\s*\(",
            r"\bMarkup\s*\(",
            r"\binnerHTML\b",
            r"\bouterHTML\b",
            r"<html",
            r"<script",
            r"<body",
            r"mimetype\s*=\s*[\"']text/html",
            r"\bhtml\b",
        ],

        "apis": [
            "Response",
            "render_template_string",
            "Markup",
            "innerHTML",
            "outerHTML",
        ],

        "keywords": [
            "html",
            "xss",
            "cross site scripting",
            "browser output",
            "rendered output",
        ],
    },

    "CWE-22": {
        "name": "Path Traversal",

        "patterns": [
            r"\bopen\s*\(",
            r"\bos\.path\.join\s*\(",
            r"\bPath\s*\(",
            r"\.read_text\s*\(",
            r"\.write_text\s*\(",
            r"\.read_bytes\s*\(",
            r"\.write_bytes\s*\(",
            r"\.\./",
            r"\.\.\\",
            r"\bfilename\b",
            r"\bfilepath\b",
            r"\bfile_path\b",
            r"\bpath\b",
        ],

        "apis": [
            "open",
            "os.path.join",
            "Path",
            "read_text",
            "write_text",
        ],

        "keywords": [
            "path",
            "filename",
            "filepath",
            "file path",
            "directory",
            "path traversal",
            "directory traversal",
        ],
    },

    "CWE-798": {
        "name": "Hard-coded Credentials",

        "patterns": [
            r"\bpassword\s*=\s*[\"']",
            r"\bpasswd\s*=\s*[\"']",
            r"\bapi[_-]?key\s*=\s*[\"']",
            r"\bsecret[_-]?key\s*=\s*[\"']",
            r"\bsecret\s*=\s*[\"']",
            r"\btoken\s*=\s*[\"']",
            r"\bauth[_-]?token\s*=\s*[\"']",
            r"\baccess[_-]?token\s*=\s*[\"']",
            r"\bcredential[s]?\s*=\s*[\"']",
            r"\bdatabase[_-]?password\s*=\s*[\"']",
        ],

        "apis": [],

        "keywords": [
            "password",
            "passwd",
            "api key",
            "api_key",
            "secret",
            "secret key",
            "token",
            "credential",
            "credentials",
            "database password",
            "hard-coded",
            "hardcoded",
        ],
    },
}


def calculate_security_signal(code, cwe_id):
    """
    Calculate a simple security-pattern score between 0 and 1.
    """

    profile = SECURITY_PROFILES[cwe_id]

    code_lower = code.lower()

    pattern_matches = 0

    for pattern in profile["patterns"]:
        if re.search(
            pattern,
            code,
            re.IGNORECASE
        ):
            pattern_matches += 1

    keyword_matches = 0

    for keyword in profile["keywords"]:
        if keyword.lower() in code_lower:
            keyword_matches += 1

    # Pattern matches are stronger evidence than plain keywords.
    pattern_score = min(
        pattern_matches / 3,
        1.0
    )

    keyword_score = min(
        keyword_matches / 3,
        1.0
    )

    score = (
        0.75 * pattern_score
        + 0.25 * keyword_score
    )

    return min(score, 1.0)