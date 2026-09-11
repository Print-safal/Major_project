import os
from typing import List

from groq import Groq
from pydantic import BaseModel, ConfigDict


class Vulnerability(BaseModel):
    model_config = ConfigDict(extra="forbid")

    cwe: str
    vulnerability_name: str
    location: str
    explanation: str
    remediation: str


class SecurityReview(BaseModel):
    model_config = ConfigDict(extra="forbid")

    vulnerable: bool
    vulnerabilities: List[Vulnerability]


SYSTEM_PROMPT = """
You are a security-focused Python code reviewer.

Analyze Python source code for real security vulnerabilities.

Evaluate ONLY these five CWE categories:
1. CWE-89 - SQL Injection
2. CWE-78 - OS Command Injection
3. CWE-79 - Cross-Site Scripting (XSS)
4. CWE-22 - Path Traversal
5. CWE-798 - Use of Hard-coded Credentials

DECISION PROCESS:
1. First determine whether the code is actually vulnerable.
2. Trace untrusted input from source to security-sensitive sink.
3. Then check ALL FIVE target CWEs independently.
4. Use the most specific applicable CWE.
5. Do not invent vulnerabilities or rely on assumptions not shown in the code.
6. An explicit exploit payload is not required when the dangerous data flow is clear.

CWE-89 SQL INJECTION:
Report when untrusted input is incorporated into SQL through string
concatenation, f-strings, percent-formatting, .format(), or other dynamic SQL.
Correctly parameterized queries are generally safe.

CWE-78 OS COMMAND INJECTION:
Report when untrusted input reaches OS command execution such as os.system(),
subprocess with shell=True, or dynamically constructed shell commands.
subprocess with a list of arguments and shell=False is normally safe.

CWE-79 XSS:
Report when untrusted input is inserted into HTML or browser-rendered output
without appropriate escaping or sanitization. Properly escaped output is safe.

CWE-22 PATH TRAVERSAL:
Report when untrusted input controls a filesystem path and can access outside
the intended directory. A variable filename alone is not sufficient evidence.

CWE-798 HARD-CODED CREDENTIALS:
Report credentials or authentication secrets directly embedded in source code,
including API keys, passwords, database passwords, tokens, secret keys, or
access credentials. If a credential is directly hard-coded, prefer CWE-798.
Environment variables and secret managers are not CWE-798.

MULTIPLE VULNERABILITIES:
Report multiple independent vulnerabilities when each is supported by code.
Do not add multiple CWEs for the same issue merely because several labels
could theoretically apply.

SAFE CODE:
If none of the five target vulnerabilities is present, set vulnerable=false
and vulnerabilities=[].

OUTPUT:
For each vulnerability provide the exact CWE identifier, vulnerability name,
affected location, concise explanation, and practical remediation.

CWE identifiers MUST be exactly one of:
CWE-89, CWE-78, CWE-79, CWE-22, CWE-798

Never return only the numeric CWE.
Return only the requested structured output.
"""


MODEL = "openai/gpt-oss-120b"


def get_groq_client():
    """Create and return the Groq client using the environment API key."""

    api_key = os.getenv("GROQ_API_KEY")

    if not api_key:
        raise RuntimeError(
            "GROQ_API_KEY is not set. "
            "Set it in PowerShell before running."
        )

    return Groq(api_key=api_key)

def review_code(code: str, security_context: str = "") -> SecurityReview:
    """
    Review Python code using the Groq LLM.

    code:
        Python source code to analyze.

    security_context:
        Security knowledge retrieved by the RAG system.

    Returns:
        A structured SecurityReview object.
    """

    client = get_groq_client()

    user_prompt = (
        "Analyze the following Python code for security vulnerabilities.\n\n"
        "Use the retrieved security knowledge below as supporting context.\n"
        "The retrieved knowledge is provided by the project's RAG security knowledge base.\n\n"
        "Retrieved Security Knowledge:\n\n"
        f"{security_context}\n\n"
        "Python code:\n\n"
        "```python\n"
        f"{code}\n"
        "```\n\n"
        "Determine whether the code contains any of the five target CWE "
        "vulnerabilities defined in the system instructions."
    )

    response = client.chat.completions.create(
        model=MODEL,
        messages=[
            {
                "role": "system",
                "content": SYSTEM_PROMPT,
            },
            {
                "role": "user",
                "content": user_prompt,
            },
        ],
        temperature=0,
        response_format={
            "type": "json_schema",
            "json_schema": {
                "name": "security_review",
                "schema": SecurityReview.model_json_schema(),
                "strict": True,
            },
        },
    )

    parsed = SecurityReview.model_validate_json(
        response.choices[0].message.content
    )

    return parsed