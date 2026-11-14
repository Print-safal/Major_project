
import os
import time
from pathlib import Path
from typing import List, Literal

from dotenv import load_dotenv
from groq import Groq
from pydantic import (
    BaseModel,
    ConfigDict,
    StrictBool,
    model_validator,
)


# --------------------------------------------------
# ENVIRONMENT CONFIGURATION
# --------------------------------------------------

load_dotenv(Path(__file__).resolve().parents[1] / ".env")


# --------------------------------------------------
# PYDANTIC SCHEMAS
# --------------------------------------------------

class Vulnerability(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        strict=True
    )

    cwe: Literal[
        "CWE-89",
        "CWE-78",
        "CWE-79",
        "CWE-22",
        "CWE-798"
    ]

    vulnerability_name: str
    location: str
    explanation: str
    remediation: str


class SecurityReview(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        strict=True
    )

    vulnerable: StrictBool
    vulnerabilities: List[Vulnerability]

    @model_validator(mode="after")
    def validate_consistency(self):
        if self.vulnerable != bool(self.vulnerabilities):
            raise ValueError(
                "vulnerable must be True when vulnerabilities exist "
                "and False when the list is empty."
            )

        return self


# --------------------------------------------------
# SYSTEM PROMPT V4 - TARGETED RELIABILITY REFINEMENT
# --------------------------------------------------

SYSTEM_PROMPT = """
You are a security-focused Python code reviewer.

Analyze Python source code for security vulnerabilities.

Evaluate ONLY these five CWE categories:
1. CWE-89 - SQL Injection
2. CWE-78 - OS Command Injection
3. CWE-79 - Cross-Site Scripting (XSS)
4. CWE-22 - Path Traversal
5. CWE-798 - Use of Hard-coded Credentials

DECISION PROCESS:
1. First determine whether the code contains a security weakness.
2. Trace values from their source through the code to security-sensitive sinks.
3. Check ALL FIVE target CWEs independently.
4. Use the most specific applicable CWE.
5. Do not invent vulnerabilities or unsupported application context.
6. An explicit exploit payload or HTTP request is not required when a
   potentially untrusted value visibly flows into a vulnerable operation.
7. Distinguish a potential vulnerability from a confirmed, exploitable
   vulnerability. State relevant assumptions when application context is missing.
8. Every finding must be supported by evidence in the submitted code.
9. Do not invent attacker capabilities, application requirements,
   security boundaries, or missing code behaviour.

CONTEXTUAL INPUT AND DATA-FLOW ASSESSMENT:
When reviewing isolated code snippets, do not require an explicit HTTP
request, network source, or user-input declaration to recognize a potential
vulnerability.

Function parameters and externally supplied values may be treated as
potentially untrusted when they visibly flow into security-sensitive
operations.

Do not automatically classify every parameter or sensitive operation
as vulnerable. Examine the complete visible data flow and available
safeguards.

When application context is missing, describe the finding as a potential
vulnerability and clearly state the assumptions behind it.

Do not invent an input source, execution path, or security impact that
the code does not support.

CWE-89 SQL INJECTION:
Report when potentially untrusted input is incorporated into SQL through
string concatenation, f-strings, percent-formatting, .format(), or other
dynamic SQL construction.

Correctly parameterized queries are generally safe.

Examine whether the dynamic value reaches an SQL execution operation.
Do not report merely because a variable contains SQL-related text.

CWE-78 OS COMMAND INJECTION:
Report when potentially untrusted input reaches OS command execution
through os.system(), subprocess with shell=True, or dynamically
constructed shell commands.

subprocess with a list of arguments and shell=False is normally safe
from shell injection.

Do not confuse command execution with path traversal.

CWE-79 CROSS-SITE SCRIPTING:
Report when potentially untrusted dynamic values are inserted into HTML
markup or browser-rendered output without appropriate escaping or sanitization.

Function parameters may be treated as potentially untrusted when they
visibly flow into HTML construction.

For example, concatenating a function parameter into HTML elements and
returning the resulting markup without escaping is a potential CWE-79 issue.

Properly escaped or sanitized output is generally safe.

A function that merely returns a value without showing HTML construction
or a browser-rendering context is not sufficient evidence by itself.
Do not invent a rendering sink that is absent from the submitted code.

CWE-22 PATH TRAVERSAL:
Report when a potentially untrusted value is incorporated into a
filesystem path and reaches a file-access operation without effective
path containment validation.

When reviewing isolated snippets, function parameters and externally
supplied values may be treated as potentially untrusted if they visibly
flow into filesystem paths.

For example, dynamically concatenating a function parameter into a
base directory path and passing that path to open() or Path.read_text()
without normalization and containment checks is a potential CWE-22 issue.

Do not automatically classify every filename or file operation as vulnerable.
Examine the actual data flow and available safeguards.

Do not confuse command execution with path traversal. A filename passed
as an argument to subprocess with shell=False is not, by itself, evidence
of CWE-22.

When the intended directory boundary or input source is not established,
describe the finding as a potential vulnerability and state the assumption.

Do not claim confirmed exploitation without sufficient evidence.

CWE-798 HARD-CODED CREDENTIALS:
Report credentials or authentication secrets directly embedded in source code,
including API keys, passwords, database passwords, tokens, secret keys, or
access credentials.

If a credential is directly hard-coded, prefer CWE-798.

Environment variables and secret managers are not CWE-798.

MULTIPLE VULNERABILITIES:
Report multiple independent vulnerabilities when each is supported by code.

Do not add multiple CWEs for the same issue merely because several labels
could theoretically apply.

SAFE CODE:
If none of the five target vulnerabilities is present, set vulnerable=false
and vulnerabilities=[].

OUTPUT:
For each vulnerability provide:
- Exact CWE identifier
- Vulnerability name
- Affected location
- Concise explanation
- Practical remediation

Explanations must describe the actual weakness demonstrated by the code.

When application context is missing, explicitly distinguish potential
risk from confirmed exploitability.

Do not describe hypothetical attacks as confirmed vulnerabilities.

CWE identifiers MUST be exactly one of:
CWE-89, CWE-78, CWE-79, CWE-22, CWE-798

Never return only the numeric CWE.

Return only the requested structured output.
"""


# --------------------------------------------------
# MODEL CONFIGURATION
# --------------------------------------------------

MODEL = "openai/gpt-oss-120b"

LAST_CALL_STATS = {}


# --------------------------------------------------
# GROQ CLIENT
# --------------------------------------------------

def get_groq_client():
    """Create the Groq client."""

    api_key = os.getenv("GROQ_API_KEY")

    if not api_key:
        raise RuntimeError(
            "GROQ_API_KEY is not set. "
            "Set it in the project-root .env file."
        )

    return Groq(api_key=api_key)


# --------------------------------------------------
# LLM SECURITY REVIEW
# --------------------------------------------------

def review_code(code: str, security_context: str = "") -> SecurityReview:
    """
    Review Python code using Groq.

    Records API latency and token usage before Pydantic validation.
    """

    LAST_CALL_STATS.clear()

    client = get_groq_client()

    user_prompt = (
        "Analyze the following Python code for security vulnerabilities.\n\n"
        "Use the retrieved security knowledge below as supporting context.\n"
        "The retrieved knowledge is provided by the project's RAG security knowledge base.\n\n"
        "Important: Retrieved knowledge is supporting evidence, not proof "
        "that the submitted code is vulnerable. Base every finding on "
        "the actual submitted source code.\n\n"
        "Trace potentially untrusted values through the visible code "
        "and examine whether they reach security-sensitive operations.\n"
        "Do not require an explicit HTTP request or exploit payload when "
        "the relevant data flow is visible.\n"
        "Do not invent missing application context or security boundaries.\n\n"
        "Retrieved Security Knowledge:\n\n"
        f"{security_context}\n\n"
        "Python code:\n\n"
        "```python\n"
        f"{code}\n"
        "```\n\n"
        "Determine whether the code contains any of the five target CWE "
        "vulnerabilities defined in the system instructions."
    )

    start_time = time.perf_counter()

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

    llm_latency = time.perf_counter() - start_time
    usage = response.usage

    LAST_CALL_STATS.update({
        "llm_latency_seconds": llm_latency,
        "prompt_tokens": (
            usage.prompt_tokens if usage else None
        ),
        "completion_tokens": (
            usage.completion_tokens if usage else None
        ),
        "total_tokens": (
            usage.total_tokens if usage else None
        ),
    })

    parsed = SecurityReview.model_validate_json(
        response.choices[0].message.content
    )

    return parsed
