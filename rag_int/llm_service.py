import os
import time
from pathlib import Path
from typing import List, Literal, Optional

from dotenv import load_dotenv
from groq import Groq
from pydantic import BaseModel, ConfigDict, Field, StrictBool, model_validator


# Load the project-root .env file.
load_dotenv(Path(__file__).resolve().parents[1] / ".env")


class Vulnerability(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    cwe: Literal["CWE-89", "CWE-78", "CWE-79", "CWE-22", "CWE-798"]
    vulnerability_name: str
    location: str
    explanation: str
    remediation: str


class SecurityReview(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

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


ConfidenceLevelName = Literal["High", "Medium", "Low", "Undetermined"]


class SourceLocation(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    line_start: int = Field(ge=1)
    column_start: int = Field(ge=0)
    line_end: int = Field(ge=1)
    column_end: int = Field(ge=0)


class EvidenceReference(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    cwe_id: Literal["CWE-22", "CWE-78", "CWE-79", "CWE-798", "CWE-89"]
    kind: Literal["semantic", "vulnerable", "secure", "contextual"]
    evidence: str
    provenance: str
    score: Optional[float] = Field(default=None, ge=-1, le=1)
    location: Optional[SourceLocation] = None
    explanation: str


class ConfidenceComponentResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    name: str
    score: Optional[float] = Field(default=None, ge=0, le=100)
    level: ConfidenceLevelName
    weight: float = Field(ge=0)
    explanation: str
    supporting_evidence: List[EvidenceReference]
    conflicting_evidence: List[EvidenceReference]

    @model_validator(mode="after")
    def validate_level_score(self):
        if (self.score is None) != (self.level == "Undetermined"):
            raise ValueError("Undetermined confidence requires a null score")
        return self


class FindingConfidenceResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    cwe_id: Literal["CWE-22", "CWE-78", "CWE-79", "CWE-798", "CWE-89"]
    location: str
    score: Optional[float] = Field(default=None, ge=0, le=100)
    level: ConfidenceLevelName
    components: List[ConfidenceComponentResponse]
    supporting_evidence: List[EvidenceReference]
    conflicting_evidence: List[EvidenceReference]
    explanation: str

    @model_validator(mode="after")
    def validate_level_score(self):
        if (self.score is None) != (self.level == "Undetermined"):
            raise ValueError("Undetermined confidence requires a null score")
        return self


class ReviewedVulnerability(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    cwe: Literal["CWE-89", "CWE-78", "CWE-79", "CWE-22", "CWE-798"]
    vulnerability_name: str
    location: str
    explanation: str
    remediation: str
    confidence: FindingConfidenceResponse

    @model_validator(mode="after")
    def validate_confidence_target(self):
        if self.confidence.cwe_id != self.cwe or self.confidence.location != self.location:
            raise ValueError("finding confidence must match its CWE and location")
        return self


class AssessmentConfidenceResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    vulnerable: StrictBool
    score: Optional[float] = Field(default=None, ge=0, le=100)
    level: ConfidenceLevelName
    components: List[ConfidenceComponentResponse]
    finding_confidences: List[FindingConfidenceResponse]
    supporting_evidence: List[EvidenceReference]
    conflicting_evidence: List[EvidenceReference]
    explanation: str

    @model_validator(mode="after")
    def validate_level_score(self):
        if (self.score is None) != (self.level == "Undetermined"):
            raise ValueError("Undetermined confidence requires a null score")
        return self


class EnrichedSecurityReview(BaseModel):
    """API review response; separate from the schema requested from the LLM."""

    model_config = ConfigDict(extra="forbid", strict=True)

    vulnerable: StrictBool
    vulnerabilities: List[ReviewedVulnerability]
    assessment_confidence: AssessmentConfidenceResponse

    @model_validator(mode="after")
    def validate_consistency(self):
        if self.vulnerable != bool(self.vulnerabilities):
            raise ValueError("vulnerable must agree with the vulnerability list")
        if self.assessment_confidence.vulnerable != self.vulnerable:
            raise ValueError("assessment confidence must match review status")
        if len(self.assessment_confidence.finding_confidences) != len(self.vulnerabilities):
            raise ValueError("assessment finding confidence count must match findings")
        for finding, confidence in zip(
            self.vulnerabilities, self.assessment_confidence.finding_confidences
        ):
            if finding.cwe != confidence.cwe_id or finding.location != confidence.location:
                raise ValueError("assessment finding confidence must match each finding")
        return self


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

# Statistics from the most recent API request.
LAST_CALL_STATS = {}


def get_groq_client():
    """Create the Groq client."""

    api_key = os.getenv("GROQ_API_KEY")

    if not api_key:
        raise RuntimeError(
            "GROQ_API_KEY is not set. "
            "Set it in the project-root .env file."
        )

    return Groq(api_key=api_key)


def review_code(
    code: str,
    security_context: str = "",
    *,
    client=None,
    llm_only: bool = False,
    return_raw: bool = False,
):
    """
    Review Python code using Groq.

    Token usage and API latency are recorded immediately after the API
    response, before Pydantic validation. Therefore, usage is retained
    even when structured response validation fails.
    """

    # Clear previous request statistics to prevent stale values.
    LAST_CALL_STATS.clear()

    client = client or get_groq_client()

    user_prompt = (
        "Analyze the following Python code for security vulnerabilities.\n\n"
        "Python code:\n\n"
        "```python\n"
        f"{code}\n"
        "```\n\n"
        "Determine whether the code contains any of the five target CWE "
        "vulnerabilities defined in the system instructions."
    ) if llm_only else (
        "Analyze the following Python code for security vulnerabilities.\n\n"
        "Use the retrieved security knowledge below as supporting context.\n"
        "The retrieved knowledge is provided by the project's RAG security knowledge base.\n\n"
        "Important: Retrieved knowledge is supporting context, not proof "
        "that the submitted code is vulnerable. Base every finding on "
        "the actual submitted source code.\n\n"
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

    # Record API usage BEFORE attempting response validation.
    request_stats = {
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
    }
    LAST_CALL_STATS.update(request_stats)

    # Validation happens only after usage has been recorded.
    raw_text = response.choices[0].message.content or ""
    try:
        parsed = SecurityReview.model_validate_json(raw_text)
    except Exception as exc:
        if return_raw:
            return None, raw_text, dict(request_stats), exc
        raise

    if return_raw:
        return parsed, raw_text, dict(request_stats), None
    return parsed
