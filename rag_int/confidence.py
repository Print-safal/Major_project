"""Deterministic evidence-based review confidence heuristics.

Scores summarize agreement and evidence sufficiency; they are not calibrated
probabilities, exploitability estimates, or vulnerability severity scores.
Semantic documents are supporting references only and cannot establish a flaw.
Potential AST source-to-sink links receive weaker credit than direct indicators
and are always described as unverified.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any, Literal, Optional, Sequence

from rag.retrieval.contextual_retrieval import EvidenceItem


SUPPORTED_CWES = ("CWE-22", "CWE-78", "CWE-79", "CWE-798", "CWE-89")
ConfidenceLevel = Literal["High", "Medium", "Low", "Undetermined"]


@dataclass(frozen=True)
class ConfidenceComponent:
    name: str
    score: Optional[float]
    weight: float
    explanation: str
    supporting_evidence: tuple[EvidenceItem, ...] = ()
    conflicting_evidence: tuple[EvidenceItem, ...] = ()

    def __post_init__(self):
        _validate_optional_score(self.score, f"component {self.name}")
        if not math.isfinite(self.weight) or self.weight < 0:
            raise ValueError("component weight must be finite and non-negative")

    @property
    def level(self) -> ConfidenceLevel:
        """Expose the default qualitative band for this component score."""
        return _level(self.score, DEFAULT_THRESHOLDS)


@dataclass(frozen=True)
class FindingConfidence:
    cwe_id: str
    location: str
    score: Optional[float]
    level: ConfidenceLevel
    components: tuple[ConfidenceComponent, ...]
    supporting_evidence: tuple[EvidenceItem, ...]
    conflicting_evidence: tuple[EvidenceItem, ...]
    explanation: str

    def __post_init__(self):
        _validate_optional_score(self.score, "finding confidence")
        _validate_level_score(self.score, self.level)


@dataclass(frozen=True)
class AssessmentConfidence:
    vulnerable: bool
    score: Optional[float]
    level: ConfidenceLevel
    components: tuple[ConfidenceComponent, ...]
    finding_confidences: tuple[FindingConfidence, ...]
    supporting_evidence: tuple[EvidenceItem, ...]
    conflicting_evidence: tuple[EvidenceItem, ...]
    explanation: str

    def __post_init__(self):
        _validate_optional_score(self.score, "assessment confidence")
        _validate_level_score(self.score, self.level)


@dataclass(frozen=True)
class ConfidenceWeights:
    """Configurable heuristic weights; defaults sum to 100 points."""

    semantic_relevance: float = 10.0
    cwe_agreement: float = 10.0
    contextual_indicators: float = 20.0
    source_to_sink: float = 20.0
    safeguards: float = 15.0
    llm_consistency: float = 25.0

    def __post_init__(self):
        values = tuple(getattr(self, name) for name in self.__dataclass_fields__)
        if any(not math.isfinite(value) or value < 0 for value in values):
            raise ValueError("weights must be finite and non-negative")
        if not math.isclose(sum(values), 100.0, abs_tol=1e-9):
            raise ValueError("confidence weights must sum to 100")


@dataclass(frozen=True)
class ConfidenceThresholds:
    high: float = 75.0
    medium: float = 50.0
    minimum_available_weight: float = 25.0
    minimum_code_channels: int = 1

    def __post_init__(self):
        if not (0 <= self.medium <= self.high <= 100):
            raise ValueError("thresholds must satisfy 0 <= medium <= high <= 100")
        if not (0 <= self.minimum_available_weight <= 100):
            raise ValueError("minimum_available_weight must be between 0 and 100")
        if self.minimum_code_channels < 0:
            raise ValueError("minimum_code_channels cannot be negative")


@dataclass(frozen=True)
class ReviewCoverage:
    """Caller-supplied coverage facts used for safe-review assessments."""

    analyzed_cwes: tuple[str, ...]
    syntax_valid: bool
    context_extraction_complete: bool
    semantic_retrieval_complete: bool


DEFAULT_WEIGHTS = ConfidenceWeights()
DEFAULT_THRESHOLDS = ConfidenceThresholds()


def _validate_optional_score(score: Optional[float], label: str) -> None:
    if score is not None and (
        isinstance(score, bool) or not isinstance(score, (int, float))
        or not math.isfinite(score) or not 0 <= score <= 100
    ):
        raise ValueError(f"{label} score must be between 0 and 100 or None")


def _validate_level_score(score: Optional[float], level: str) -> None:
    if level not in {"High", "Medium", "Low", "Undetermined"}:
        raise ValueError(f"invalid confidence level: {level}")
    if (score is None) != (level == "Undetermined"):
        raise ValueError("Undetermined level must have no score; other levels need a score")


def _deduplicate(evidence: Sequence[EvidenceItem]) -> tuple[EvidenceItem, ...]:
    unique = {}
    for item in evidence:
        if not isinstance(item, EvidenceItem):
            raise TypeError("evidence_items must contain EvidenceItem values")
        if item.cwe_id not in SUPPORTED_CWES:
            raise ValueError(f"unsupported CWE in evidence: {item.cwe_id}")
        if item.kind not in {"semantic", "vulnerable", "secure", "contextual"}:
            raise ValueError(f"unsupported evidence kind: {item.kind}")
        if item.score is not None and (
            isinstance(item.score, bool) or not isinstance(item.score, (int, float))
            or not math.isfinite(item.score) or not -1 <= item.score <= 1
        ):
            raise ValueError("semantic evidence score must be between -1 and 1")
        key = (item.cwe_id, item.kind, item.evidence, item.provenance,
               item.score, item.location, item.explanation)
        unique[key] = item
    return tuple(unique.values())


def _field(obj: Any, name: str, default=None):
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


def _finding_fields(finding: Any) -> tuple[str, str]:
    cwe = _field(finding, "cwe", _field(finding, "cwe_id"))
    location = _field(finding, "location", "")
    if cwe not in SUPPORTED_CWES:
        raise ValueError(f"unsupported finding CWE: {cwe}")
    if not isinstance(location, str):
        raise TypeError("finding location must be a string")
    return cwe, location


def _level(score: Optional[float], thresholds: ConfidenceThresholds) -> ConfidenceLevel:
    if score is None:
        return "Undetermined"
    if score >= thresholds.high:
        return "High"
    if score >= thresholds.medium:
        return "Medium"
    return "Low"


def _component_score(items: Sequence[EvidenceItem], cwe: str, component: str):
    relevant = [item for item in items if item.cwe_id == cwe]
    if component == "semantic_relevance":
        semantic = [item for item in relevant if item.kind == "semantic" and item.score is not None]
        if not semantic:
            return None, (), ()
        # FAISS cosine-like scores are bounded [-1, 1]; convert to bounded
        # relevance with zero as no positive similarity, not as a probability.
        return max(0.0, min(1.0, max(float(item.score) for item in semantic))) * 100, tuple(semantic), ()
    if component == "cwe_agreement":
        semantic = [item for item in items if item.kind == "semantic"]
        if not semantic:
            return None, (), ()
        cwes = {item.cwe_id for item in semantic}
        score = 100.0 / len(cwes) if cwe in cwes else 0.0
        matching = tuple(item for item in semantic if item.cwe_id == cwe)
        other = tuple(item for item in semantic if item.cwe_id != cwe)
        return score, matching, other
    if component == "contextual_indicators":
        vulnerable = tuple(item for item in relevant if item.kind == "vulnerable")
        contextual = tuple(item for item in relevant if item.kind == "contextual")
        secure = tuple(item for item in relevant if item.kind == "secure")
        if not (vulnerable or contextual or secure):
            return None, (), ()
        score = 100.0 if vulnerable else (45.0 if contextual else 0.0)
        return score, vulnerable + contextual, secure
    if component == "source_to_sink":
        flows = tuple(item for item in relevant if item.provenance == "ast.source_to_sink_candidate")
        return (55.0, flows, ()) if flows else (None, (), ())
    if component == "safeguards":
        safeguards = tuple(item for item in relevant if item.kind == "secure")
        return (0.0, (), safeguards) if safeguards else (None, (), ())
    raise ValueError(f"unknown confidence component: {component}")


def _make_components(
    cwe: str,
    all_evidence: tuple[EvidenceItem, ...],
    llm_score: Optional[float],
    llm_support: tuple[EvidenceItem, ...],
    llm_conflict: tuple[EvidenceItem, ...],
    weights: ConfidenceWeights,
) -> tuple[ConfidenceComponent, ...]:
    explanations = {
        "semantic_relevance": "Maximum target-CWE retrieval relevance; semantic relevance is supporting context only.",
        "cwe_agreement": "Share of distinct retrieved CWE labels agreeing with this finding; retrieval agreement is not proof.",
        "contextual_indicators": "AST/profile indicator support, with safeguards retained as conflicting evidence.",
        "source_to_sink": "Potential AST source-to-sink candidates receive limited support and remain unconfirmed.",
        "safeguards": "A matching safeguard is treated as evidence against the reported vulnerability, not as guaranteed protection.",
        "llm_consistency": "Consistency of the reported LLM finding with independent collected code evidence.",
    }
    components = []
    for name in explanations:
        if name == "llm_consistency":
            score, supporting, conflicting = llm_score, llm_support, llm_conflict
        else:
            score, supporting, conflicting = _component_score(all_evidence, cwe, name)
        components.append(ConfidenceComponent(name, score,
            getattr(weights, name), explanations[name], supporting, conflicting))
    return tuple(components)


def _weighted_score(components: Sequence[ConfidenceComponent]) -> tuple[Optional[float], float]:
    available = [component for component in components if component.score is not None and component.weight > 0]
    denominator = sum(component.weight for component in available)
    if denominator == 0:
        return None, 0.0
    return sum(component.score * component.weight for component in available) / denominator, denominator


def score_finding_confidence(
    finding: Any,
    evidence_items: Sequence[EvidenceItem],
    *,
    all_evidence: Optional[Sequence[EvidenceItem]] = None,
    weights: ConfidenceWeights = DEFAULT_WEIGHTS,
    thresholds: ConfidenceThresholds = DEFAULT_THRESHOLDS,
) -> FindingConfidence:
    """Score one Pydantic Vulnerability or compatible mapping/object."""
    cwe, location = _finding_fields(finding)
    evidence = _deduplicate(evidence_items)
    review_evidence = _deduplicate(all_evidence if all_evidence is not None else evidence)
    target = tuple(item for item in evidence if item.cwe_id == cwe)
    vulnerable = tuple(item for item in target if item.kind == "vulnerable")
    secure = tuple(item for item in target if item.kind == "secure")
    contextual = tuple(item for item in target if item.kind == "contextual")
    flows = tuple(item for item in target if item.provenance == "ast.source_to_sink_candidate")
    semantic = tuple(item for item in target if item.kind == "semantic")

    # LLM consistency uses only code-derived corroboration. Semantic documents
    # alone cannot corroborate a vulnerability finding.
    if vulnerable:
        llm_score = 65.0 if secure else 100.0
        llm_support, llm_conflict = vulnerable + contextual + flows, secure
    elif flows:
        llm_score, llm_support, llm_conflict = 60.0, flows + contextual, secure
    elif contextual:
        llm_score, llm_support, llm_conflict = 45.0, contextual, secure
    elif secure:
        llm_score, llm_support, llm_conflict = 0.0, (), secure
    elif semantic:
        llm_score, llm_support, llm_conflict = 25.0, (), ()
    else:
        llm_score, llm_support, llm_conflict = None, (), ()

    components = _make_components(cwe, review_evidence, llm_score,
                                  llm_support, llm_conflict, weights)
    score, available_weight = _weighted_score(components)
    code_channels = sum(bool(items) for items in (vulnerable, contextual, flows, secure))
    sufficient = (available_weight >= thresholds.minimum_available_weight
                  and code_channels >= thresholds.minimum_code_channels
                  and (bool(vulnerable or secure) or code_channels >= 2))
    if not sufficient:
        score = None
    level = _level(score, thresholds)
    supporting = tuple(dict.fromkeys(
        item for component in components for item in component.supporting_evidence
    ))
    conflicting = tuple(dict.fromkeys(
        item for component in components for item in component.conflicting_evidence
    ))
    explanation = (
        "Score summarizes available evidence and agreement; it is not a probability. "
        + ("Secure indicators conflict with the finding. " if secure else "")
        + ("Potential source-to-sink evidence is syntactic and unverified. " if flows else "")
        + ("Evidence is insufficient for a numeric assessment." if score is None else
           "Vulnerability severity is assessed separately.")
    )
    return FindingConfidence(cwe, location, score, level, components,
                             supporting, conflicting, explanation)


def _review_findings(review: Any) -> tuple[bool, tuple[Any, ...]]:
    vulnerable = _field(review, "vulnerable")
    findings = _field(review, "vulnerabilities")
    if type(vulnerable) is not bool:
        raise TypeError("review.vulnerable must be a boolean")
    if not isinstance(findings, (list, tuple)):
        raise TypeError("review.vulnerabilities must be a list or tuple")
    if vulnerable != bool(findings):
        raise ValueError("review vulnerable flag must agree with finding list")
    return vulnerable, tuple(findings)


def score_assessment_confidence(
    review: Any,
    evidence_items: Sequence[EvidenceItem],
    *,
    coverage: Optional[ReviewCoverage] = None,
    weights: ConfidenceWeights = DEFAULT_WEIGHTS,
    thresholds: ConfidenceThresholds = DEFAULT_THRESHOLDS,
) -> AssessmentConfidence:
    """Score a whole review without averaging findings indiscriminately.

    Vulnerable reviews use 70% of the weakest reported finding and 30% of the
    mean finding score so one poorly supported report cannot be hidden by many
    strong findings. Safe reviews require explicit complete coverage of all five
    supported CWEs; absence of matches by itself is not evidence of safety.
    """
    vulnerable, findings = _review_findings(review)
    evidence = _deduplicate(evidence_items)
    finding_scores = tuple(score_finding_confidence(
        finding, evidence, all_evidence=evidence, weights=weights, thresholds=thresholds
    ) for finding in findings)

    if vulnerable:
        numeric = [result.score for result in finding_scores]
        if any(value is None for value in numeric):
            return AssessmentConfidence(True, None, "Undetermined", (), finding_scores,
                tuple(item for result in finding_scores for item in result.supporting_evidence),
                tuple(item for result in finding_scores for item in result.conflicting_evidence),
                "At least one reported finding has insufficient evidence; assessment confidence is undetermined.")
        low = min(numeric)
        mean = sum(numeric) / len(numeric)
        score = 0.70 * low + 0.30 * mean
        level = _level(score, thresholds)
        components = tuple(ConfidenceComponent(
            f"finding:{result.cwe_id}:{result.location}", result.score, 1.0,
            "Reported-finding confidence; overall aggregation emphasizes the weakest finding.",
            result.supporting_evidence, result.conflicting_evidence,
        ) for result in finding_scores)
        return AssessmentConfidence(True, score, level, components, finding_scores,
            tuple(dict.fromkeys(item for result in finding_scores for item in result.supporting_evidence)),
            tuple(dict.fromkeys(item for result in finding_scores for item in result.conflicting_evidence)),
            "Overall score is 70% the weakest finding and 30% the mean finding score; it is not a probability.")

    if coverage is not None and not isinstance(coverage, ReviewCoverage):
        raise TypeError("coverage must be ReviewCoverage or None")
    covered = set(coverage.analyzed_cwes) if coverage else set()
    if not covered.issubset(SUPPORTED_CWES):
        raise ValueError("coverage contains unsupported CWE identifiers")
    complete = bool(coverage and coverage.syntax_valid and coverage.context_extraction_complete
                    and coverage.semantic_retrieval_complete and covered == set(SUPPORTED_CWES))
    semantic_cwes = {item.cwe_id for item in evidence if item.kind == "semantic"}
    coverage_score = 100.0 if complete else None
    semantic_coverage_score = (100.0 * len(semantic_cwes & set(SUPPORTED_CWES)) / len(SUPPORTED_CWES)
                               if coverage and coverage.semantic_retrieval_complete else None)
    secure_evidence = tuple(item for item in evidence if item.kind == "secure")
    vulnerable_evidence = tuple(item for item in evidence if item.kind == "vulnerable")
    components = (
        ConfidenceComponent("review_coverage", coverage_score, 50.0,
            "All five CWEs, syntax parsing, context extraction, and retrieval must be explicitly covered.",
            (), ()),
        ConfidenceComponent("semantic_cwe_coverage", semantic_coverage_score, 20.0,
            "Breadth of retrieved CWE references; references alone do not prove safety.",
            tuple(item for item in evidence if item.kind == "semantic"), ()),
        ConfidenceComponent("secure_indicators", 80.0 if secure_evidence else None, 15.0,
            "Detected safeguards provide limited supporting evidence for a safe review.",
            secure_evidence, ()),
        ConfidenceComponent("vulnerable_indicators", 0.0 if vulnerable_evidence else None, 15.0,
            "Any vulnerable indicator conflicts with a safe conclusion; no matches are treated as missing, not negative evidence.",
            (), vulnerable_evidence),
    )
    score, available_weight = _weighted_score(components)
    if not complete or available_weight < thresholds.minimum_available_weight or vulnerable_evidence:
        score = None
    level = _level(score, thresholds)
    explanation = (
        "Safe-review confidence requires explicit complete coverage of all five supported CWEs; "
        "no findings or no indicators alone do not establish safety. "
        + ("Coverage/evidence is insufficient." if score is None else
           "Coverage is complete; safeguards and retrieval breadth contribute as limited evidence. "
           "This score is not a probability.")
    )
    return AssessmentConfidence(False, score, level, components, (),
        tuple(item for component in components for item in component.supporting_evidence),
        tuple(item for component in components for item in component.conflicting_evidence), explanation)


def score_vulnerability_confidence(*args, **kwargs) -> FindingConfidence:
    """Alias for callers that prefer the full vulnerability-oriented name."""
    return score_finding_confidence(*args, **kwargs)

