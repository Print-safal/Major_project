import os
import time
from dataclasses import asdict

from rag.analysis.ast_context import CodeContext, extract_code_context
from rag.retrieval.contextual_retrieval import (
    EvidenceItem,
    build_shadow_retrieval,
    match_context,
)
from rag.retrieval.cwe_aggregator import aggregate_cwe_results
from rag_int.confidence import (
    ReviewCoverage,
    SUPPORTED_CWES,
    score_assessment_confidence,
    score_finding_confidence,
)
from rag_int.llm_service import (
    AssessmentConfidenceResponse,
    ConfidenceComponentResponse,
    EnrichedSecurityReview,
    EvidenceReference,
    FindingConfidenceResponse,
    ReviewedVulnerability,
    SourceLocation,
    review_code,
)


# Diagnostic shadow order can be selected for A/B inspection. The existing
# aggregator remains the default and is always retained as the fallback.
USE_SHADOW_RANKING = os.getenv("RAG_USE_SHADOW_RANKING", "false").lower() == "true"

# Stores timing and ordering information for the most recent API request.
LAST_RAG_STATS = {}


def semantic_search(query, top_k=20):
    """Use the existing FAISS search lazily to keep import-time side effects out."""
    from rag.retrieval.hybrid_retriever import semantic_search as faiss_search
    return faiss_search(query, top_k=top_k)


def _location_model(location):
    return SourceLocation.model_validate(asdict(location)) if location is not None else None


def _evidence_model(item: EvidenceItem) -> EvidenceReference:
    return EvidenceReference(
        cwe_id=item.cwe_id,
        kind=item.kind,
        evidence=item.evidence,
        provenance=item.provenance,
        score=item.score,
        location=_location_model(item.location),
        explanation=item.explanation,
    )


def _component_model(component) -> ConfidenceComponentResponse:
    return ConfidenceComponentResponse(
        name=component.name,
        score=component.score,
        level=component.level,
        weight=component.weight,
        explanation=component.explanation,
        supporting_evidence=[_evidence_model(item) for item in component.supporting_evidence],
        conflicting_evidence=[_evidence_model(item) for item in component.conflicting_evidence],
    )


def _finding_confidence_model(confidence) -> FindingConfidenceResponse:
    return FindingConfidenceResponse(
        cwe_id=confidence.cwe_id,
        location=confidence.location,
        score=confidence.score,
        level=confidence.level,
        components=[_component_model(item) for item in confidence.components],
        supporting_evidence=[_evidence_model(item) for item in confidence.supporting_evidence],
        conflicting_evidence=[_evidence_model(item) for item in confidence.conflicting_evidence],
        explanation=confidence.explanation,
    )


def _assessment_model(confidence) -> AssessmentConfidenceResponse:
    return AssessmentConfidenceResponse(
        vulnerable=confidence.vulnerable,
        score=confidence.score,
        level=confidence.level,
        components=[_component_model(item) for item in confidence.components],
        finding_confidences=[_finding_confidence_model(item) for item in confidence.finding_confidences],
        supporting_evidence=[_evidence_model(item) for item in confidence.supporting_evidence],
        conflicting_evidence=[_evidence_model(item) for item in confidence.conflicting_evidence],
        explanation=confidence.explanation,
    )


def format_rag_context(rag_results, contextual_matches=()):
    """Format legacy ranked RAG results plus explicitly qualified context evidence."""
    context_parts = []
    if not rag_results:
        context_parts.append("No relevant security evidence was retrieved.")
    else:
        # Preserve the existing production behavior: top two CWEs, one chunk each.
        for result in rag_results[:2]:
            context_parts.append(
                f"CWE: {result['cwe_id']} - {result['cwe_name']}\n"
                f"CWE Score: {result['score']:.4f}\n"
                f"Security Signal: {result['security_score']:.4f}\n"
                f"Vulnerability Evidence Count: "
                f"{result['vulnerable_evidence_count']}\n"
            )
            for chunk in result.get("supporting_chunks", [])[:1]:
                context_parts.append(
                    f"Evidence Type: {chunk.get('section', 'unknown')}\n"
                    f"Evidence: {chunk.get('text', '')}\n"
                )
            context_parts.append("")

    if contextual_matches:
        context_parts.append(
            "AST and indicator evidence (candidate evidence only; it does not prove a vulnerability):"
        )
        for match in contextual_matches:
            span = match.location
            location = f"line {span.line_start}:{span.column_start}" if span else "location unavailable"
            context_parts.append(
                f"- {match.cwe_id} [{match.indicator_type}] at {location}: "
                f"{match.evidence}. {match.explanation}"
            )
    return "\n".join(context_parts)


def _sort_with_shadow_order(legacy_results, shadow_results):
    order = {result.cwe_id: index for index, result in enumerate(shadow_results)}
    return sorted(legacy_results, key=lambda item: order.get(item["cwe_id"], len(order)))


def _build_api_review(review, findings, assessment) -> EnrichedSecurityReview:
    enriched_findings = []
    if len(findings) != len(review.vulnerabilities):
        raise ValueError("finding confidence count does not match LLM findings")
    for vulnerability, confidence in zip(review.vulnerabilities, findings):
        if vulnerability.cwe != confidence.cwe_id or vulnerability.location != confidence.location:
            raise ValueError("finding confidence does not match its LLM finding")
        enriched_findings.append(ReviewedVulnerability(
            cwe=vulnerability.cwe,
            vulnerability_name=vulnerability.vulnerability_name,
            location=vulnerability.location,
            explanation=vulnerability.explanation,
            remediation=vulnerability.remediation,
            confidence=_finding_confidence_model(confidence),
        ))
    return EnrichedSecurityReview(
        vulnerable=review.vulnerable,
        vulnerabilities=enriched_findings,
        assessment_confidence=_assessment_model(assessment),
    )


def review_code_with_rag(code: str, context: CodeContext | None = None):
    """Run legacy retrieval and LLM review, then attach deterministic confidence."""
    LAST_RAG_STATS.clear()
    if context is None:
        context = extract_code_context(code)
    elif context.source != code:
        raise ValueError("CodeContext source does not match submitted source")
    if context.parse_error is not None:
        raise ValueError("Cannot review code with invalid Python syntax")

    # One FAISS candidate batch is shared by the legacy aggregator and shadow
    # evidence path so their comparison uses identical retrieval evidence.
    retrieval_start = time.perf_counter()
    semantic_candidates = semantic_search(code, top_k=30)
    rag_results = aggregate_cwe_results(
        code, candidate_k=30, top_k=5, semantic_candidates=semantic_candidates
    )
    shadow_results = build_shadow_retrieval(
        code, semantic_candidates=semantic_candidates, context=context, top_k=5
    )
    contextual_matches = match_context(context)
    retrieval_latency = time.perf_counter() - retrieval_start

    legacy_order = [item["cwe_id"] for item in rag_results]
    shadow_order = [item.cwe_id for item in shadow_results]
    chosen_results = _sort_with_shadow_order(rag_results, shadow_results) if USE_SHADOW_RANKING else rag_results
    chosen_order = [item["cwe_id"] for item in chosen_results]
    LAST_RAG_STATS.update({
        "retrieval_latency_seconds": retrieval_latency,
        "legacy_candidate_order": legacy_order,
        "shadow_candidate_order": shadow_order,
        "selected_candidate_order": chosen_order,
        "shadow_ranking_enabled": USE_SHADOW_RANKING,
    })

    security_context = format_rag_context(chosen_results, contextual_matches)
    llm_review = review_code(code=code, security_context=security_context)

    evidence = tuple(item for result in shadow_results for item in result.evidence)
    finding_confidences = tuple(
        score_finding_confidence(finding, evidence, all_evidence=evidence)
        for finding in llm_review.vulnerabilities
    )
    coverage = ReviewCoverage(
        analyzed_cwes=SUPPORTED_CWES,
        syntax_valid=context.parse_error is None,
        context_extraction_complete=context.parse_error is None,
        semantic_retrieval_complete=True,
    )
    assessment = score_assessment_confidence(
        llm_review, evidence, coverage=coverage
    )
    return _build_api_review(llm_review, finding_confidences, assessment)
