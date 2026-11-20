"""Diagnostic contextual matching and shadow evidence ranking.

Nothing in this module changes the production aggregator or its ranking formula.
All code-derived matches are indicators for review, not vulnerability findings.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Literal, Optional, Sequence

from rag.analysis.ast_context import CodeContext, SourceSpan, extract_code_context
from rag.retrieval.security_profiles import (
    SECURITY_PROFILES,
    get_contextual_security_evidence,
    get_matched_secure_indicators,
    get_matched_vulnerability_indicators,
)


IndicatorType = Literal["vulnerable", "secure", "contextual"]
EvidenceKind = Literal["semantic", "vulnerable", "secure", "contextual"]


@dataclass(frozen=True)
class ContextualMatch:
    cwe_id: str
    indicator_type: IndicatorType
    evidence: str
    location: Optional[SourceSpan]
    certainty: str
    explanation: str
    provenance: str


@dataclass(frozen=True)
class EvidenceItem:
    cwe_id: str
    kind: EvidenceKind
    evidence: str
    provenance: str
    score: Optional[float] = None
    location: Optional[SourceSpan] = None
    explanation: str = ""


@dataclass(frozen=True)
class ShadowCWEResult:
    cwe_id: str
    semantic_max_score: Optional[float]
    semantic_candidate_count: int
    contextual_match_count: int
    vulnerable_match_count: int
    secure_match_count: int
    evidence: tuple[EvidenceItem, ...]
    shadow_order_key: tuple[float, int, int]


def _locate_pattern(source: str, pattern: str) -> Optional[SourceSpan]:
    match = re.search(pattern, source, re.IGNORECASE)
    if match is None:
        return None
    start = match.start()
    end = match.end()
    line_start = source.count("\n", 0, start) + 1
    line_end = source.count("\n", 0, end) + 1
    line_offset = source.rfind("\n", 0, start)
    end_offset = source.rfind("\n", 0, end)
    return SourceSpan(line_start, start - line_offset - 1, line_end,
                      end - end_offset - 1)


def match_context(context: CodeContext) -> list[ContextualMatch]:
    """Match existing CWE indicators against AST-derived code context.

    Existing profile helpers remain the source of regex indicator behavior.
    AST call/assignment facts add structured evidence and source locations.
    Match certainty is intentionally qualitative; a match is not a probability.
    """
    if context.parse_error is not None:
        return []
    source = context.source
    matches: list[ContextualMatch] = []

    def add(cwe: str, kind: IndicatorType, evidence: str,
            location: Optional[SourceSpan], explanation: str, provenance: str):
        matches.append(ContextualMatch(cwe, kind, evidence, location,
                                       "syntactic_indicator", explanation, provenance))

    for cwe_id, profile in SECURITY_PROFILES.items():
        for pattern in get_matched_vulnerability_indicators(source, cwe_id):
            add(cwe_id, "vulnerable", pattern, _locate_pattern(source, pattern),
                "An existing vulnerable-indicator pattern matched source text; this is not proof of exploitability.",
                "security_profiles.patterns")
        for pattern in get_matched_secure_indicators(source, cwe_id):
            add(cwe_id, "secure", pattern, _locate_pattern(source, pattern),
                "An existing secure-indicator pattern matched; verify that it protects the relevant operation.",
                "security_profiles.secure_patterns")
        for evidence in get_contextual_security_evidence(source, cwe_id):
            add(cwe_id, "contextual", evidence, None,
                "Existing contextual diagnostic matched; its safety depends on surrounding code and usage.",
                "security_profiles.contextual")

    # AST evidence helps identify structured indicators that regex profiles do
    # not fully represent, while retaining a low-claim interpretation.
    for assignment in context.assignments:
        for cwe_id in assignment.cwe_categories:
            add(cwe_id, "vulnerable", assignment.expression, assignment.span,
                "Credential-like literal assignment detected syntactically; inspect the value and use context.",
                "ast.assignment")
    for call in context.calls:
        for cwe_id in call.cwe_categories:
            add(cwe_id, "contextual", call.call_name, call.span,
                "Security-sensitive call detected; the call alone does not establish unsafe input or exploitability.",
                "ast.call")
        for safeguard in call.safeguards:
            cwes = ("CWE-89",) if "SQL" in safeguard else (
                ("CWE-78",) if "subprocess" in safeguard else
                (("CWE-79",) if "escap" in safeguard or "sanit" in safeguard else
                 (("CWE-22",) if "path" in safeguard else ()))
            )
            for cwe_id in cwes:
                add(cwe_id, "secure", safeguard, call.span,
                    "AST recognized a possible safeguard; correctness and coverage are not verified.",
                    "ast.safeguard")

    for flow in context.flows:
        for cwe_id in flow.cwe_categories:
            add(cwe_id, "contextual", f"{flow.source} → {flow.sink}", flow.span,
                flow.uncertainty, "ast.source_to_sink_candidate")

    # Deduplicate equivalent evidence while retaining distinct provenance.
    unique = {}
    for match in matches:
        key = (match.cwe_id, match.indicator_type, match.evidence,
               match.location, match.provenance)
        unique[key] = match
    return list(unique.values())


def build_shadow_retrieval(
    code: str,
    *,
    query: Optional[str] = None,
    semantic_candidates: Optional[Sequence[dict[str, Any]]] = None,
    context: Optional[CodeContext] = None,
    top_k: int = 5,
) -> list[ShadowCWEResult]:
    """Combine FAISS candidates and contextual evidence for diagnostic comparison.

    If ``semantic_candidates`` is omitted, the existing ``semantic_search``
    implementation is called lazily. The returned shadow order is lexicographic:
    maximum existing semantic score, then contextual match count, then candidate
    count. No new weights or confidence values are introduced. This output is
    not consumed by the production LLM pipeline.
    """
    if semantic_candidates is None:
        from rag.retrieval.hybrid_retriever import semantic_search
        semantic_candidates = semantic_search(query if query is not None else code, top_k=20)

    context = context if context is not None else extract_code_context(code)
    matches = match_context(context)
    by_cwe: dict[str, list[EvidenceItem]] = {cwe: [] for cwe in SECURITY_PROFILES}
    semantic_counts = {cwe: 0 for cwe in SECURITY_PROFILES}
    semantic_scores: dict[str, list[float]] = {cwe: [] for cwe in SECURITY_PROFILES}

    for candidate in semantic_candidates:
        cwe = candidate.get("cwe_id")
        if cwe not in by_cwe:
            continue
        score = candidate.get("semantic_score")
        score = float(score) if score is not None else None
        semantic_counts[cwe] += 1
        if score is not None:
            semantic_scores[cwe].append(score)
        # Documents are explicitly provenance-bearing reference material only.
        by_cwe[cwe].append(EvidenceItem(cwe, "semantic",
            str(candidate.get("text", "")),
            f"faiss:{candidate.get('source', 'unknown')}#{candidate.get('section', 'unknown')}",
            score=score, explanation="Retrieved CWE knowledge; supporting context only, not proof of a code vulnerability."))

    for match in matches:
        by_cwe[match.cwe_id].append(EvidenceItem(match.cwe_id, match.indicator_type,
            match.evidence, match.provenance, location=match.location,
            explanation=match.explanation))

    results = []
    for cwe, items in by_cwe.items():
        # Defensive deduplication across semantic and contextual inputs.
        deduped = {}
        for item in items:
            key = (item.kind, item.evidence, item.provenance, item.location)
            deduped[key] = item
        items = list(deduped.values())
        vuln_count = sum(item.kind == "vulnerable" for item in items)
        secure_count = sum(item.kind == "secure" for item in items)
        context_count = sum(item.kind == "contextual" for item in items)
        max_score = max(semantic_scores[cwe]) if semantic_scores[cwe] else None
        # Existing semantic score is primary; contextual evidence is a tie-break
        # diagnostic only. Candidate presence distinguishes no retrieval evidence.
        order_key = (max_score if max_score is not None else float("-inf"),
                     context_count + vuln_count + secure_count, semantic_counts[cwe])
        results.append(ShadowCWEResult(cwe, max_score, semantic_counts[cwe],
            context_count + vuln_count + secure_count, vuln_count, secure_count,
            tuple(items), order_key))
    results.sort(key=lambda result: result.shadow_order_key, reverse=True)
    return results[:top_k]
