from rag.retrieval.cwe_aggregator import aggregate_cwe_results
from rag_int.llm_service import review_code


def format_rag_context(rag_results):
    """
    Convert ranked RAG results into concise security
    context for the LLM.
    """

    if not rag_results:
        return "No relevant security evidence was retrieved."

    context_parts = []

    for result in rag_results:
        context_parts.append(
            f"CWE: {result['cwe_id']} - {result['cwe_name']}\n"
            f"CWE Score: {result['score']:.4f}\n"
            f"Security Signal: {result['security_score']:.4f}\n"
            f"Vulnerability Evidence Count: "
            f"{result['vulnerable_evidence_count']}\n"
        )

        # Only send the strongest few evidence chunks.
        for chunk in result.get("supporting_chunks", [])[:3]:
            context_parts.append(
                f"Evidence Type: "
                f"{chunk.get('section', 'unknown')}\n"
                f"Evidence: "
                f"{chunk.get('text', '')}\n"
            )

        context_parts.append("")

    return "\n".join(context_parts)


def review_code_with_rag(code: str):
    """
    Retrieve CWE evidence using RAG and pass the
    formatted evidence to the existing LLM.
    """

    # 1. Retrieve ranked CWE evidence
    rag_results = aggregate_cwe_results(
        code,
        candidate_k=30,
        top_k=5
    )

    # 2. Convert RAG results to LLM context
    security_context = format_rag_context(
        rag_results
    )

    # 3. Send code + RAG context to the LLM
    return review_code(
        code=code,
        security_context=security_context
    )