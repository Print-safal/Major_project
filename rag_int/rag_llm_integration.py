import time

from rag.retrieval.cwe_aggregator import aggregate_cwe_results
from rag_int.llm_service import review_code


# Stores timing information for the most recent RAG retrieval.
LAST_RAG_STATS = {}


def format_rag_context(rag_results):
    """
    Format the top retrieved CWE results and supporting
    evidence into context for the LLM.
    """

    if not rag_results:
        return "No relevant security evidence was retrieved."

    context_parts = []

    # Include the top 2 retrieved CWE results.
    for result in rag_results[:2]:

        context_parts.append(
            f"CWE: {result['cwe_id']} - {result['cwe_name']}\n"
            f"CWE Score: {result['score']:.4f}\n"
            f"Security Signal: {result['security_score']:.4f}\n"
            f"Vulnerability Evidence Count: "
            f"{result['vulnerable_evidence_count']}\n"
        )

        # Include supporting evidence for each retrieved CWE.
        for chunk in result.get("supporting_chunks", [])[:1]:

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
    Retrieve relevant CWE evidence using RAG,
    measure retrieval time, and pass evidence to the LLM.
    """

    LAST_RAG_STATS.clear()

    # 1. Measure RAG retrieval time.
    retrieval_start = time.perf_counter()

    rag_results = aggregate_cwe_results(
        code,
        candidate_k=30,
        top_k=5
    )

    retrieval_latency = time.perf_counter() - retrieval_start

    LAST_RAG_STATS.update({
        "retrieval_latency_seconds": retrieval_latency
    })

    # 2. Format retrieved security evidence.
    security_context = format_rag_context(rag_results)

    # 3. Send source code and RAG context to the LLM.
    return review_code(
        code=code,
        security_context=security_context
    )