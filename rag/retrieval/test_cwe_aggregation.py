from collections import defaultdict

from rag.retrieval.hybrid_retriever import semantic_search
from rag.retrieval.security_profiles import (
    SECURITY_PROFILES,
    calculate_security_signal,
    calculate_secure_signal,
)


# Evidence importance for security-code review.
#
# Vulnerable evidence should be prioritized because it
# directly supports the presence of a vulnerability.
#
# Secure examples are still useful, but mainly as
# contrastive evidence.
EVIDENCE_WEIGHTS = {
    "vulnerable_patterns": 1.15,
    "vulnerable_examples": 1.15,
    "detection_indicators": 1.10,
    "mitre_detectionmethods": 1.05,
    "mitre_description": 1.00,
    "mitre_extendeddescription": 1.00,
    "common_causes": 1.00,
    "remediation": 0.90,
    "secure_patterns": 0.85,
    "secure_examples": 0.75,
    "keywords": 0.60,
}


# A strong explicit mitigation should suppress
# a CWE candidate rather than merely lowering its score.
SECURE_SIGNAL_THRESHOLD = 1.0


def get_evidence_weight(section):
    """
    Return the importance assigned to a knowledge section.
    """

    return EVIDENCE_WEIGHTS.get(
        section,
        1.00
    )


def aggregate_cwe_results(
    query,
    candidate_k=30,
    top_k=5
):
    """
    Retrieve knowledge chunks, combine semantic and
    security-pattern evidence, then aggregate results
    at the CWE level.

    Explicit secure patterns can suppress a CWE
    candidate when the mitigation signal is strong.
    """

    # -----------------------------------------------------
    # 1. Semantic retrieval
    # -----------------------------------------------------

    candidates = semantic_search(
        query,
        top_k=candidate_k
    )

    # -----------------------------------------------------
    # 2. Security signals
    # -----------------------------------------------------

    security_scores = {}
    secure_scores = {}

    for cwe_id in SECURITY_PROFILES:

        security_scores[cwe_id] = (
            calculate_security_signal(
                query,
                cwe_id
            )
        )

        secure_scores[cwe_id] = (
            calculate_secure_signal(
                query,
                cwe_id
            )
        )

    # -----------------------------------------------------
    # 3. Score every retrieved chunk
    # -----------------------------------------------------

    for result in candidates:

        cwe_id = result["cwe_id"]

        semantic_score = result[
            "semantic_score"
        ]

        security_score = security_scores.get(
            cwe_id,
            0.0
        )

        secure_score = secure_scores.get(
            cwe_id,
            0.0
        )

        evidence_weight = get_evidence_weight(
            result["section"]
        )

        base_score = (
            0.70 * semantic_score
            + 0.30 * security_score
        )

        evidence_score = (
            base_score
            * evidence_weight
        )

        result["security_score"] = (
            security_score
        )

        result["secure_score"] = (
            secure_score
        )

        result["evidence_weight"] = (
            evidence_weight
        )

        result["combined_score"] = (
            evidence_score
        )

    # -----------------------------------------------------
    # 4. Group chunks by CWE
    # -----------------------------------------------------

    grouped = defaultdict(list)

    for result in candidates:
        grouped[result["cwe_id"]].append(
            result
        )

    # -----------------------------------------------------
    # 5. Calculate CWE-level scores
    # -----------------------------------------------------

    cwe_results = []

    for cwe_id, results in grouped.items():

        results.sort(
            key=lambda item: item[
                "combined_score"
            ],
            reverse=True
        )

        top_chunks = results[:5]

        # Strongest evidence
        max_score = top_chunks[0][
            "combined_score"
        ]

        # Supporting evidence
        average_score = sum(
            item["combined_score"]
            for item in top_chunks
        ) / len(top_chunks)

        # Number of strong vulnerability indicators
        vulnerable_evidence = [
            item
            for item in results
            if item["section"] in {
                "vulnerable_patterns",
                "vulnerable_examples",
                "detection_indicators",
                "mitre_detectionmethods",
            }
        ]

        vulnerable_support = min(
            len(vulnerable_evidence) / 3,
            1.0
        )

        # Explicit mitigation signal
        secure_score = secure_scores[
            cwe_id
        ]

        is_suppressed = (
            secure_score
            >= SECURE_SIGNAL_THRESHOLD
        )

        # Final CWE score
        cwe_score = (
            0.65 * max_score
            + 0.20 * average_score
            + 0.15 * vulnerable_support
        )

        cwe_results.append({
            "cwe_id": cwe_id,
            "cwe_name": SECURITY_PROFILES[
                cwe_id
            ]["name"],
            "score": cwe_score,
            "security_score": security_scores[
                cwe_id
            ],
            "secure_score": secure_score,
            "suppressed": is_suppressed,
            "supporting_chunks": top_chunks,
            "supporting_chunk_count": len(
                results
            ),
            "vulnerable_evidence_count": len(
                vulnerable_evidence
            ),
        })

    # -----------------------------------------------------
    # 6. Remove explicitly suppressed CWEs
    # -----------------------------------------------------

    cwe_results = [
        result
        for result in cwe_results
        if not result["suppressed"]
    ]

    # -----------------------------------------------------
    # 7. Rank CWEs
    # -----------------------------------------------------

    cwe_results.sort(
        key=lambda item: item["score"],
        reverse=True
    )

    return cwe_results[:top_k]


if __name__ == "__main__":

    print("=" * 70)
    print("CWE-LEVEL AGGREGATED RETRIEVAL")
    print("=" * 70)

    query = input(
        "\nEnter Python code/security query:\n"
    )

    results = aggregate_cwe_results(
        query,
        candidate_k=30,
        top_k=5
    )

    print("\n" + "=" * 70)
    print("RANKED CWEs")
    print("=" * 70)

    if not results:
        print("\nNo unsuppressed CWE candidates found.")

    for rank, result in enumerate(
        results,
        start=1
    ):

        print(
            f"\nRank {rank}: "
            f"{result['cwe_id']} - "
            f"{result['cwe_name']}"
        )

        print(
            f"CWE Score: "
            f"{result['score']:.4f}"
        )

        print(
            f"Security Signal: "
            f"{result['security_score']:.4f}"
        )

        print(
            f"Secure Signal: "
            f"{result['secure_score']:.4f}"
        )

        print(
            f"Suppressed: "
            f"{result['suppressed']}"
        )

        print(
            f"Supporting chunks: "
            f"{result['supporting_chunk_count']}"
        )

        print(
            f"Vulnerability evidence: "
            f"{result['vulnerable_evidence_count']}"
        )

        print("\nTop supporting evidence:")

        for chunk in result[
            "supporting_chunks"
        ][:3]:

            print(
                f"  - {chunk['section']} "
                f"(score="
                f"{chunk['combined_score']:.4f}, "
                f"weight="
                f"{chunk['evidence_weight']:.2f})"
            )

            print(
                f"    {chunk['text'][:180]}"
            )