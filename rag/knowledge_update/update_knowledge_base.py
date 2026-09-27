from rag.knowledge_update.fetch_cwe import (
    fetch_cwe_knowledge,
    CWE_IDS,
)

from rag.knowledge_update.enrich_cwe import (
    load_json,
    enrich_cwe,
    RAW_DIR as ENRICH_RAW_DIR,
    ENRICHED_DIR,
)

from rag.knowledge_update.merge_cwe import (
    CWE_FILES,
    merge_cwe,
    save_json,
    CURATED_DIR,
)

from rag.vector_store.dynamic_build_index import (
    build_dynamic_index,
)


def run_enrichment():
    print("\n" + "=" * 70)
    print("STEP 2: ENRICHING CWE DATA")
    print("=" * 70)

    ENRICHED_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    for cwe_id in CWE_IDS:

        raw_file = (
            ENRICH_RAW_DIR
            / f"CWE-{cwe_id}.json"
        )

        if not raw_file.exists():
            raise FileNotFoundError(
                f"Missing raw CWE file: {raw_file}"
            )

        print(
            f"\nEnriching CWE-{cwe_id}..."
        )

        raw_data = load_json(
            raw_file
        )

        enriched_data = enrich_cwe(
            cwe_id,
            raw_data
        )

        output_file = (
            ENRICHED_DIR
            / f"CWE-{cwe_id}.json"
        )

        save_json(
            enriched_data,
            output_file
        )

        print(
            f"Saved: {output_file}"
        )


def run_merge():
    print("\n" + "=" * 70)
    print("STEP 3: MERGING CURATED KNOWLEDGE")
    print("=" * 70)

    ENRICHED_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    for cwe_id, curated_filename in CWE_FILES.items():

        enriched_file = (
            ENRICHED_DIR
            / f"CWE-{cwe_id}.json"
        )

        curated_file = (
            CURATED_DIR
            / curated_filename
        )

        if not enriched_file.exists():
            raise FileNotFoundError(
                f"Missing enriched file: "
                f"{enriched_file}"
            )

        if not curated_file.exists():
            raise FileNotFoundError(
                f"Missing curated file: "
                f"{curated_file}"
            )

        print(
            f"\nMerging CWE-{cwe_id}..."
        )

        enriched_data = load_json(
            enriched_file
        )

        curated_data = load_json(
            curated_file
        )

        merged_data = merge_cwe(
            cwe_id,
            curated_data,
            enriched_data
        )

        save_json(
            merged_data,
            enriched_file
        )

        print(
            f"Merged curated knowledge "
            f"into CWE-{cwe_id}"
        )


def run_evaluation():

    # Import evaluation only after the FAISS index
    # has been built in Step 4.
    from rag.evaluation.aggregated_retrieval_eval import (
        evaluate,
    )

    print("\n" + "=" * 70)
    print("STEP 5: VALIDATING RETRIEVAL QUALITY")
    print("=" * 70)

    metrics = evaluate()

    print("\n" + "=" * 70)
    print("RETRIEVAL VALIDATION")
    print("=" * 70)

    print(
        f"Recall@1: "
        f"{metrics['recall@1'] * 100:.2f}%"
    )

    print(
        f"Recall@3: "
        f"{metrics['recall@3'] * 100:.2f}%"
    )

    print(
        f"Recall@5: "
        f"{metrics['recall@5'] * 100:.2f}%"
    )

    # Current validated baseline is 100%
    required_recall = 1.0

    if metrics["recall@1"] < required_recall:
        raise RuntimeError(
            "Retrieval regression detected: "
            "Recall@1 dropped below 100%."
        )

    if metrics["recall@3"] < required_recall:
        raise RuntimeError(
            "Retrieval regression detected: "
            "Recall@3 dropped below 100%."
        )

    if metrics["recall@5"] < required_recall:
        raise RuntimeError(
            "Retrieval regression detected: "
            "Recall@5 dropped below 100%."
        )

    print(
        "\nRetrieval validation PASSED."
    )


def run_update():

    print("=" * 70)
    print("DYNAMIC KNOWLEDGE BASE UPDATE")
    print("=" * 70)

    # -----------------------------------------------------
    # STEP 1: Fetch latest CWE data
    # -----------------------------------------------------

    print("\n" + "=" * 70)
    print("STEP 1: FETCHING MITRE CWE DATA")
    print("=" * 70)

    fetch_cwe_knowledge()

    # -----------------------------------------------------
    # STEP 2: Enrich fetched data
    # -----------------------------------------------------

    run_enrichment()

    # -----------------------------------------------------
    # STEP 3: Merge project-specific knowledge
    # -----------------------------------------------------

    run_merge()

    # -----------------------------------------------------
    # STEP 4: Rebuild FAISS index
    # -----------------------------------------------------

    print("\n" + "=" * 70)
    print("STEP 4: BUILDING DYNAMIC FAISS INDEX")
    print("=" * 70)

    build_dynamic_index()

    # -----------------------------------------------------
    # STEP 5: Validate retrieval
    # -----------------------------------------------------

    run_evaluation()

    # -----------------------------------------------------
    # COMPLETE
    # -----------------------------------------------------

    print("\n" + "=" * 70)
    print("KNOWLEDGE BASE UPDATE COMPLETE")
    print("=" * 70)

    print("\nPipeline completed successfully:")
    print("  1. MITRE CWE data fetched")
    print("  2. CWE data enriched")
    print("  3. Curated knowledge merged")
    print("  4. Dynamic FAISS index rebuilt")
    print("  5. Retrieval quality validated")

    print("\nDynamic knowledge base is ready.")


def main():

    try:
        run_update()

    except Exception as error:

        print("\n" + "=" * 70)
        print("KNOWLEDGE BASE UPDATE FAILED")
        print("=" * 70)

        print(
            f"\nError: {error}"
        )

        raise


if __name__ == "__main__":
    main()