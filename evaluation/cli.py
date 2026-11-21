from __future__ import annotations

import argparse

from evaluation.pipeline import execute


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Run or resume the Python security evaluation"
    )

    parser.add_argument(
        "--mode",
        required=True,
        choices=("llm-only", "rag-llm"),
    )

    parser.add_argument(
        "--run-id",
        help="Stable ID used to resume the same run",
    )

    parser.add_argument(
        "--limit",
        type=int,
        help="Run only the first N cases",
    )

    parser.add_argument(
        "--case-ids",
        nargs="+",
        help="Run only the specified test case IDs",
    )

    parser.add_argument(
        "--retry-failed",
        action="store_true",
        help="Retry failed and invalid-response cases",
    )

    parser.add_argument(
        "--metrics-only",
        action="store_true",
        help="Regenerate reports without API calls",
    )

    parser.add_argument(
        "--max-rpm",
        type=int,
        default=30,
    )

    parser.add_argument(
        "--max-retries",
        type=int,
        default=5,
    )

    parser.add_argument(
        "--concurrency",
        type=int,
        default=1,
    )

    args = parser.parse_args(argv)

    if args.max_rpm < 1 or args.max_retries < 0:
        parser.error(
            "--max-rpm must be positive and --max-retries nonnegative"
        )

    if args.concurrency < 1:
        parser.error("--concurrency must be at least 1")

    if args.limit is not None and args.case_ids:
        parser.error(
            "--limit and --case-ids cannot be used together"
        )

    result = execute(
        args.mode,
        run_id=args.run_id,
        limit=args.limit,
        case_ids=args.case_ids,
        retry_failed=args.retry_failed,
        max_rpm=args.max_rpm,
        max_retries=args.max_retries,
        concurrency=args.concurrency,
        metrics_only=args.metrics_only,
    )

    print(f"Evaluation output: {result}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())