import json
from pathlib import Path
from urllib.request import Request, urlopen


BASE_URL = "https://cwe-api.mitre.org/api/v1"

CWE_IDS = [
    "22",
    "78",
    "79",
    "89",
    "798",
]

BASE_DIR = Path(__file__).resolve().parents[1]
RAW_DIR = BASE_DIR / "knowledge_base" / "raw"


def fetch_json(url):
    request = Request(
        url,
        headers={
            "User-Agent": "Major-Project-RAG/1.0"
        }
    )

    with urlopen(request, timeout=30) as response:
        return json.loads(
            response.read().decode("utf-8")
        )


def save_json(data, filename):
    output_path = RAW_DIR / filename

    with open(
        output_path,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            data,
            file,
            indent=2,
            ensure_ascii=False
        )

    return output_path


def fetch_cwe_knowledge():
    """
    Fetch the current CWE data from the MITRE CWE API
    and save it into the local raw knowledge base.
    """

    RAW_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    print("=" * 60)
    print("CWE KNOWLEDGE BASE FETCHER")
    print("=" * 60)

    print("\nFetching CWE API version...")

    version_data = fetch_json(
        f"{BASE_URL}/cwe/version"
    )

    save_json(
        version_data,
        "source_metadata.json"
    )

    print(
        "CWE version information saved."
    )

    successful = 0
    failed = 0

    for cwe_id in CWE_IDS:

        print(
            f"\nFetching CWE-{cwe_id}..."
        )

        url = (
            f"{BASE_URL}/cwe/weakness/"
            f"{cwe_id}"
        )

        try:

            data = fetch_json(url)

            filename = (
                f"CWE-{cwe_id}.json"
            )

            output_path = save_json(
                data,
                filename
            )

            print(
                f"Saved: {output_path}"
            )

            successful += 1

        except Exception as error:

            print(
                f"ERROR fetching "
                f"CWE-{cwe_id}: {error}"
            )

            failed += 1

    print("\n" + "=" * 60)
    print("FETCH COMPLETE")
    print("=" * 60)

    print(
        f"Successful: {successful}"
    )

    print(
        f"Failed: {failed}"
    )

    print(
        f"Raw knowledge base: {RAW_DIR}"
    )

    if failed > 0:
        raise RuntimeError(
            f"Failed to fetch {failed} CWE entries."
        )


def main():
    fetch_cwe_knowledge()


if __name__ == "__main__":
    main()