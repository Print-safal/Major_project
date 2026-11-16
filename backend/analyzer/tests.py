from unittest.mock import ANY, patch

from django.core.files.uploadedfile import SimpleUploadedFile
from groq import GroqError
from pydantic import ValidationError
from rest_framework.test import APITestCase


class CodeUploadViewTests(APITestCase):
    url = "/api/analyze/"

    def post_file(self, name="sample.py", content=b"print('hello')\n"):
        return self.client.post(
            self.url,
            {"file": SimpleUploadedFile(name, content)},
            format="multipart",
        )

    def test_missing_file_returns_400(self):
        response = self.client.post(self.url, {}, format="multipart")

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {"error": "No file uploaded."})

    def test_non_python_file_returns_400(self):
        response = self.post_file("sample.txt")

        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(), {"error": "Only Python files are allowed."}
        )

    def test_invalid_utf8_returns_400(self):
        response = self.post_file(content=b"print('\xff')")

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {"error": "File must be UTF-8 encoded."})

    @patch("analyzer.views.review_code_with_rag")
    def test_invalid_python_syntax_returns_400_without_review(self, review):
        response = self.post_file(content=b"def broken(:\n    pass\n")

        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json()["error"],
            "Uploaded file contains invalid Python syntax.",
        )
        self.assertEqual(response.json()["line"], 1)
        self.assertIsInstance(response.json()["column"], int)
        self.assertNotIn("backend", response.content.decode("utf-8"))
        review.assert_not_called()

    @patch("analyzer.views.review_code_with_rag")
    def test_oversized_file_returns_413_without_running_review(self, review):
        with self.settings(MAX_SOURCE_UPLOAD_SIZE_BYTES=5):
            response = self.post_file(content=b"123456")

        self.assertEqual(response.status_code, 413)
        self.assertEqual(
            response.json(),
            {"error": "File exceeds the maximum allowed size of 5 bytes."},
        )
        review.assert_not_called()

    @patch(
        "analyzer.views.review_code_with_rag",
        side_effect=RuntimeError("private details"),
    )
    def test_internal_review_failure_returns_generic_500(self, review):
        with self.assertLogs("analyzer.views", level="ERROR"):
            response = self.post_file()

        self.assertEqual(response.status_code, 500)
        self.assertEqual(
            response.json(),
            {"error": "An internal error occurred while processing the file."},
        )
        self.assertNotIn("private details", response.content.decode("utf-8"))
        review.assert_called_once_with("print('hello')\n", context=ANY)

    @patch(
        "analyzer.views.review_code_with_rag",
        side_effect=RuntimeError("private retrieval details"),
    )
    def test_retrieval_failure_returns_generic_500(self, review):
        with self.assertLogs("analyzer.views", level="ERROR"):
            response = self.post_file()

        self.assertEqual(response.status_code, 500)
        self.assertEqual(
            response.json(),
            {"error": "An internal error occurred while processing the file."},
        )
        self.assertNotIn("private retrieval details", response.content.decode("utf-8"))
        review.assert_called_once_with("print('hello')\n", context=ANY)

    @patch("analyzer.views.review_code_with_rag")
    def test_malformed_llm_response_returns_generic_500(self, review):
        from rag_int.llm_service import SecurityReview

        with self.assertRaises(ValidationError) as validation_error:
            SecurityReview.model_validate({
                "vulnerable": "not-a-boolean",
                "vulnerabilities": [],
            })
        review.side_effect = validation_error.exception

        with self.assertLogs("analyzer.views", level="ERROR"):
            response = self.post_file()

        self.assertEqual(response.status_code, 500)
        self.assertEqual(
            response.json(),
            {"error": "An internal error occurred while processing the file."},
        )
        self.assertNotIn("Input should be", response.content.decode("utf-8"))
        review.assert_called_once_with("print('hello')\n", context=ANY)

    @patch(
        "analyzer.views.review_code_with_rag",
        side_effect=GroqError("provider details"),
    )
    def test_provider_failure_returns_generic_502(self, review):
        with self.assertLogs("analyzer.views", level="ERROR"):
            response = self.post_file()

        self.assertEqual(response.status_code, 502)
        self.assertEqual(
            response.json(),
            {"error": "The upstream security review provider failed."},
        )
        self.assertNotIn("provider details", response.content.decode("utf-8"))
        review.assert_called_once_with("print('hello')\n", context=ANY)

    @patch("analyzer.views.review_code_with_rag")
    def test_success_response_remains_unchanged(self, review):
        review.return_value.model_dump.return_value = {
            "vulnerable": True,
            "vulnerabilities": [{
                "cwe": "CWE-89",
                "vulnerability_name": "SQL Injection",
                "location": "line 1",
                "explanation": "User input is interpolated into SQL.",
                "remediation": "Use a parameterized query.",
            }],
        }

        source = "raise RuntimeError('do not execute')\n"
        response = self.post_file(content=source.encode("utf-8"))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {
                "filename": "sample.py",
                "language": "python",
                "review": {
                    "vulnerable": True,
                    "vulnerabilities": [{
                        "cwe": "CWE-89",
                        "vulnerability_name": "SQL Injection",
                        "location": "line 1",
                        "explanation": "User input is interpolated into SQL.",
                        "remediation": "Use a parameterized query.",
                    }],
                },
            },
        )
        review.assert_called_once_with(source, context=ANY)

    @patch("analyzer.views.review_code_with_rag")
    def test_success_response_preserves_fields_and_includes_confidence(self, review):
        from rag_int.llm_service import EnrichedSecurityReview

        review.return_value = EnrichedSecurityReview.model_validate({
            "vulnerable": False,
            "vulnerabilities": [],
            "assessment_confidence": {
                "vulnerable": False,
                "score": None,
                "level": "Undetermined",
                "components": [],
                "finding_confidences": [],
                "supporting_evidence": [],
                "conflicting_evidence": [],
                "explanation": "Insufficient evidence.",
            },
        })
        response = self.post_file(content=b"value = 1\n")

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["filename"], "sample.py")
        self.assertEqual(data["language"], "python")
        self.assertIn("vulnerable", data["review"])
        self.assertIn("vulnerabilities", data["review"])
        self.assertEqual(data["review"]["assessment_confidence"]["level"], "Undetermined")
        self.assertIsNone(data["review"]["assessment_confidence"]["score"])
        review.assert_called_once_with("value = 1\n", context=ANY)
