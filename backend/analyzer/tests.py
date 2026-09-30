from unittest.mock import patch

from django.core.files.uploadedfile import SimpleUploadedFile
from groq import GroqError
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
        review.assert_called_once_with("print('hello')\n")

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
        review.assert_called_once_with("print('hello')\n")

    @patch("analyzer.views.review_code_with_rag")
    def test_success_response_remains_unchanged(self, review):
        review.return_value.model_dump.return_value = {
            "vulnerable": False,
            "vulnerabilities": [],
        }

        source = "raise RuntimeError('do not execute')\n"
        response = self.post_file(content=source.encode("utf-8"))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {
                "filename": "sample.py",
                "language": "python",
                "review": {"vulnerable": False, "vulnerabilities": []},
            },
        )
        review.assert_called_once_with(source)
