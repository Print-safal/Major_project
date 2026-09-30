import ast
import logging

import httpx
from django.conf import settings
from django.core.files.uploadhandler import FileUploadHandler, StopUpload
from groq import GroqError
from rest_framework.views import APIView
from rest_framework.response import Response


logger = logging.getLogger(__name__)


def review_code_with_rag(code):
    """Load and call the existing RAG integration only when a review runs."""
    from rag_int.rag_llm_integration import review_code_with_rag as rag_review

    return rag_review(code)


class SourceSizeLimitUploadHandler(FileUploadHandler):
    """Stop parsing a multipart file as soon as it exceeds the configured cap."""

    def __init__(self, request=None):
        super().__init__(request)
        self.max_size = settings.MAX_SOURCE_UPLOAD_SIZE_BYTES
        self.uploaded_bytes = 0

    def new_file(
        self, field_name, file_name, content_type, content_length,
        charset=None, content_type_extra=None,
    ):
        super().new_file(
            field_name, file_name, content_type, content_length,
            charset, content_type_extra,
        )
        self.uploaded_bytes = 0

    def receive_data_chunk(self, raw_data, start):
        self.uploaded_bytes += len(raw_data)
        if self.uploaded_bytes > self.max_size:
            self.request.source_upload_too_large = True
            raise StopUpload(connection_reset=False)
        return raw_data

    def file_complete(self, file_size):
        # Let Django's configured memory or temporary-file handler create it.
        return None


class CodeUploadView(APIView):

    def post(self, request):
        # Add a streaming guard before DRF parses the multipart request.
        django_request = request._request
        django_request.source_upload_too_large = False
        django_request.upload_handlers.insert(
            0, SourceSizeLimitUploadHandler(django_request)
        )
        uploaded_files = request.FILES

        if django_request.source_upload_too_large:
            return Response(
                {
                    "error": (
                        "File exceeds the maximum allowed size of "
                        f"{settings.MAX_SOURCE_UPLOAD_SIZE_BYTES} bytes."
                    )
                },
                status=413,
            )

        # 1. Get uploaded file
        uploaded_file = uploaded_files.get("file")

        if not uploaded_file:
            return Response(
                {"error": "No file uploaded."},
                status=400
            )

        # 2. Validate Python file
        if not uploaded_file.name.endswith(".py"):
            return Response(
                {"error": "Only Python files are allowed."},
                status=400
            )

        # 3. Read Python source code
        try:
            code = uploaded_file.read().decode("utf-8")
        except UnicodeDecodeError:
            return Response(
                {"error": "File must be UTF-8 encoded."},
                status=400
            )

        try:
            ast.parse(code)
        except SyntaxError as exc:
            error = {"error": "Uploaded file contains invalid Python syntax."}
            if exc.lineno is not None:
                error["line"] = exc.lineno
            if exc.offset is not None:
                error["column"] = exc.offset
            return Response(error, status=400)

        try:
            review = review_code_with_rag(code)
        except (GroqError, httpx.HTTPError, TimeoutError, ConnectionError):
            logger.exception("Upstream provider failed during security review.")
            return Response(
                {"error": "The upstream security review provider failed."},
                status=502,
            )
        except Exception:
            logger.exception("Unexpected error during security review.")
            return Response(
                {"error": "An internal error occurred while processing the file."},
                status=500,
            )

        # 6. Return structured response
        return Response({
            "filename": uploaded_file.name,
            "language": "python",
            "review": review.model_dump()
        })
