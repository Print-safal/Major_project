from rest_framework.views import APIView
from rest_framework.response import Response

from rag_int.rag_llm_integration import review_code_with_rag


class CodeUploadView(APIView):

    def post(self, request):
        # 1. Get uploaded file
        uploaded_file = request.FILES.get("file")

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

        review = review_code_with_rag(code)

        # 6. Return structured response
        return Response({
            "filename": uploaded_file.name,
            "language": "python",
            "review": review.model_dump()
        })