from rest_framework.views import APIView
from rest_framework.response import Response

from rag.retrieval.rag_retriever import retrieve_security_context
from rag_int.llm_service import review_code


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

        # 4. Retrieve relevant security knowledge using RAG
        retrieved = retrieve_security_context(
            code,
            top_k=5
        )

        # 5. Analyze code using LLM + retrieved security context
        review = review_code(
            code=code,
            security_context=retrieved["context"]
        )

        # 6. Return structured response
        return Response({
            "filename": uploaded_file.name,
            "language": "python",
            "review": review.model_dump()
        })