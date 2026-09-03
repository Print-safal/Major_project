from django.shortcuts import render

# Create your views here.
from rest_framework.views import APIView
from rest_framework.response import Response


class CodeUploadView(APIView):

    def post(self, request):
        uploaded_file = request.FILES.get("file")

        if not uploaded_file:
            return Response(
                {"error": "No file uploaded."},
                status=400
            )

        if not uploaded_file.name.endswith(".py"):
            return Response(
                {"error": "Only Python files are allowed."},
                status=400
            )

        code = uploaded_file.read().decode("utf-8")

        return Response({
            "filename": uploaded_file.name,
            "language": "python",
            "code": code
        })