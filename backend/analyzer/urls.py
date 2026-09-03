from django.urls import path
from .views import CodeUploadView


urlpatterns = [
    path("analyze/", CodeUploadView.as_view()),
]