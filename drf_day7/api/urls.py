from django.conf.urls import url
from django.urls import path
from rest_framework_jwt.views import ObtainJSONWebToken, obtain_jwt_token

from api import views

urlpatterns = [
    url(r"login/", ObtainJSONWebToken.as_view()),
    url(r"obt/", obtain_jwt_token),
    path("user/", views.UserDetailAPIView.as_view()),
    path("check/", views.LoginAPIView.as_view()),
]
