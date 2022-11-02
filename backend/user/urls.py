from django.contrib import admin
from django.urls import path, include
from django.views.generic import TemplateView
from .views import signup

urlpatterns = [
    path("", TemplateView.as_view(template_name="index.html"), name="home"),
    path("login", TemplateView.as_view(template_name="index.html"), name="login"),
    path("signup", TemplateView.as_view(template_name="index.html"), name="signup"),
    path("signup/new", signup, name="new_user"),
    path("receta/<str:userId>", TemplateView.as_view(template_name="index.html"), name="receta"),
]