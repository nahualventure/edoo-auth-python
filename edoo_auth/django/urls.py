from django.urls import path
from edoo_auth.django import views

urlpatterns = [
    path("login/", views.login, name="edoo_auth_login"),
    path("callback/", views.callback, name="edoo_auth_callback"),
    path("logout/", views.logout, name="edoo_auth_logout"),
    path("switch/", views.switch_account, name="edoo_auth_switch"),
    path("switch-school/", views.switch_school, name="edoo_auth_switch_school"),
]
