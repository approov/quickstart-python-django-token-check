from django.urls import path

from . import views

urlpatterns = [
    path("", views.home, name="home"),
    path("approov-state", views.approov_state, name="approov_state"),
    path("approov/enable", views.enable_approov_endpoint, name="enable_approov"),
    path("approov/disable", views.disable_approov_endpoint, name="disable_approov"),
    path(
        "token-binding/enable",
        views.enable_token_binding_endpoint,
        name="enable_token_binding",
    ),
    path(
        "token-binding/disable",
        views.disable_token_binding_endpoint,
        name="disable_token_binding",
    ),
    path("unprotected", views.unprotected, name="unprotected"),
    path("token-check", views.token_check, name="token_check"),
    path("token-binding", views.token_binding, name="token_binding"),
    path("token-double-binding", views.token_double_binding, name="token_double_binding"),
]
