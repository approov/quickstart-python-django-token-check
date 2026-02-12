from __future__ import annotations

import os
from typing import Any

from django.http import HttpRequest, JsonResponse
from django.views.decorators.http import require_GET, require_POST

from .approov_service import (
    AUTH_HEADER,
    SESSION_ID_HEADER,
    get_approov_service,
    has_text,
)

approov_service = get_approov_service()


def json_response(payload: dict[str, Any], status: int = 200) -> JsonResponse:
    # Keep output compact to preserve compatibility with existing shell-based checks.
    return JsonResponse(
        payload,
        status=status,
        json_dumps_params={"separators": (",", ":")},
    )


def state_payload() -> dict[str, bool]:
    return approov_service.state()


def info_payload(details: str) -> dict[str, Any]:
    payload: dict[str, Any] = state_payload()
    payload["details"] = details
    return payload


@require_GET
def home(request: HttpRequest) -> JsonResponse:
    port = os.getenv("HTTP_PORT", "8080")
    return json_response(
        info_payload(f"Approov demo API is running on port {port}."),
        status=200,
    )


@require_GET
def approov_state(request: HttpRequest) -> JsonResponse:
    return json_response(state_payload(), status=200)


@require_POST
def enable_approov_endpoint(request: HttpRequest) -> JsonResponse:
    return json_response(approov_service.enable_approov(), status=200)


@require_POST
def disable_approov_endpoint(request: HttpRequest) -> JsonResponse:
    return json_response(approov_service.disable_approov(), status=200)


@require_POST
def enable_token_binding_endpoint(request: HttpRequest) -> JsonResponse:
    return json_response(approov_service.enable_token_binding(), status=200)


@require_POST
def disable_token_binding_endpoint(request: HttpRequest) -> JsonResponse:
    return json_response(approov_service.disable_token_binding(), status=200)


@require_GET
def unprotected(request: HttpRequest) -> JsonResponse:
    return json_response(
        info_payload(
            "Unprotected endpoint '/unprotected'; no Approov checks performed."
        ),
        status=200,
    )


@require_GET
def token_check(request: HttpRequest) -> JsonResponse:
    return json_response(
        info_payload("Protected endpoint '/token-check'; Approov token verified."),
        status=200,
    )


@require_GET
def token_binding(request: HttpRequest) -> JsonResponse:
    response = info_payload(
        "Protected endpoint '/token-binding'; Approov token binding enforced."
    )
    response["authorizationHeaderPresent"] = has_text(request.headers.get(AUTH_HEADER))
    return json_response(response, status=200)


@require_GET
def token_double_binding(request: HttpRequest) -> JsonResponse:
    response = info_payload(
        "Protected endpoint '/token-double-binding'; dual token binding enforced."
    )
    response["authorizationHeaderPresent"] = has_text(request.headers.get(AUTH_HEADER))
    response["sessionIdHeaderPresent"] = has_text(
        request.headers.get(SESSION_ID_HEADER)
    )
    return json_response(response, status=200)
