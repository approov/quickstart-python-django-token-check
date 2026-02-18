from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from typing import Final

from django.http import HttpRequest, HttpResponse, JsonResponse

from .approov_service import (
    AUTH_HEADER,
    SESSION_ID_HEADER,
    get_approov_service,
    required_headers_for_request,
    summarize_error,
)


@dataclass(frozen=True)
class ProtectedRoute:
    bound_headers: tuple[str, ...]


PROTECTED_ROUTES: Final[dict[str, ProtectedRoute]] = {
    "/token-check": ProtectedRoute(bound_headers=()),
    "/token-binding": ProtectedRoute(bound_headers=(AUTH_HEADER,)),
    "/token-double-binding": ProtectedRoute(
        bound_headers=(AUTH_HEADER, SESSION_ID_HEADER)
    ),
}


class ApproovMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        self.service = get_approov_service()
        self.logger = logging.getLogger("approov.http")

    def __call__(self, request: HttpRequest) -> HttpResponse:
        route = PROTECTED_ROUTES.get(request.path)
        summary = "request_completed"
        required_headers: list[str] = []
        error: str | None = None

        if route is not None:
            state = self.service.state()
            required_headers = required_headers_for_request(
                bound_headers=route.bound_headers,
                token_binding_enabled=state["tokenBindingEnabled"],
                approov_header=self.service.token_header,
            )

            if not state["approovEnabled"]:
                summary = "approov_disabled"
                request.approov_claims = {}
            else:
                active_bound_headers = (
                    route.bound_headers if state["tokenBindingEnabled"] else ()
                )
                verification_result = self.service.verify_approov_request(
                    request,
                    token_check=True,
                    bound_headers=active_bound_headers,
                )
                if verification_result.error is not None:
                    summary = (
                        f"approov_failed:{summarize_error(verification_result.error)}"
                    )
                    error = verification_result.error
                    response = JsonResponse({"message": "Unauthorized"}, status=401)
                    return self._finalize_response(
                        request,
                        response,
                        summary,
                        required_headers,
                        error,
                    )

                request.approov_claims = verification_result.claims or {}
                summary = "approov_ok"
        else:
            request.approov_claims = {}

        response = self.get_response(request)

        if response.status_code == 401 and summary == "approov_ok":
            summary = "approov_failed:downstream_unauthorized"

        return self._finalize_response(
            request, response, summary, required_headers, error
        )

    def _finalize_response(
        self,
        request: HttpRequest,
        response: HttpResponse,
        summary: str,
        required_headers: list[str],
        error: str | None,
    ) -> HttpResponse:
        if response.status_code in (200, 401):
            self._log_http_request_completed(
                request,
                response,
                summary,
                required_headers,
                error,
            )
        return response

    def _request_server_port(self, request: HttpRequest) -> int:
        server_port = request.META.get("SERVER_PORT")
        if isinstance(server_port, str):
            normalized = server_port.strip()
            if normalized:
                try:
                    return int(normalized)
                except ValueError:
                    pass

        configured_port = os.getenv("HTTP_PORT", "8080")
        try:
            return int(configured_port)
        except ValueError:
            return 8080

    def _log_http_request_completed(
        self,
        request: HttpRequest,
        response: HttpResponse,
        summary: str,
        required_headers: list[str],
        error: str | None,
    ) -> None:
        state = self.service.state()
        payload = {
            "summary": summary,
            "method": request.method,
            "path": request.path,
            "status": response.status_code,
            "ip": request.META.get("REMOTE_ADDR", "") or "",
            "port": self._request_server_port(request),
            "approovEnabled": state["approovEnabled"],
            "tokenBindingEnabled": state["tokenBindingEnabled"],
            "required_headers": required_headers,
        }

        if error:
            payload["error"] = error

        message = "http.request.completed " + json.dumps(payload, separators=(",", ":"))

        if response.status_code == 401:
            self.logger.warning(message)
        else:
            self.logger.info(message)
