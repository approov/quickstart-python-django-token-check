from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import logging
import os
import threading
from dataclasses import dataclass
from typing import Any, Final, Mapping, Sequence, TypeGuard

import jwt

APPROOV_HEADER = "Approov-Token"
AUTH_HEADER = "Authorization"
SESSION_ID_HEADER = "SessionId"
PLACEHOLDER_SECRET = "approov_base64url_secret_here"
JWT_ALGORITHM: Final[str] = "HS256"
REQUIRED_TOKEN_CLAIMS: Final[tuple[str, ...]] = ("exp",)
SECRET_NOT_SET_ERROR = "Required secret is not set"
SECRET_INVALID_ERROR = "Required secret is invalid"

_logger = logging.getLogger("approov")


@dataclass(frozen=True, slots=True)
class VerificationResult:
    error: str | None
    claims: dict[str, Any] | None

    @classmethod
    def success(cls, claims: dict[str, Any]) -> VerificationResult:
        return cls(error=None, claims=claims)

    @classmethod
    def failure(cls, error: str) -> VerificationResult:
        return cls(error=error, claims=None)


def has_text(value: str | None) -> TypeGuard[str]:
    return value is not None and value.strip() != ""


def _decode_base64url(secret: str) -> bytes:
    padding = "=" * (-len(secret) % 4)
    return base64.urlsafe_b64decode(secret + padding)


def _normalize_base64url(value: str) -> str:
    return value.strip().replace("+", "-").replace("/", "_").rstrip("=")


def _raise_config_error(message: str) -> None:
    _logger.error(message)
    raise RuntimeError(message)


def load_approov_secret_from_env() -> bytes:
    raw_secret = os.getenv("APPROOV_BASE64URL_SECRET")
    if not has_text(raw_secret):
        _raise_config_error(SECRET_NOT_SET_ERROR)

    normalized_secret = raw_secret.strip()
    if normalized_secret == PLACEHOLDER_SECRET:
        _raise_config_error(SECRET_NOT_SET_ERROR)

    try:
        decoded = _decode_base64url(normalized_secret)
    except (binascii.Error, ValueError):
        _raise_config_error(SECRET_INVALID_ERROR)

    if len(decoded) < 32:
        _raise_config_error(SECRET_INVALID_ERROR)

    return decoded


def build_token_binding_string(
    headers: Mapping[str, str],
    bound_headers: Sequence[str],
) -> tuple[str | None, str | None]:
    if not bound_headers:
        return "[approov] binding headers not specified", None

    values: list[str] = []
    for header in bound_headers:
        header_value = headers.get(header)
        if not has_text(header_value):
            return f"[approov] bound header '{header}' does not exist", None
        values.append(header_value.strip())

    # Helper function: construct the token binding input string
    return None, "".join(values)


def sha256_b64url_from_str(value: str) -> str:
    digest = hashlib.sha256(value.encode("utf-8")).digest()
    # Helper function: hash input and encode as base64url
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def binding_matches(pay_claim: str, computed_hash: str) -> bool:
    return hmac.compare_digest(
        _normalize_base64url(pay_claim),
        _normalize_base64url(computed_hash),
    )


def summarize_error(error: str) -> str:
    if error.startswith("[approov] missing ") and error.endswith(" header"):
        return "missing_approov_token"
    if "bound header" in error and "does not exist" in error:
        return "missing_binding_header"
    if "hash mismatch" in error or "does not have a 'pay' claim" in error:
        return "binding_mismatch"
    return "token_verification_failed"


def required_headers_for_request(
    bound_headers: Sequence[str],
    token_binding_enabled: bool,
    approov_header: str = APPROOV_HEADER,
) -> list[str]:
    if (not token_binding_enabled) or (not bound_headers):
        return [approov_header]

    return [approov_header, *list(bound_headers)]


class ApproovService:
    def __init__(
        self,
        secret: bytes,
        token_header: str = APPROOV_HEADER,
        approov_enabled: bool = True,
        token_binding_enabled: bool = True,
    ) -> None:
        self._secret = secret
        self._token_header = token_header
        self._approov_enabled = approov_enabled
        self._token_binding_enabled = token_binding_enabled
        self._lock = threading.Lock()

    @property
    def token_header(self) -> str:
        return self._token_header

    def is_approov_enabled(self) -> bool:
        with self._lock:
            return self._approov_enabled

    def is_token_binding_enabled(self) -> bool:
        with self._lock:
            return self._token_binding_enabled

    def state(self) -> dict[str, bool]:
        with self._lock:
            return {
                "approovEnabled": self._approov_enabled,
                "tokenBindingEnabled": self._token_binding_enabled,
            }

    def enable_approov(self) -> dict[str, bool]:
        with self._lock:
            self._approov_enabled = True
            self._token_binding_enabled = True
        return self.state()

    def disable_approov(self) -> dict[str, bool]:
        with self._lock:
            self._approov_enabled = False
            self._token_binding_enabled = False
        return self.state()

    def enable_token_binding(self) -> dict[str, bool]:
        with self._lock:
            self._token_binding_enabled = True
        return self.state()

    def disable_token_binding(self) -> dict[str, bool]:
        with self._lock:
            self._token_binding_enabled = False
        return self.state()

    def _decode_approov_claims(self, token: str) -> VerificationResult:
        try:
            claims = jwt.decode(
                token,
                self._secret,
                algorithms=[JWT_ALGORITHM],
                options={
                    "require": list(REQUIRED_TOKEN_CLAIMS),
                    "verify_signature": True,
                    "verify_exp": True,
                },
            )
        except jwt.ExpiredSignatureError:
            return VerificationResult.failure("[approov] token expired")
        except jwt.InvalidSignatureError:
            return VerificationResult.failure("[approov] token signature invalid")
        except jwt.InvalidTokenError as error:
            return VerificationResult.failure(f"[approov] token invalid: {error}")

        return VerificationResult.success(claims)

    def _verify_token_binding(
        self,
        headers: Mapping[str, str],
        approov_claims: Mapping[str, Any],
        requested_headers: Sequence[str],
    ) -> str | None:
        pay_claim = approov_claims.get("pay")
        if pay_claim is None or (isinstance(pay_claim, str) and not has_text(pay_claim)):
            return "[approov] token does not have a 'pay' claim"

        if not isinstance(pay_claim, str):
            return "[approov] token does not have a valid 'pay' claim"

        binding_error, binding_value = build_token_binding_string(headers, requested_headers)
        if binding_error is not None or binding_value is None:
            return binding_error

        computed_hash = sha256_b64url_from_str(binding_value)
        if not binding_matches(pay_claim, computed_hash):
            return (
                "[approov] token binding: hash mismatch "
                f"(expected '{computed_hash}', got '{pay_claim}')"
            )

        return None

    def verify_approov_token(
        self,
        headers: Mapping[str, str],
        *,
        token_check: bool = True,
        bound_headers: Sequence[str] | None = None,
    ) -> VerificationResult:
        if not token_check or not self.is_approov_enabled():
            return VerificationResult.success({})

        approov_token = headers.get(self._token_header)
        if not has_text(approov_token):
            return VerificationResult.failure(
                error=f"[approov] missing {self._token_header} header"
            )

        decode_result = self._decode_approov_claims(approov_token.strip())
        if decode_result.error is not None:
            return decode_result

        approov_claims = decode_result.claims or {}
        requested_headers = tuple(bound_headers or ())
        if requested_headers:
            binding_error = self._verify_token_binding(
                headers,
                approov_claims,
                requested_headers,
            )
            if binding_error is not None:
                return VerificationResult.failure(binding_error)

        return VerificationResult.success(approov_claims)


_service_lock = threading.Lock()
_service_instance: ApproovService | None = None


def get_approov_service() -> ApproovService:
    global _service_instance

    if _service_instance is None:
        with _service_lock:
            if _service_instance is None:
                _service_instance = ApproovService(secret=load_approov_secret_from_env())

    return _service_instance
