"""Error taxonomy (L6): typed hierarchy, classification, and raise helpers.

Single copy per SDK — oauth.py and the clients import from here; no module
keeps a private duplicate. Attribution fields (layer/source/provider/
request_id) are extracted without ever discarding the raw payload
(tests/test_parity_contract.py::test_error_attribution_is_available_without_losing_raw_payload).
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import httpx

from trustedrouter._retry import _retry_after_seconds


class TrustedRouterError(RuntimeError):
    """Base for all SDK-raised errors. Subclasses discriminate by HTTP
    status so callers can `except RateLimitError` / `except AuthenticationError`
    without inspecting numeric status codes."""

    def __init__(self, status_code: int, message: str, *, payload: Any | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.payload = payload
        detail = payload.get("error", payload) if isinstance(payload, Mapping) else {}
        if not isinstance(detail, Mapping):
            detail = {}
        self.layer = _optional_error_string(detail, "layer")
        self.source = _optional_error_string(detail, "source")
        self.provider = _optional_error_string(detail, "provider")
        self.request_id = _optional_error_string(detail, "request_id")


def _optional_error_string(payload: Mapping[str, Any], key: str) -> str | None:
    value = payload.get(key)
    return value if isinstance(value, str) and value else None


class BadRequestError(TrustedRouterError):
    """4xx-class request error (mostly 400, 422). Body is malformed or
    rejected by the gateway/model."""


class AuthenticationError(TrustedRouterError):
    """401 — bearer token is missing, malformed, or revoked."""


class PermissionDeniedError(TrustedRouterError):
    """403 — bearer is valid but lacks scope for this resource."""


class NotFoundError(TrustedRouterError):
    """404 — the model or resource doesn't exist."""


class EndpointNotSupportedError(TrustedRouterError):
    """501 — this OpenRouter-compatible endpoint is intentionally stubbed."""


class RateLimitError(TrustedRouterError):
    """429 — slow down. `retry_after` is the value of the Retry-After
    header in seconds, or None if the gateway didn't send one."""

    def __init__(
        self,
        status_code: int,
        message: str,
        *,
        payload: Any | None = None,
        retry_after: float | None = None,
    ) -> None:
        super().__init__(status_code, message, payload=payload)
        self.retry_after = retry_after


class InternalError(TrustedRouterError):
    """5xx — gateway or upstream model failure. These are the requests
    the SDK retries automatically (see `max_retries`)."""


def _classify_error(
    status_code: int, message: str, *, payload: Any | None, retry_after: float | None
) -> TrustedRouterError:
    if status_code == 401:
        return AuthenticationError(status_code, message, payload=payload)
    if status_code == 403:
        return PermissionDeniedError(status_code, message, payload=payload)
    if status_code == 404:
        return NotFoundError(status_code, message, payload=payload)
    if status_code == 429:
        return RateLimitError(status_code, message, payload=payload, retry_after=retry_after)
    if status_code == 501:
        return EndpointNotSupportedError(status_code, message, payload=payload)
    if 400 <= status_code < 500:
        return BadRequestError(status_code, message, payload=payload)
    if status_code >= 500:
        return InternalError(status_code, message, payload=payload)
    return TrustedRouterError(status_code, message, payload=payload)


def _transport_retry_error(exc: httpx.TransportError) -> InternalError:
    return InternalError(503, f"TrustedRouter endpoint unavailable: {exc!s}")


def _json_or_raise(response: httpx.Response) -> dict[str, Any]:
    retry_after = _retry_after_seconds(response.headers)
    try:
        payload = response.json()
    except ValueError as exc:
        if response.is_error:
            raise _classify_error(
                response.status_code,
                response.text[:240],
                payload=None,
                retry_after=retry_after,
            ) from exc
        raise
    if response.is_error:
        message = _error_message(payload)
        raise _classify_error(
            response.status_code, message, payload=payload, retry_after=retry_after
        )
    if not isinstance(payload, dict):
        raise TrustedRouterError(response.status_code, "Expected JSON object", payload=payload)
    return payload


def _error_message(payload: Any) -> str:
    if isinstance(payload, dict):
        error = payload.get("error")
        if isinstance(error, dict):
            return str(error.get("message") or error.get("type") or "TrustedRouter error")
        if payload.get("message"):
            return str(payload["message"])
    return "TrustedRouter error"


def _raise_for_stream_response(response: httpx.Response) -> None:
    """Translate a 4xx/5xx response (during stream open) into the
    appropriate typed error subclass — same hierarchy `_json_or_raise`
    uses for non-streaming requests, so callers can `except RateLimitError`
    consistently."""
    detail = response.read().decode("utf-8", errors="replace")[:240]
    raise _classify_error(
        response.status_code,
        detail,
        payload=None,
        retry_after=_retry_after_seconds(response.headers),
    )


async def _araise_for_stream_response(response: httpx.Response) -> None:
    detail = (await response.aread()).decode("utf-8", errors="replace")[:240]
    raise _classify_error(
        response.status_code,
        detail,
        payload=None,
        retry_after=_retry_after_seconds(response.headers),
    )
