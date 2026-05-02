from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import httpx

DEFAULT_API_BASE_URL = "https://api.quillrouter.com/v1"
DEFAULT_TRUST_RELEASE_URL = "https://trust.trustedrouter.com/trust/gcp-release.json"


class TrustedRouterError(RuntimeError):
    def __init__(self, status_code: int, message: str, *, payload: Any | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.payload = payload


class TrustedRouter:
    def __init__(
        self,
        api_key: str | None = None,
        *,
        base_url: str = DEFAULT_API_BASE_URL,
        timeout: float = 120.0,
        headers: Mapping[str, str] | None = None,
    ) -> None:
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self._client = httpx.Client(timeout=timeout, headers=dict(headers or {}))

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> TrustedRouter:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def request(
        self,
        method: str,
        path: str,
        *,
        json: Mapping[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> dict[str, Any]:
        merged_headers = dict(headers or {})
        if self.api_key:
            merged_headers["authorization"] = f"Bearer {self.api_key}"
        response = self._client.request(
            method,
            f"{self.base_url}/{path.lstrip('/')}",
            json=json,
            headers=merged_headers,
        )
        return _json_or_raise(response)

    def chat_completions(
        self,
        *,
        model: str,
        messages: list[Mapping[str, Any]],
        **params: Any,
    ) -> dict[str, Any]:
        return self.request(
            "POST",
            "/chat/completions",
            json={"model": model, "messages": messages, **params},
        )

    def models(self) -> dict[str, Any]:
        return self.request("GET", "/models")

    def credits(self) -> dict[str, Any]:
        return self.request("GET", "/credits")

    def activity(self, **params: Any) -> dict[str, Any]:
        query = httpx.QueryParams({k: v for k, v in params.items() if v is not None})
        suffix = f"?{query}" if query else ""
        return self.request("GET", f"/activity{suffix}")

    def trust_release(self, url: str = DEFAULT_TRUST_RELEASE_URL) -> dict[str, Any]:
        response = self._client.get(url)
        return _json_or_raise(response)


def fetch_trust_release(
    url: str = DEFAULT_TRUST_RELEASE_URL,
    *,
    timeout: float = 30.0,
) -> dict[str, Any]:
    with httpx.Client(timeout=timeout) as client:
        return _json_or_raise(client.get(url))


def _json_or_raise(response: httpx.Response) -> dict[str, Any]:
    try:
        payload = response.json()
    except ValueError as exc:
        if response.is_error:
            raise TrustedRouterError(response.status_code, response.text[:240]) from exc
        raise
    if response.is_error:
        message = _error_message(payload)
        raise TrustedRouterError(response.status_code, message, payload=payload)
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
