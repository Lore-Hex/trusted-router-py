"""Browser OAuth / PKCE helpers for the TrustedRouter delegated-key flow.

This is the Python twin of the JS SDK's OAuth surface. The flow lets an
app obtain a scoped, delegated TrustedRouter key on behalf of a user
without ever handling the user's credentials:

  1. The app builds an authorize URL (`oauth_authorize_url` /
     `create_oauth_authorization`) carrying a PKCE `code_challenge` and
     an opaque `state` embedded into the `callback_url`, and keeps the
     matching `code_verifier` locally.
  2. The user approves in the browser; TrustedRouter redirects to
     `callback_url?code=...&user_id=...` (plus the embedded `state`).
  3. The app exchanges `code` + `code_verifier` for the delegated key
     (`exchange_oauth_key`) — a public-client POST with NO Authorization
     header.
  4. The app can later read the bound identity with `fetch_userinfo`,
     passing the delegated key as a Bearer token.

PKCE is RFC 7636 S256: `code_verifier` is base64url(32 random bytes),
`code_challenge` is base64url(SHA-256(verifier)) with `=` padding
stripped. The TrustedRouter authorize endpoint uses `callback_url`
(NOT `redirect_uri`) and has no `client_id`/`response_type`/`scope` —
this module matches the live backend contract exactly.

All network helpers raise the SDK's typed errors
(`AuthenticationError`, `BadRequestError`, ...) on any HTTP >= 400, so
callers can discriminate failures the same way they do for inference
calls.
"""
from __future__ import annotations

import base64
import hashlib
import secrets
from dataclasses import dataclass
from typing import Any

import httpx

from trustedrouter.client import (
    _DEFAULT_USER_AGENT,
    DEFAULT_CONTROL_BASE_URL,
    _classify_error,
    _retry_after_seconds,
)

# ---- low-level encoding helpers ------------------------------------------


def _base64url_no_pad(raw: bytes) -> str:
    """base64url-encode bytes with the `=` padding stripped — the encoding
    PKCE (RFC 7636) and the TrustedRouter backend both expect."""
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _random_base64url(byte_length: int) -> str:
    return _base64url_no_pad(secrets.token_bytes(byte_length))


def _sha256_base64url(text: str) -> str:
    digest = hashlib.sha256(text.encode("utf-8")).digest()
    return _base64url_no_pad(digest)


# ---- dataclasses ----------------------------------------------------------


@dataclass(frozen=True, slots=True)
class PKCEPair:
    """A PKCE verifier/challenge pair. Keep `code_verifier` secret and
    local; send `code_challenge` (+ `code_challenge_method`) in the
    authorize URL, then present `code_verifier` again at key exchange."""

    code_verifier: str
    code_challenge: str
    code_challenge_method: str = "S256"


@dataclass(frozen=True, slots=True)
class OAuthAuthorization:
    """Everything an app needs to start (and later finish) the flow:
    `url` is where to send the browser, and `code_verifier` + `state`
    are the secrets to keep until the redirect comes back."""

    code_verifier: str
    code_challenge: str
    code_challenge_method: str
    state: str
    url: str


@dataclass(frozen=True, slots=True)
class OAuthToken:
    """The result of exchanging an authorization `code` for a delegated
    key. `key` is the `sk-tr-v1-...` bearer token; `identity` is the
    bound user identity (sub/email/wallet) or None if the backend didn't
    attach one; `data` is the full exchange payload for forward-compat."""

    key: str
    user_id: str | None
    identity: dict[str, Any] | None
    data: dict[str, Any]


# ---- PKCE / state helpers -------------------------------------------------


def random_oauth_state(byte_length: int = 16) -> str:
    """Return an opaque, URL-safe CSRF/state token. Embed it into the
    `callback_url` (the authorize helpers do this for you) and verify it
    matches on the redirect back."""
    return _random_base64url(byte_length)


def create_pkce_pair(code_verifier: str | None = None) -> PKCEPair:
    """Build a PKCE S256 pair. Pass `code_verifier` to reuse an existing
    verifier (e.g. one you persisted across a redirect); otherwise a
    fresh 32-byte verifier is generated."""
    verifier = code_verifier if code_verifier is not None else _random_base64url(32)
    return PKCEPair(
        code_verifier=verifier,
        code_challenge=_sha256_base64url(verifier),
        code_challenge_method="S256",
    )


def _callback_url_with_state(callback_url: str, state: str) -> str:
    """Set/overwrite the `state` query param on `callback_url`, mirroring
    the JS SDK's `callbackUrlWithState`."""
    url = httpx.URL(callback_url)
    return str(url.copy_set_param("state", state))


# ---- authorize URL --------------------------------------------------------


def oauth_authorize_url(
    *,
    base_url: str = DEFAULT_CONTROL_BASE_URL,
    callback_url: str,
    code_challenge: str | None = None,
    code_challenge_method: str | None = None,
    key_label: str | None = None,
    limit: float | int | str | None = None,
    usage_limit_type: str | None = None,
    expires_at: str | None = None,
    spawn_agent: str | bool | None = None,
    spawn_cloud: str | bool | None = None,
    state: str | None = None,
) -> str:
    """Build the browser authorize URL: GET {base_url}/auth?... .

    Only params that are set are included. `callback_url` is required and
    is the one redirect target (TrustedRouter uses `callback_url`, not
    `redirect_uri`; there is no client_id/response_type/scope). When
    `state` is given it is embedded into `callback_url` so it round-trips
    on the redirect. Raises ValueError if `code_challenge_method` is set
    without `code_challenge`."""
    if not callback_url:
        raise ValueError("callback_url is required")
    if code_challenge_method and not code_challenge:
        raise ValueError("code_challenge is required when code_challenge_method is set")

    effective_callback = (
        _callback_url_with_state(callback_url, state) if state else callback_url
    )
    params: dict[str, str] = {"callback_url": effective_callback}
    if code_challenge:
        params["code_challenge"] = code_challenge
    if code_challenge_method:
        params["code_challenge_method"] = code_challenge_method
    if key_label:
        params["key_label"] = key_label
    if limit is not None:
        params["limit"] = str(limit)
    if usage_limit_type:
        params["usage_limit_type"] = usage_limit_type
    if expires_at:
        params["expires_at"] = expires_at
    if spawn_agent:
        params["spawn_agent"] = str(spawn_agent)
    if spawn_cloud:
        params["spawn_cloud"] = str(spawn_cloud)

    authorize = httpx.URL(f"{base_url.rstrip('/')}/auth").copy_merge_params(params)
    return str(authorize)


def create_oauth_authorization(
    *,
    callback_url: str,
    base_url: str = DEFAULT_CONTROL_BASE_URL,
    code_verifier: str | None = None,
    state: str | None = None,
    **opts: Any,
) -> OAuthAuthorization:
    """One call to kick off the flow: generate a PKCE pair (+ state if
    none given), build the authorize URL, and return all the secrets the
    app must keep until the redirect. `**opts` are forwarded to
    `oauth_authorize_url` (key_label, limit, usage_limit_type,
    expires_at, spawn_agent, spawn_cloud)."""
    pkce = create_pkce_pair(code_verifier)
    effective_state = state if state is not None else random_oauth_state()
    url = oauth_authorize_url(
        base_url=base_url,
        callback_url=callback_url,
        code_challenge=pkce.code_challenge,
        code_challenge_method=pkce.code_challenge_method,
        state=effective_state,
        **opts,
    )
    return OAuthAuthorization(
        code_verifier=pkce.code_verifier,
        code_challenge=pkce.code_challenge,
        code_challenge_method=pkce.code_challenge_method,
        state=effective_state,
        url=url,
    )


# ---- HTTP plumbing --------------------------------------------------------


def _json_or_raise(response: httpx.Response) -> dict[str, Any]:
    """Parse a JSON object response, raising the SDK's typed errors on
    HTTP >= 400 — a local copy of the client's plumbing so the OAuth
    helpers don't need a client instance."""
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
        from trustedrouter.client import TrustedRouterError

        raise TrustedRouterError(
            response.status_code, "Expected JSON object", payload=payload
        )
    return payload


def _error_message(payload: Any) -> str:
    if isinstance(payload, dict):
        error = payload.get("error")
        if isinstance(error, dict):
            return str(error.get("message") or error.get("type") or "TrustedRouter error")
        if payload.get("message"):
            return str(payload["message"])
    return "TrustedRouter error"


def _exchange_body(
    code: str, code_verifier: str | None, code_challenge_method: str | None
) -> dict[str, Any]:
    if not code:
        raise ValueError("code is required")
    body: dict[str, Any] = {"code": code}
    if code_verifier:
        body["code_verifier"] = code_verifier
    if code_challenge_method:
        body["code_challenge_method"] = code_challenge_method
    return body


def _token_from_payload(payload: dict[str, Any]) -> OAuthToken:
    identity = payload.get("identity")
    return OAuthToken(
        key=str(payload.get("key") or ""),
        user_id=(str(payload["user_id"]) if payload.get("user_id") is not None else None),
        identity=identity if isinstance(identity, dict) else None,
        data=payload,
    )


def _userinfo_data(payload: dict[str, Any]) -> dict[str, Any]:
    data = payload.get("data")
    return data if isinstance(data, dict) else payload


# ---- key exchange ---------------------------------------------------------


def exchange_oauth_key(
    *,
    code: str,
    code_verifier: str | None = None,
    code_challenge_method: str | None = None,
    base_url: str = DEFAULT_CONTROL_BASE_URL,
    client: httpx.Client | None = None,
    timeout: float = 30,
) -> OAuthToken:
    """Exchange an authorization `code` (+ PKCE `code_verifier`) for a
    delegated key. POSTs to {base_url}/auth/keys as a public client —
    NO Authorization header. Pass `client` to reuse a connection pool;
    otherwise a short-lived client is created and closed."""
    body = _exchange_body(code, code_verifier, code_challenge_method)
    url = f"{base_url.rstrip('/')}/auth/keys"
    headers = {"user-agent": _DEFAULT_USER_AGENT}
    if client is not None:
        response = client.post(url, json=body, headers=headers, timeout=timeout)
    else:
        with httpx.Client(timeout=timeout) as owned:
            response = owned.post(url, json=body, headers=headers)
    return _token_from_payload(_json_or_raise(response))


async def exchange_oauth_key_async(
    *,
    code: str,
    code_verifier: str | None = None,
    code_challenge_method: str | None = None,
    base_url: str = DEFAULT_CONTROL_BASE_URL,
    client: httpx.AsyncClient | None = None,
    timeout: float = 30,
) -> OAuthToken:
    """Async twin of `exchange_oauth_key`."""
    body = _exchange_body(code, code_verifier, code_challenge_method)
    url = f"{base_url.rstrip('/')}/auth/keys"
    headers = {"user-agent": _DEFAULT_USER_AGENT}
    if client is not None:
        response = await client.post(url, json=body, headers=headers, timeout=timeout)
    else:
        async with httpx.AsyncClient(timeout=timeout) as owned:
            response = await owned.post(url, json=body, headers=headers)
    return _token_from_payload(_json_or_raise(response))


# ---- userinfo -------------------------------------------------------------


def fetch_userinfo(
    *,
    api_key: str,
    base_url: str = DEFAULT_CONTROL_BASE_URL,
    client: httpx.Client | None = None,
    timeout: float = 30,
) -> dict[str, Any]:
    """Read the identity bound to a delegated key. GETs
    {base_url}/auth/userinfo with `Authorization: Bearer <api_key>` and
    returns the unwrapped `data` dict
    (sub/email/email_verified/wallet_address/workspace_id/created_at)."""
    url = f"{base_url.rstrip('/')}/auth/userinfo"
    headers = {
        "user-agent": _DEFAULT_USER_AGENT,
        "authorization": f"Bearer {api_key}",
    }
    if client is not None:
        response = client.get(url, headers=headers, timeout=timeout)
    else:
        with httpx.Client(timeout=timeout) as owned:
            response = owned.get(url, headers=headers)
    return _userinfo_data(_json_or_raise(response))


async def fetch_userinfo_async(
    *,
    api_key: str,
    base_url: str = DEFAULT_CONTROL_BASE_URL,
    client: httpx.AsyncClient | None = None,
    timeout: float = 30,
) -> dict[str, Any]:
    """Async twin of `fetch_userinfo`."""
    url = f"{base_url.rstrip('/')}/auth/userinfo"
    headers = {
        "user-agent": _DEFAULT_USER_AGENT,
        "authorization": f"Bearer {api_key}",
    }
    if client is not None:
        response = await client.get(url, headers=headers, timeout=timeout)
    else:
        async with httpx.AsyncClient(timeout=timeout) as owned:
            response = await owned.get(url, headers=headers)
    return _userinfo_data(_json_or_raise(response))


__all__ = [
    "OAuthAuthorization",
    "OAuthToken",
    "PKCEPair",
    "create_oauth_authorization",
    "create_pkce_pair",
    "exchange_oauth_key",
    "exchange_oauth_key_async",
    "fetch_userinfo",
    "fetch_userinfo_async",
    "oauth_authorize_url",
    "random_oauth_state",
]
