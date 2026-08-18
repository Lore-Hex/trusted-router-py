"""Attempt assembly helpers (L4): per-attempt request construction.

URL/query building, stream-open request kwargs, default headers with
empty-string suppression, and the User-Agent string. Idempotency keys are
minted ONCE per logical call by the facades (see ``_retry._new_idempotency_key``,
the single key generator) and replayed verbatim on every attempt and domain.
"""

from __future__ import annotations

import platform
import sys
from collections.abc import Mapping, MutableMapping
from typing import Any
from urllib.parse import urlencode

import httpx

RESERVED_HEADERS = frozenset({"x-tr-client"})
"""Headers the SDK owns outright; only the telemetry recorder may set them.

``x-tr-client`` is SDK-reserved in all six SDKs: a stale or forged value from
caller default headers, per-call headers, or an injected client's own headers
is stripped rather than sent -- on every path, including the ones that record
nothing (opt-out, custom base, control plane).

Enforcement is in three layers, because an injected ``httpx.Client`` is
caller-owned and gets several chances to write the header after the SDK has
built its request:

1. the per-attempt request dict is scrubbed, then set from the recorder;
2. a terminal request event hook (:func:`_install_reserved_header_hook`) runs
   immediately before transport -- after the caller's ``Auth`` flow and after
   any request hook they installed -- and re-asserts the reservation for SDK
   requests only.  The caller-owned client's global defaults are never
   mutated.

Residual boundary, now genuinely narrow: a request hook the caller appends
AFTER the SDK was constructed runs after ours and wins, and the standalone
helpers in ``trustedrouter.oauth`` take an injected client directly and never
reach this module.
"""

_RESERVED_MARKER = "trustedrouter_reserved"
"""``Request.extensions`` key marking a request the SDK built.

Carries the value the reservation must end up with: a recorder string, or
``None`` meaning "no x-tr-client at all". Requests WITHOUT this marker belong
to the caller's own traffic on a shared client and are left strictly alone.
"""

_CREDENTIAL_FREE_MARKER = "trustedrouter_credential_free"
_CREDENTIAL_HEADERS = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "cookie",
        "idempotency-key",
        "x-api-key",
        "x-trustedrouter-workspace",
    }
)


def _strip_reserved_headers(headers: MutableMapping[str, str]) -> None:
    """Remove every reserved header, case-insensitively, in place.

    Accepts a plain header dict, an ``httpx.Headers`` store (an injected
    client's own defaults), or a fully merged ``httpx.Request``, because a
    request-level dict cannot delete a header httpx merges in from the client.
    """
    for key in tuple(headers):
        if key.lower() in RESERVED_HEADERS:
            del headers[key]


def _strip_credentials(headers: MutableMapping[str, str]) -> None:
    for key in tuple(headers):
        if key.lower() in _CREDENTIAL_HEADERS:
            del headers[key]


def _enforce_reserved_headers(request: httpx.Request) -> None:
    """Re-assert the reservation on a fully built, post-Auth, post-hook request.

    Runs as the SDK's terminal request event hook, making it the last write
    before the transport. Only touches requests the SDK marked: an unmarked
    request is the caller's other traffic on a client they also lent to us.
    """
    if _RESERVED_MARKER not in request.extensions:
        if request.extensions.get(_CREDENTIAL_FREE_MARKER) is True:
            _strip_credentials(request.headers)
        return
    expected = request.extensions[_RESERVED_MARKER]
    _strip_reserved_headers(request.headers)
    if expected is not None:
        request.headers["x-tr-client"] = expected
    if request.extensions.get(_CREDENTIAL_FREE_MARKER) is True:
        _strip_credentials(request.headers)


async def _aenforce_reserved_headers(request: httpx.Request) -> None:
    """Async twin: httpx requires an awaitable hook on an ``AsyncClient``."""
    _enforce_reserved_headers(request)


def _install_reserved_header_hook(
    client: httpx.Client | httpx.AsyncClient, *, is_async: bool
) -> None:
    """Append the terminal reservation hook to ``client``'s request hooks.

    Appended rather than prepended so it runs AFTER any hook the caller already
    configured; httpx runs request hooks after the ``Auth`` flow, so those two
    -- the only writers that can beat the per-attempt scrub -- are both covered.
    Touches the hook list once at construction, never per request, and the hook
    itself only ever mutates request-local headers.
    """
    hook = _aenforce_reserved_headers if is_async else _enforce_reserved_headers
    hooks = client.event_hooks.setdefault("request", [])
    if hook not in hooks:
        hooks.append(hook)
    # Re-assign so httpx re-normalises its own copy of the mapping.
    client.event_hooks = client.event_hooks


def _credential_free_request(
    client: httpx.Client,
    method: str,
    url: str,
    **kwargs: Any,
) -> httpx.Response:
    """Send one SDK metadata/OAuth request without ambient credentials.

    ``httpx`` merges an injected client's default headers while building the
    request.  Building first lets us remove that merged state locally; passing
    ``auth=None`` also disables a configured client Auth object.  Redirects are
    disabled so the credential-free boundary cannot silently become a second
    cross-origin request.
    """

    request = client.build_request(method, url, **kwargs)
    _strip_credentials(request.headers)
    _strip_reserved_headers(request.headers)
    request.extensions[_CREDENTIAL_FREE_MARKER] = True
    request.extensions[_RESERVED_MARKER] = None
    return client.send(request, auth=None, follow_redirects=False)


async def _acredential_free_request(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    **kwargs: Any,
) -> httpx.Response:
    request = client.build_request(method, url, **kwargs)
    _strip_credentials(request.headers)
    _strip_reserved_headers(request.headers)
    request.extensions[_CREDENTIAL_FREE_MARKER] = True
    request.extensions[_RESERVED_MARKER] = None
    return await client.send(request, auth=None, follow_redirects=False)


def _user_agent() -> str:
    # Lazy: read __version__ from the installed package metadata so the
    # UA stays in sync with whatever PyPI has, without import-cycling on
    # the package's __init__.py.
    try:
        from importlib.metadata import version as _v

        v = _v("trusted-router-py")
    except Exception:  # noqa: BLE001
        v = "unknown"
    py = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    return f"trusted-router-py/{v} python/{py} httpx/{httpx.__version__} {platform.system()}"


_DEFAULT_USER_AGENT = _user_agent()


def _build_stream_request(
    method: str,
    url: str,
    *,
    body: Mapping[str, Any] | None,
    api_key: str | None,
    extra_headers: Mapping[str, str] | None,
    idempotency_key: str | None = None,
    workspace_id: str | None = None,
    timeout: float | httpx.Timeout | None = None,
) -> dict[str, Any]:
    headers: dict[str, str] = {
        "accept": "text/event-stream",
        "user-agent": _DEFAULT_USER_AGENT,
    }
    if extra_headers:
        headers.update(extra_headers)
    if idempotency_key:
        headers["idempotency-key"] = idempotency_key
    if workspace_id:
        headers["x-trustedrouter-workspace"] = workspace_id
    if api_key:
        headers["authorization"] = f"Bearer {api_key}"
    payload: Mapping[str, Any] | None = body
    request: dict[str, Any] = {
        "method": method,
        "url": url,
        "json": payload,
        "headers": headers,
    }
    if timeout is not None:
        request["timeout"] = timeout
    return request


def _responses_body(
    *,
    model: str,
    input: str | list[Mapping[str, Any]],
    instructions: str | None,
    stream: bool,
    params: Mapping[str, Any],
) -> dict[str, Any]:
    params_dict = dict(params)
    for reserved in (
        "api_key",
        "extra_headers",
        "idempotency_key",
        "timeout",
        "workspace_id",
        "stream",
    ):
        params_dict.pop(reserved, None)
    body: dict[str, Any] = {"model": model, "input": input, "stream": stream, **params_dict}
    if instructions is not None:
        body["instructions"] = instructions
    return body


def _broadcast_destination_body(
    *,
    type: str,
    name: str,
    endpoint: str | None,
    enabled: bool,
    include_content: bool,
    method: str,
    headers: Mapping[str, str] | None,
    api_key: str | None,
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "type": type,
        "name": name,
        "enabled": enabled,
        "include_content": include_content,
        "method": method,
    }
    if endpoint is not None:
        body["endpoint"] = endpoint
    if headers is not None:
        body["headers"] = dict(headers)
    if api_key is not None:
        body["api_key"] = api_key
    return body


def _models_path(
    *,
    open_weights: bool | None = None,
    provider_jurisdiction: str | None = None,
    provider_region: str | None = None,
) -> str:
    params: dict[str, str] = {}
    if open_weights is not None:
        params["open_weights"] = "true" if open_weights else "false"
    if provider_jurisdiction:
        params["provider[jurisdiction]"] = provider_jurisdiction
    if provider_region:
        params["provider[region]"] = provider_region
    if not params:
        return "/models"
    return f"/models?{urlencode(params)}"
