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

Boundary, and it is a real one: the reservation is enforced on everything the
SDK builds, but an injected ``httpx.Client`` is caller-owned and gets the last
write. httpx merges client default headers UNDER the per-request ones and
offers no per-request delete, so the store itself is scrubbed at construction
(closing the pre-construction vector); past that point three things still land
after the SDK is done, and no in-SDK scrub can reach them:

* mutating ``client.headers`` AFTER the SDK was constructed;
* a caller ``Auth`` flow, and a caller ``event_hooks["request"]`` hook -- both
  run inside ``Client.send()``, i.e. after ``build_request()`` and after any
  scrub the SDK could perform, so a hook can overwrite even an ACTIVE
  recorder's value;
* the standalone helpers in ``trustedrouter.oauth``, which take an injected
  client directly and never see this module.

This mirrors the boundary accepted for the Rust SDK, where reqwest merges
default headers after the request has left the SDK entirely.
"""


def _strip_reserved_headers(headers: MutableMapping[str, str]) -> None:
    """Remove every reserved header, case-insensitively, in place.

    Accepts a plain header dict or an ``httpx.Headers`` store (an injected
    client's own defaults), because a request-level dict cannot delete a
    header httpx merges in from the client.
    """
    for key in tuple(headers):
        if key.lower() in RESERVED_HEADERS:
            del headers[key]


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
