from __future__ import annotations

import asyncio
import json as jsonlib
import platform
import random
import sys
import time
from collections.abc import AsyncIterator, Iterator, Mapping
from typing import Any

import httpx

from trustedrouter.models import (
    ActivityList,
    AuthSession,
    ChatCompletion,
    ChatCompletionChunk,
    CheckoutSession,
    CreditsBalance,
    EmbeddingResponse,
    LogoutResponse,
    MessagesResponse,
    ModelList,
    ProviderList,
    RegionList,
    ResponseInputTokens,
    ResponseObject,
    TrustRelease,
)

DEFAULT_API_BASE_URL = "https://api.quillrouter.com/v1"
DEFAULT_TRUST_RELEASE_URL = "https://trust.trustedrouter.com/trust/gcp-release.json"
DEFAULT_STATUS_URL = "https://status.trustedrouter.com/status.json"
AUTO_MODEL = "trustedrouter/auto"

# Region routing — see https://trust.trustedrouter.com for the live list.
# Apex (`api.quillrouter.com`) is currently us-central1, so we treat the
# us-central1 entry as an alias of the apex until a regional subdomain
# for it is published.
REGION_HOSTS: dict[str, str] = {
    "us-central1": "api.quillrouter.com",
    "europe-west4": "api-europe-west4.quillrouter.com",
}


def region_base_url(region: str) -> str:
    """Return the OpenAI-compatible /v1 base URL for a TrustedRouter region.

    Raises ValueError if the region isn't in REGION_HOSTS — callers that
    want to opt into an unpublished regional gateway should pass the full
    `base_url=...` to the client constructor instead."""
    if region not in REGION_HOSTS:
        known = ", ".join(sorted(REGION_HOSTS))
        raise ValueError(f"unknown TrustedRouter region {region!r}; known: {known}")
    return f"https://{REGION_HOSTS[region]}/v1"


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


# ---- error hierarchy ------------------------------------------------------


class TrustedRouterError(RuntimeError):
    """Base for all SDK-raised errors. Subclasses discriminate by HTTP
    status so callers can `except RateLimitError` / `except AuthenticationError`
    without inspecting numeric status codes."""

    def __init__(self, status_code: int, message: str, *, payload: Any | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.payload = payload


class BadRequestError(TrustedRouterError):
    """4xx-class request error (mostly 400, 422). Body is malformed or
    rejected by the gateway/model."""


class AuthenticationError(TrustedRouterError):
    """401 — bearer token is missing, malformed, or revoked."""


class PermissionDeniedError(TrustedRouterError):
    """403 — bearer is valid but lacks scope for this resource."""


class NotFoundError(TrustedRouterError):
    """404 — the model, region, or resource doesn't exist."""


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


def _retry_after_seconds(headers: Mapping[str, str]) -> float | None:
    """Parse Retry-After. Per RFC 7231 it can be either an integer number
    of seconds OR an HTTP-date; we only honor the integer form because
    the gateway only emits that and the date form is rarely useful for
    short retries."""
    raw = headers.get("retry-after") or headers.get("Retry-After")
    if not raw:
        return None
    try:
        return max(0.0, float(raw.strip()))
    except ValueError:
        return None


# ---- retry policy --------------------------------------------------------


def _retryable(status_code: int) -> bool:
    """Which responses the SDK retries by default. 429 + 5xx are safe
    to retry idempotently; the gateway is responsible for 5xx-on-write
    being safe (its writes are idempotent or the response is 4xx)."""
    return status_code == 429 or status_code >= 500


def _retry_sleep(attempt: int, *, retry_after: float | None) -> float:
    """Exponential backoff with full jitter, capped at 30 s. If the
    server gave us a Retry-After hint, honor that as the floor."""
    base = min(30.0, 0.5 * (2**attempt))
    delay = random.uniform(0, base)  # noqa: S311  not crypto
    if retry_after is not None:
        delay = max(delay, retry_after)
    return delay


# ---- shared streaming helpers --------------------------------------------


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


def _parse_sse_line(line: str) -> dict[str, Any] | None:
    """Parse one `data: {...}` line. Returns None for non-data lines or [DONE]."""
    if not line.startswith("data: "):
        return None
    payload = line[len("data: ") :].strip()
    if not payload or payload == "[DONE]":
        return None
    try:
        return jsonlib.loads(payload)  # type: ignore[no-any-return]
    except jsonlib.JSONDecodeError:
        return None


def _event_from_sse_frame(lines: list[str]) -> dict[str, Any] | None:
    event_name: str | None = None
    data_parts: list[str] = []
    for line in lines:
        if line.startswith("event:"):
            event_name = line[len("event:") :].strip()
        elif line.startswith("data:"):
            data_parts.append(line[len("data:") :].strip())
    data = "\n".join(data_parts).strip()
    if not data or data == "[DONE]":
        return None
    try:
        payload = jsonlib.loads(data)
    except jsonlib.JSONDecodeError:
        payload = {"data": data}
    if event_name and isinstance(payload, dict) and "event" not in payload:
        payload = {"event": event_name, **payload}
    return payload if isinstance(payload, dict) else {"event": event_name, "data": payload}


def _iter_sse_events(response: httpx.Response) -> Iterator[dict[str, Any]]:
    frame: list[str] = []
    for line in response.iter_lines():
        if line:
            frame.append(line)
            continue
        event = _event_from_sse_frame(frame)
        frame = []
        if event is not None:
            yield event
    event = _event_from_sse_frame(frame)
    if event is not None:
        yield event


async def _aiter_sse_events(response: httpx.Response) -> AsyncIterator[dict[str, Any]]:
    frame: list[str] = []
    async for line in response.aiter_lines():
        if line:
            frame.append(line)
            continue
        event = _event_from_sse_frame(frame)
        frame = []
        if event is not None:
            yield event
    event = _event_from_sse_frame(frame)
    if event is not None:
        yield event


def _delta_text(chunk: Mapping[str, Any]) -> str:
    choices = chunk.get("choices") or []
    if not choices:
        return ""
    delta = choices[0].get("delta") or {}
    content = delta.get("content")
    return content if isinstance(content, str) else ""


def _iter_sse_chunks(response: httpx.Response) -> Iterator[dict[str, Any]]:
    """Walk an open SSE response and yield each parsed `data: {...}` chunk
    as a dict. Skips blank lines and `[DONE]` sentinels. Shared by the
    sync chat_completions* methods so the SSE parsing lives in one place."""
    for line in response.iter_lines():
        chunk = _parse_sse_line(line)
        if chunk is not None:
            yield chunk


async def _aiter_sse_chunks(response: httpx.Response) -> AsyncIterator[dict[str, Any]]:
    """Async twin of _iter_sse_chunks."""
    async for line in response.aiter_lines():
        chunk = _parse_sse_line(line)
        if chunk is not None:
            yield chunk


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


def _collect_completion(chunks: list[dict[str, Any]]) -> dict[str, Any]:
    """Reconstruct the OpenAI chat.completion JSON shape from a list of
    chat.completion.chunk frames. Used so callers that asked for
    stream=False still get a JSON object even though the gateway
    insists on streaming."""
    if not chunks:
        return {
            "id": "",
            "object": "chat.completion",
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": ""},
                    "finish_reason": "stop",
                }
            ],
        }
    text_parts: list[str] = []
    finish_reason: str | None = None
    for c in chunks:
        choices = c.get("choices") or []
        if not choices:
            continue
        delta = choices[0].get("delta") or {}
        if isinstance(delta.get("content"), str):
            text_parts.append(delta["content"])
        if choices[0].get("finish_reason"):
            finish_reason = choices[0]["finish_reason"]
    last = chunks[-1]
    return {
        "id": last.get("id", ""),
        "object": "chat.completion",
        "created": last.get("created", 0),
        "model": last.get("model", ""),
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": "".join(text_parts)},
                "finish_reason": finish_reason or "stop",
            }
        ],
    }


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


# ---- sync client ---------------------------------------------------------


class TrustedRouter:
    def __init__(
        self,
        api_key: str | None = None,
        *,
        base_url: str | None = None,
        region: str | None = None,
        timeout: float = 120.0,
        headers: Mapping[str, str] | None = None,
        workspace_id: str | None = None,
        client: httpx.Client | None = None,
        max_retries: int = 2,
    ) -> None:
        """Sync TrustedRouter client.

        Either pass `region="europe-west4"` (or another known region) for
        a one-line regional pin, OR pass `base_url=...` for a custom
        endpoint (e.g. a self-hosted gateway). Passing both is a
        configuration error. With neither, the client uses the apex
        `api.quillrouter.com/v1` (currently us-central1).

        `max_retries` controls automatic retry of 429 / 5xx responses
        with exponential backoff + jitter. Set to 0 to disable retries
        entirely (e.g. inside an outer retry loop)."""
        if region is not None and base_url is not None:
            raise ValueError("pass region= OR base_url=, not both")
        if region is not None:
            base_url = region_base_url(region)
        if base_url is None:
            base_url = DEFAULT_API_BASE_URL
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.region = region
        self.workspace_id = workspace_id
        self.max_retries = max(0, int(max_retries))
        default_headers = {"user-agent": _DEFAULT_USER_AGENT}
        if headers:
            default_headers.update(headers)
        if client is not None:
            # Caller is responsible for the client's lifecycle (timeouts,
            # transport, cert pinning, etc.). close() becomes a no-op.
            self._client = client
            self._owns_client = False
        else:
            self._client = httpx.Client(timeout=timeout, headers=default_headers)
            self._owns_client = True

    def close(self) -> None:
        if self._owns_client:
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
        api_key: str | None = None,
        workspace_id: str | None = None,
        idempotency_key: str | None = None,
        timeout: float | httpx.Timeout | None = None,
    ) -> dict[str, Any]:
        merged_headers: dict[str, str] = {"user-agent": _DEFAULT_USER_AGENT}
        if headers:
            merged_headers.update(headers)
        if idempotency_key:
            merged_headers["idempotency-key"] = idempotency_key
        selected_workspace_id = workspace_id if workspace_id is not None else self.workspace_id
        if selected_workspace_id:
            merged_headers["x-trustedrouter-workspace"] = selected_workspace_id
        selected_api_key = api_key if api_key is not None else self.api_key
        if selected_api_key:
            merged_headers["authorization"] = f"Bearer {selected_api_key}"
        url = f"{self.base_url}/{path.lstrip('/')}"
        kwargs: dict[str, Any] = {"json": json, "headers": merged_headers}
        if timeout is not None:
            kwargs["timeout"] = timeout
        # Retry 429 + 5xx with exponential backoff + jitter. Honors
        # Retry-After when present.
        attempt = 0
        while True:
            response = self._client.request(method, url, **kwargs)
            if attempt >= self.max_retries or not _retryable(response.status_code):
                return _json_or_raise(response)
            time.sleep(_retry_sleep(attempt, retry_after=_retry_after_seconds(response.headers)))
            attempt += 1

    def _build_chat_request(
        self,
        *,
        model: str,
        messages: list[Mapping[str, Any]],
        api_key: str | None,
        params: Mapping[str, Any],
        extra_headers: Mapping[str, str] | None = None,
        idempotency_key: str | None = None,
        timeout: float | httpx.Timeout | None = None,
    ) -> dict[str, Any]:
        # Pull our reserved kwargs out of `params` so they aren't sent
        # into the JSON body. (Defensive: callers spreading a dict
        # might inadvertently include these.)
        params_dict = dict(params)
        workspace_id = params_dict.pop("workspace_id", None)
        for reserved in ("extra_headers", "idempotency_key", "timeout", "api_key"):
            params_dict.pop(reserved, None)
        body = {"model": model, "messages": messages, "stream": True, **params_dict}
        return _build_stream_request(
            "POST",
            f"{self.base_url}/chat/completions",
            body=body,
            api_key=api_key if api_key is not None else self.api_key,
            extra_headers=extra_headers,
            idempotency_key=idempotency_key,
            workspace_id=workspace_id if workspace_id is not None else self.workspace_id,
            timeout=timeout,
        )

    def chat_completions_stream(
        self,
        *,
        model: str,
        messages: list[Mapping[str, Any]],
        api_key: str | None = None,
        extra_headers: Mapping[str, str] | None = None,
        idempotency_key: str | None = None,
        timeout: float | httpx.Timeout | None = None,
        **params: Any,
    ) -> Iterator[str]:
        """Yield assistant-message text deltas as they arrive. The gateway
        streams every response (text/event-stream) regardless of the
        `stream` request param, so this is the lowest-overhead consumer.

        Pass `api_key` to override the instance-level key for this single
        call. Pass `extra_headers`, `idempotency_key`, or `timeout` to
        tune the single request without recreating the client."""
        req = self._build_chat_request(
            model=model, messages=messages, api_key=api_key, params=params,
            extra_headers=extra_headers, idempotency_key=idempotency_key, timeout=timeout,
        )
        with self._client.stream(**req) as response:
            if response.is_error:
                _raise_for_stream_response(response)
            for chunk in _iter_sse_chunks(response):
                txt = _delta_text(chunk)
                if txt:
                    yield txt

    def chat_completions_chunk_stream(
        self,
        *,
        model: str,
        messages: list[Mapping[str, Any]],
        api_key: str | None = None,
        extra_headers: Mapping[str, str] | None = None,
        idempotency_key: str | None = None,
        timeout: float | httpx.Timeout | None = None,
        **params: Any,
    ) -> Iterator[ChatCompletionChunk]:
        """Yield parsed OpenAI chat.completion.chunk frames as typed
        ChatCompletionChunk models. Use this when you need access to
        fields beyond the text delta (e.g. `finish_reason`, `model`,
        `id`) — for instance when translating to a different SSE shape."""
        req = self._build_chat_request(
            model=model, messages=messages, api_key=api_key, params=params,
            extra_headers=extra_headers, idempotency_key=idempotency_key, timeout=timeout,
        )
        with self._client.stream(**req) as response:
            if response.is_error:
                _raise_for_stream_response(response)
            for chunk in _iter_sse_chunks(response):
                yield ChatCompletionChunk.model_validate(chunk)

    def chat_completions(
        self,
        *,
        model: str = AUTO_MODEL,
        messages: list[Mapping[str, Any]],
        api_key: str | None = None,
        extra_headers: Mapping[str, str] | None = None,
        idempotency_key: str | None = None,
        timeout: float | httpx.Timeout | None = None,
        **params: Any,
    ) -> ChatCompletion:
        """Collect the streamed response into a single typed
        ChatCompletion. Use chat_completions_stream() if you want to
        stream tokens to the user instead."""
        req = self._build_chat_request(
            model=model, messages=messages, api_key=api_key, params=params,
            extra_headers=extra_headers, idempotency_key=idempotency_key, timeout=timeout,
        )
        with self._client.stream(**req) as response:
            if response.is_error:
                _raise_for_stream_response(response)
            chunks = list(_iter_sse_chunks(response))
        return ChatCompletion.model_validate(_collect_completion(chunks))

    def models(self) -> ModelList:
        return ModelList.model_validate(self.request("GET", "/models"))

    def providers(self) -> ProviderList:
        return ProviderList.model_validate(self.request("GET", "/providers"))

    def regions(self) -> RegionList:
        return RegionList.model_validate(self.request("GET", "/regions"))

    def credits(self, *, workspace_id: str | None = None) -> CreditsBalance:
        return CreditsBalance.model_validate(
            self.request("GET", "/credits", workspace_id=workspace_id)
        )

    def embeddings(
        self,
        *,
        model: str,
        input: str | list[str] | list[int] | list[list[int]],
        encoding_format: str | None = None,
        dimensions: int | None = None,
        user: str | None = None,
    ) -> EmbeddingResponse:
        """OpenAI-compatible embeddings wrapper.

        The hosted TrustedRouter API currently returns a stable
        EndpointNotSupportedError for this route instead of fake vectors.
        The wrapper remains so self-hosted deployments and future hosted
        releases have a typed call site.
        """
        body: dict[str, Any] = {"model": model, "input": input}
        if encoding_format is not None:
            body["encoding_format"] = encoding_format
        if dimensions is not None:
            body["dimensions"] = dimensions
        if user is not None:
            body["user"] = user
        return EmbeddingResponse.model_validate(self.request("POST", "/embeddings", json=body))

    def messages(
        self,
        *,
        model: str,
        messages: list[Mapping[str, Any]],
        max_tokens: int = 1024,
        **params: Any,
    ) -> MessagesResponse:
        """Anthropic-shape Messages endpoint. For providers that expose
        the native Anthropic API (rather than translating to/from
        OpenAI shape), this preserves system prompts, content blocks,
        and tool_use semantics that the OpenAI shape can't carry."""
        body: dict[str, Any] = {
            "model": model,
            "messages": messages,
            "max_tokens": max_tokens,
            **params,
        }
        return MessagesResponse.model_validate(self.request("POST", "/messages", json=body))

    def responses(
        self,
        *,
        model: str = AUTO_MODEL,
        input: str | list[Mapping[str, Any]],
        instructions: str | None = None,
        api_key: str | None = None,
        extra_headers: Mapping[str, str] | None = None,
        idempotency_key: str | None = None,
        workspace_id: str | None = None,
        timeout: float | httpx.Timeout | None = None,
        **params: Any,
    ) -> ResponseObject:
        """Create a stateless OpenAI Responses API request."""
        body = _responses_body(
            model=model,
            input=input,
            instructions=instructions,
            stream=False,
            params=params,
        )
        return ResponseObject.model_validate(
            self.request(
                "POST",
                "/responses",
                json=body,
                headers=extra_headers,
                api_key=api_key,
                workspace_id=workspace_id,
                idempotency_key=idempotency_key,
                timeout=timeout,
            )
        )

    def responses_stream(
        self,
        *,
        model: str = AUTO_MODEL,
        input: str | list[Mapping[str, Any]],
        instructions: str | None = None,
        api_key: str | None = None,
        extra_headers: Mapping[str, str] | None = None,
        idempotency_key: str | None = None,
        workspace_id: str | None = None,
        timeout: float | httpx.Timeout | None = None,
        **params: Any,
    ) -> Iterator[dict[str, Any]]:
        """Yield parsed Responses SSE events as dictionaries."""
        body = _responses_body(
            model=model,
            input=input,
            instructions=instructions,
            stream=True,
            params=params,
        )
        req = _build_stream_request(
            "POST",
            f"{self.base_url}/responses",
            body=body,
            api_key=api_key if api_key is not None else self.api_key,
            extra_headers=extra_headers,
            idempotency_key=idempotency_key,
            workspace_id=workspace_id if workspace_id is not None else self.workspace_id,
            timeout=timeout,
        )
        with self._client.stream(**req) as response:
            if response.is_error:
                _raise_for_stream_response(response)
            yield from _iter_sse_events(response)

    def responses_raw_stream(
        self,
        *,
        model: str = AUTO_MODEL,
        input: str | list[Mapping[str, Any]],
        instructions: str | None = None,
        api_key: str | None = None,
        extra_headers: Mapping[str, str] | None = None,
        idempotency_key: str | None = None,
        workspace_id: str | None = None,
        timeout: float | httpx.Timeout | None = None,
        **params: Any,
    ) -> Iterator[bytes]:
        body = _responses_body(
            model=model,
            input=input,
            instructions=instructions,
            stream=True,
            params=params,
        )
        req = _build_stream_request(
            "POST",
            f"{self.base_url}/responses",
            body=body,
            api_key=api_key if api_key is not None else self.api_key,
            extra_headers=extra_headers,
            idempotency_key=idempotency_key,
            workspace_id=workspace_id if workspace_id is not None else self.workspace_id,
            timeout=timeout,
        )
        with self._client.stream(**req) as response:
            if response.is_error:
                _raise_for_stream_response(response)
            yield from response.iter_bytes()

    def responses_input_tokens(
        self,
        *,
        model: str = AUTO_MODEL,
        input: str | list[Mapping[str, Any]],
        instructions: str | None = None,
        workspace_id: str | None = None,
        **params: Any,
    ) -> ResponseInputTokens:
        body = _responses_body(
            model=model,
            input=input,
            instructions=instructions,
            stream=False,
            params=params,
        )
        return ResponseInputTokens.model_validate(
            self.request(
                "POST",
                "/responses/input_tokens",
                json=body,
                workspace_id=workspace_id,
            )
        )

    def billing_checkout(
        self,
        *,
        amount: int | str,
        payment_method: str | None = None,
        workspace_id: str | None = None,
        success_url: str | None = None,
        cancel_url: str | None = None,
        idempotency_key: str | None = None,
    ) -> CheckoutSession:
        """Create a Stripe checkout session. Pass `idempotency_key=` to
        guarantee at-most-once charge semantics across network retries
        — strongly recommended for production."""
        body: dict[str, Any] = {"amount": amount}
        if payment_method is not None:
            body["payment_method"] = payment_method
        if workspace_id is not None:
            body["workspace_id"] = workspace_id
        if success_url is not None:
            body["success_url"] = success_url
        if cancel_url is not None:
            body["cancel_url"] = cancel_url
        return CheckoutSession.model_validate(
            self.request(
                "POST",
                "/billing/checkout",
                json=body,
                workspace_id=workspace_id,
                idempotency_key=idempotency_key,
            )
        )

    def stablecoin_checkout(self, *, amount: int | str, **params: Any) -> CheckoutSession:
        return self.billing_checkout(amount=amount, payment_method="stablecoin", **params)

    def auth_session(self) -> AuthSession:
        return AuthSession.model_validate(self.request("GET", "/auth/session"))

    def logout(self) -> LogoutResponse:
        return LogoutResponse.model_validate(self.request("POST", "/auth/logout"))

    def activity(self, **params: Any) -> ActivityList:
        """List recent generations for the authenticated key/workspace.
        Pass any subset of {since, until, limit, model, workspace_id};
        None values are dropped from the query string."""
        query = httpx.QueryParams({k: v for k, v in params.items() if v is not None})
        suffix = f"?{query}" if query else ""
        return ActivityList.model_validate(self.request("GET", f"/activity{suffix}"))

    def broadcast_destinations(self, *, workspace_id: str | None = None) -> dict[str, Any]:
        return self.request("GET", "/broadcast/destinations", workspace_id=workspace_id)

    def create_broadcast_destination(
        self,
        *,
        type: str,
        name: str = "Broadcast destination",
        endpoint: str | None = None,
        enabled: bool = True,
        include_content: bool = False,
        method: str = "POST",
        headers: Mapping[str, str] | None = None,
        api_key: str | None = None,
        workspace_id: str | None = None,
    ) -> dict[str, Any]:
        body = _broadcast_destination_body(
            type=type,
            name=name,
            endpoint=endpoint,
            enabled=enabled,
            include_content=include_content,
            method=method,
            headers=headers,
            api_key=api_key,
        )
        return self.request("POST", "/broadcast/destinations", json=body, workspace_id=workspace_id)

    def get_broadcast_destination(
        self,
        destination_id: str,
        *,
        workspace_id: str | None = None,
    ) -> dict[str, Any]:
        return self.request(
            "GET",
            f"/broadcast/destinations/{destination_id}",
            workspace_id=workspace_id,
        )

    def update_broadcast_destination(
        self,
        destination_id: str,
        *,
        workspace_id: str | None = None,
        **patch: Any,
    ) -> dict[str, Any]:
        return self.request(
            "PATCH",
            f"/broadcast/destinations/{destination_id}",
            json={key: value for key, value in patch.items() if value is not None},
            workspace_id=workspace_id,
        )

    def delete_broadcast_destination(
        self,
        destination_id: str,
        *,
        workspace_id: str | None = None,
    ) -> dict[str, Any]:
        return self.request(
            "DELETE",
            f"/broadcast/destinations/{destination_id}",
            workspace_id=workspace_id,
        )

    def test_broadcast_destination(
        self,
        destination_id: str,
        *,
        workspace_id: str | None = None,
    ) -> dict[str, Any]:
        return self.request(
            "POST",
            f"/broadcast/destinations/{destination_id}/test",
            workspace_id=workspace_id,
        )

    def status(self, url: str = DEFAULT_STATUS_URL) -> dict[str, Any]:
        response = self._client.get(url)
        return _json_or_raise(response)

    def attestation(self) -> bytes:
        """Fetch the gateway's live attestation document. Returns the raw
        JWT bytes (Confidential Space mints an OIDC JWT). Pass to
        `trustedrouter.attestation.verify_gateway_attestation` to verify."""
        # /attestation lives at the API root, not under /v1
        url = self.base_url.rsplit("/v1", 1)[0] + "/attestation"
        response = self._client.get(url)
        if response.is_error:
            raise TrustedRouterError(response.status_code, response.text[:240])
        return response.content

    def trust_release(self, url: str = DEFAULT_TRUST_RELEASE_URL) -> TrustRelease:
        response = self._client.get(url)
        return TrustRelease.model_validate(_json_or_raise(response))


# ---- async client --------------------------------------------------------


class AsyncTrustedRouter:
    """Async variant. Same surface as TrustedRouter but every method is a
    coroutine, and the streaming helpers return AsyncIterators. Used by
    asyncio servers (e.g. the Pi's quill-device FastAPI app) so they
    don't block the event loop on a streaming generation call."""

    def __init__(
        self,
        api_key: str | None = None,
        *,
        base_url: str | None = None,
        region: str | None = None,
        timeout: float = 120.0,
        headers: Mapping[str, str] | None = None,
        verify: bool | str = True,
        workspace_id: str | None = None,
        client: httpx.AsyncClient | None = None,
        max_retries: int = 2,
    ) -> None:
        if region is not None and base_url is not None:
            raise ValueError("pass region= OR base_url=, not both")
        if region is not None:
            base_url = region_base_url(region)
        if base_url is None:
            base_url = DEFAULT_API_BASE_URL
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.region = region
        self.workspace_id = workspace_id
        self.max_retries = max(0, int(max_retries))
        default_headers = {"user-agent": _DEFAULT_USER_AGENT}
        if headers:
            default_headers.update(headers)
        if client is not None:
            # Caller is responsible for the client's lifecycle (timeouts,
            # transport, verify, event hooks for cert pinning, etc.).
            # aclose() becomes a no-op.
            self._client = client
            self._owns_client = False
        else:
            self._client = httpx.AsyncClient(
                timeout=timeout, headers=default_headers, verify=verify
            )
            self._owns_client = True

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    async def __aenter__(self) -> AsyncTrustedRouter:
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.aclose()

    async def request(
        self,
        method: str,
        path: str,
        *,
        json: Mapping[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
        api_key: str | None = None,
        workspace_id: str | None = None,
        idempotency_key: str | None = None,
        timeout: float | httpx.Timeout | None = None,
    ) -> dict[str, Any]:
        merged_headers: dict[str, str] = {"user-agent": _DEFAULT_USER_AGENT}
        if headers:
            merged_headers.update(headers)
        if idempotency_key:
            merged_headers["idempotency-key"] = idempotency_key
        selected_workspace_id = workspace_id if workspace_id is not None else self.workspace_id
        if selected_workspace_id:
            merged_headers["x-trustedrouter-workspace"] = selected_workspace_id
        selected_api_key = api_key if api_key is not None else self.api_key
        if selected_api_key:
            merged_headers["authorization"] = f"Bearer {selected_api_key}"
        url = f"{self.base_url}/{path.lstrip('/')}"
        kwargs: dict[str, Any] = {"json": json, "headers": merged_headers}
        if timeout is not None:
            kwargs["timeout"] = timeout
        attempt = 0
        while True:
            response = await self._client.request(method, url, **kwargs)
            if attempt >= self.max_retries or not _retryable(response.status_code):
                return _json_or_raise(response)
            await asyncio.sleep(
                _retry_sleep(attempt, retry_after=_retry_after_seconds(response.headers))
            )
            attempt += 1

    def _build_chat_request(
        self,
        *,
        model: str,
        messages: list[Mapping[str, Any]],
        api_key: str | None,
        params: Mapping[str, Any],
        extra_headers: Mapping[str, str] | None = None,
        idempotency_key: str | None = None,
        timeout: float | httpx.Timeout | None = None,
    ) -> dict[str, Any]:
        # Pull our reserved kwargs out of `params` so they aren't sent
        # into the JSON body. (Defensive: callers spreading a dict
        # might inadvertently include these.)
        params_dict = dict(params)
        workspace_id = params_dict.pop("workspace_id", None)
        for reserved in ("extra_headers", "idempotency_key", "timeout", "api_key"):
            params_dict.pop(reserved, None)
        body = {"model": model, "messages": messages, "stream": True, **params_dict}
        return _build_stream_request(
            "POST",
            f"{self.base_url}/chat/completions",
            body=body,
            api_key=api_key if api_key is not None else self.api_key,
            extra_headers=extra_headers,
            idempotency_key=idempotency_key,
            workspace_id=workspace_id if workspace_id is not None else self.workspace_id,
            timeout=timeout,
        )

    async def chat_completions_stream(
        self,
        *,
        model: str,
        messages: list[Mapping[str, Any]],
        api_key: str | None = None,
        extra_headers: Mapping[str, str] | None = None,
        idempotency_key: str | None = None,
        timeout: float | httpx.Timeout | None = None,
        **params: Any,
    ) -> AsyncIterator[str]:
        """Yield assistant-message text deltas as they arrive. Pass
        `api_key` to override the instance key for this single call."""
        req = self._build_chat_request(
            model=model, messages=messages, api_key=api_key, params=params,
            extra_headers=extra_headers, idempotency_key=idempotency_key, timeout=timeout,
        )
        async with self._client.stream(**req) as response:
            if response.is_error:
                await _araise_for_stream_response(response)
            async for chunk in _aiter_sse_chunks(response):
                txt = _delta_text(chunk)
                if txt:
                    yield txt

    async def chat_completions_chunk_stream(
        self,
        *,
        model: str,
        messages: list[Mapping[str, Any]],
        api_key: str | None = None,
        extra_headers: Mapping[str, str] | None = None,
        idempotency_key: str | None = None,
        timeout: float | httpx.Timeout | None = None,
        **params: Any,
    ) -> AsyncIterator[ChatCompletionChunk]:
        """Yield parsed OpenAI chat.completion.chunk frames as typed
        ChatCompletionChunk models."""
        req = self._build_chat_request(
            model=model, messages=messages, api_key=api_key, params=params,
            extra_headers=extra_headers, idempotency_key=idempotency_key, timeout=timeout,
        )
        async with self._client.stream(**req) as response:
            if response.is_error:
                await _araise_for_stream_response(response)
            async for chunk in _aiter_sse_chunks(response):
                yield ChatCompletionChunk.model_validate(chunk)

    async def chat_completions_raw_stream(
        self,
        *,
        model: str,
        messages: list[Mapping[str, Any]],
        api_key: str | None = None,
        extra_headers: Mapping[str, str] | None = None,
        idempotency_key: str | None = None,
        timeout: float | httpx.Timeout | None = None,
        **params: Any,
    ) -> AsyncIterator[bytes]:
        """Pass-through SSE bytes. For relays that need to forward the
        raw `data: {...}\\n\\n` framing without decoding (e.g. an HTTP
        proxy in front of the gateway)."""
        req = self._build_chat_request(
            model=model, messages=messages, api_key=api_key, params=params,
            extra_headers=extra_headers, idempotency_key=idempotency_key, timeout=timeout,
        )
        async with self._client.stream(**req) as response:
            if response.is_error:
                await _araise_for_stream_response(response)
            async for chunk in response.aiter_bytes():
                yield chunk

    async def chat_completions(
        self,
        *,
        model: str = AUTO_MODEL,
        messages: list[Mapping[str, Any]],
        api_key: str | None = None,
        extra_headers: Mapping[str, str] | None = None,
        idempotency_key: str | None = None,
        timeout: float | httpx.Timeout | None = None,
        **params: Any,
    ) -> ChatCompletion:
        req = self._build_chat_request(
            model=model, messages=messages, api_key=api_key, params=params,
            extra_headers=extra_headers, idempotency_key=idempotency_key, timeout=timeout,
        )
        chunks: list[dict[str, Any]] = []
        async with self._client.stream(**req) as response:
            if response.is_error:
                await _araise_for_stream_response(response)
            async for chunk in _aiter_sse_chunks(response):
                chunks.append(chunk)
        return ChatCompletion.model_validate(_collect_completion(chunks))

    async def models(self) -> ModelList:
        return ModelList.model_validate(await self.request("GET", "/models"))

    async def providers(self) -> ProviderList:
        return ProviderList.model_validate(await self.request("GET", "/providers"))

    async def regions(self) -> RegionList:
        return RegionList.model_validate(await self.request("GET", "/regions"))

    async def credits(self, *, workspace_id: str | None = None) -> CreditsBalance:
        return CreditsBalance.model_validate(
            await self.request("GET", "/credits", workspace_id=workspace_id)
        )

    async def embeddings(
        self,
        *,
        model: str,
        input: str | list[str] | list[int] | list[list[int]],
        encoding_format: str | None = None,
        dimensions: int | None = None,
        user: str | None = None,
    ) -> EmbeddingResponse:
        body: dict[str, Any] = {"model": model, "input": input}
        if encoding_format is not None:
            body["encoding_format"] = encoding_format
        if dimensions is not None:
            body["dimensions"] = dimensions
        if user is not None:
            body["user"] = user
        return EmbeddingResponse.model_validate(
            await self.request("POST", "/embeddings", json=body)
        )

    async def messages(
        self,
        *,
        model: str,
        messages: list[Mapping[str, Any]],
        max_tokens: int = 1024,
        **params: Any,
    ) -> MessagesResponse:
        body: dict[str, Any] = {
            "model": model,
            "messages": messages,
            "max_tokens": max_tokens,
            **params,
        }
        return MessagesResponse.model_validate(
            await self.request("POST", "/messages", json=body)
        )

    async def responses(
        self,
        *,
        model: str = AUTO_MODEL,
        input: str | list[Mapping[str, Any]],
        instructions: str | None = None,
        api_key: str | None = None,
        extra_headers: Mapping[str, str] | None = None,
        idempotency_key: str | None = None,
        workspace_id: str | None = None,
        timeout: float | httpx.Timeout | None = None,
        **params: Any,
    ) -> ResponseObject:
        body = _responses_body(
            model=model,
            input=input,
            instructions=instructions,
            stream=False,
            params=params,
        )
        return ResponseObject.model_validate(
            await self.request(
                "POST",
                "/responses",
                json=body,
                headers=extra_headers,
                api_key=api_key,
                workspace_id=workspace_id,
                idempotency_key=idempotency_key,
                timeout=timeout,
            )
        )

    async def responses_stream(
        self,
        *,
        model: str = AUTO_MODEL,
        input: str | list[Mapping[str, Any]],
        instructions: str | None = None,
        api_key: str | None = None,
        extra_headers: Mapping[str, str] | None = None,
        idempotency_key: str | None = None,
        workspace_id: str | None = None,
        timeout: float | httpx.Timeout | None = None,
        **params: Any,
    ) -> AsyncIterator[dict[str, Any]]:
        body = _responses_body(
            model=model,
            input=input,
            instructions=instructions,
            stream=True,
            params=params,
        )
        req = _build_stream_request(
            "POST",
            f"{self.base_url}/responses",
            body=body,
            api_key=api_key if api_key is not None else self.api_key,
            extra_headers=extra_headers,
            idempotency_key=idempotency_key,
            workspace_id=workspace_id if workspace_id is not None else self.workspace_id,
            timeout=timeout,
        )
        async with self._client.stream(**req) as response:
            if response.is_error:
                await _araise_for_stream_response(response)
            async for event in _aiter_sse_events(response):
                yield event

    async def responses_raw_stream(
        self,
        *,
        model: str = AUTO_MODEL,
        input: str | list[Mapping[str, Any]],
        instructions: str | None = None,
        api_key: str | None = None,
        extra_headers: Mapping[str, str] | None = None,
        idempotency_key: str | None = None,
        workspace_id: str | None = None,
        timeout: float | httpx.Timeout | None = None,
        **params: Any,
    ) -> AsyncIterator[bytes]:
        body = _responses_body(
            model=model,
            input=input,
            instructions=instructions,
            stream=True,
            params=params,
        )
        req = _build_stream_request(
            "POST",
            f"{self.base_url}/responses",
            body=body,
            api_key=api_key if api_key is not None else self.api_key,
            extra_headers=extra_headers,
            idempotency_key=idempotency_key,
            workspace_id=workspace_id if workspace_id is not None else self.workspace_id,
            timeout=timeout,
        )
        async with self._client.stream(**req) as response:
            if response.is_error:
                await _araise_for_stream_response(response)
            async for chunk in response.aiter_bytes():
                yield chunk

    async def responses_input_tokens(
        self,
        *,
        model: str = AUTO_MODEL,
        input: str | list[Mapping[str, Any]],
        instructions: str | None = None,
        workspace_id: str | None = None,
        **params: Any,
    ) -> ResponseInputTokens:
        body = _responses_body(
            model=model,
            input=input,
            instructions=instructions,
            stream=False,
            params=params,
        )
        return ResponseInputTokens.model_validate(
            await self.request(
                "POST",
                "/responses/input_tokens",
                json=body,
                workspace_id=workspace_id,
            )
        )

    async def billing_checkout(
        self,
        *,
        amount: int | str,
        payment_method: str | None = None,
        workspace_id: str | None = None,
        success_url: str | None = None,
        cancel_url: str | None = None,
        idempotency_key: str | None = None,
    ) -> CheckoutSession:
        body: dict[str, Any] = {"amount": amount}
        if payment_method is not None:
            body["payment_method"] = payment_method
        if workspace_id is not None:
            body["workspace_id"] = workspace_id
        if success_url is not None:
            body["success_url"] = success_url
        if cancel_url is not None:
            body["cancel_url"] = cancel_url
        return CheckoutSession.model_validate(
            await self.request(
                "POST",
                "/billing/checkout",
                json=body,
                workspace_id=workspace_id,
                idempotency_key=idempotency_key,
            )
        )

    async def stablecoin_checkout(self, *, amount: int | str, **params: Any) -> CheckoutSession:
        return await self.billing_checkout(amount=amount, payment_method="stablecoin", **params)

    async def auth_session(self) -> AuthSession:
        return AuthSession.model_validate(await self.request("GET", "/auth/session"))

    async def logout(self) -> LogoutResponse:
        return LogoutResponse.model_validate(await self.request("POST", "/auth/logout"))

    async def activity(self, **params: Any) -> ActivityList:
        query = httpx.QueryParams({k: v for k, v in params.items() if v is not None})
        suffix = f"?{query}" if query else ""
        return ActivityList.model_validate(await self.request("GET", f"/activity{suffix}"))

    async def broadcast_destinations(self, *, workspace_id: str | None = None) -> dict[str, Any]:
        return await self.request("GET", "/broadcast/destinations", workspace_id=workspace_id)

    async def create_broadcast_destination(
        self,
        *,
        type: str,
        name: str = "Broadcast destination",
        endpoint: str | None = None,
        enabled: bool = True,
        include_content: bool = False,
        method: str = "POST",
        headers: Mapping[str, str] | None = None,
        api_key: str | None = None,
        workspace_id: str | None = None,
    ) -> dict[str, Any]:
        body = _broadcast_destination_body(
            type=type,
            name=name,
            endpoint=endpoint,
            enabled=enabled,
            include_content=include_content,
            method=method,
            headers=headers,
            api_key=api_key,
        )
        return await self.request(
            "POST",
            "/broadcast/destinations",
            json=body,
            workspace_id=workspace_id,
        )

    async def get_broadcast_destination(
        self,
        destination_id: str,
        *,
        workspace_id: str | None = None,
    ) -> dict[str, Any]:
        return await self.request(
            "GET",
            f"/broadcast/destinations/{destination_id}",
            workspace_id=workspace_id,
        )

    async def update_broadcast_destination(
        self,
        destination_id: str,
        *,
        workspace_id: str | None = None,
        **patch: Any,
    ) -> dict[str, Any]:
        return await self.request(
            "PATCH",
            f"/broadcast/destinations/{destination_id}",
            json={key: value for key, value in patch.items() if value is not None},
            workspace_id=workspace_id,
        )

    async def delete_broadcast_destination(
        self,
        destination_id: str,
        *,
        workspace_id: str | None = None,
    ) -> dict[str, Any]:
        return await self.request(
            "DELETE",
            f"/broadcast/destinations/{destination_id}",
            workspace_id=workspace_id,
        )

    async def test_broadcast_destination(
        self,
        destination_id: str,
        *,
        workspace_id: str | None = None,
    ) -> dict[str, Any]:
        return await self.request(
            "POST",
            f"/broadcast/destinations/{destination_id}/test",
            workspace_id=workspace_id,
        )

    async def status(self, url: str = DEFAULT_STATUS_URL) -> dict[str, Any]:
        response = await self._client.get(url)
        return _json_or_raise(response)

    async def attestation(self) -> bytes:
        url = self.base_url.rsplit("/v1", 1)[0] + "/attestation"
        response = await self._client.get(url)
        if response.is_error:
            raise TrustedRouterError(response.status_code, response.text[:240])
        return response.content


def fetch_trust_release(
    url: str = DEFAULT_TRUST_RELEASE_URL,
    *,
    timeout: float = 30.0,
) -> TrustRelease:
    """Fetch and parse the public trust release. Returns a typed
    `TrustRelease` model (use `.model_dump()` if you need a dict)."""
    with httpx.Client(timeout=timeout) as client:
        return TrustRelease.model_validate(_json_or_raise(client.get(url)))


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
