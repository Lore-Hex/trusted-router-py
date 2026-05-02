from __future__ import annotations

import json as jsonlib
from collections.abc import AsyncIterator, Iterator, Mapping
from typing import Any

import httpx

DEFAULT_API_BASE_URL = "https://api.quillrouter.com/v1"
DEFAULT_TRUST_RELEASE_URL = "https://trust.trustedrouter.com/trust/gcp-release.json"
AUTO_MODEL = "trustedrouter/auto"


class TrustedRouterError(RuntimeError):
    def __init__(self, status_code: int, message: str, *, payload: Any | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.payload = payload


# ---- shared streaming helpers --------------------------------------------


def _build_stream_request(
    method: str,
    url: str,
    *,
    body: Mapping[str, Any] | None,
    api_key: str | None,
    extra_headers: Mapping[str, str] | None,
) -> dict[str, Any]:
    headers: dict[str, str] = {"accept": "text/event-stream"}
    if extra_headers:
        headers.update(extra_headers)
    if api_key:
        headers["authorization"] = f"Bearer {api_key}"
    payload: Mapping[str, Any] | None = body
    return {"method": method, "url": url, "json": payload, "headers": headers}


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


# ---- sync client ---------------------------------------------------------


class TrustedRouter:
    def __init__(
        self,
        api_key: str | None = None,
        *,
        base_url: str = DEFAULT_API_BASE_URL,
        timeout: float = 120.0,
        headers: Mapping[str, str] | None = None,
        client: httpx.Client | None = None,
    ) -> None:
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        if client is not None:
            # Caller is responsible for the client's lifecycle (timeouts,
            # transport, cert pinning, etc.). close() becomes a no-op.
            self._client = client
            self._owns_client = False
        else:
            self._client = httpx.Client(timeout=timeout, headers=dict(headers or {}))
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

    def _build_chat_request(
        self,
        *,
        model: str,
        messages: list[Mapping[str, Any]],
        api_key: str | None,
        params: Mapping[str, Any],
    ) -> dict[str, Any]:
        body = {"model": model, "messages": messages, "stream": True, **params}
        return _build_stream_request(
            "POST",
            f"{self.base_url}/chat/completions",
            body=body,
            api_key=api_key if api_key is not None else self.api_key,
            extra_headers=None,
        )

    def chat_completions_stream(
        self,
        *,
        model: str,
        messages: list[Mapping[str, Any]],
        api_key: str | None = None,
        **params: Any,
    ) -> Iterator[str]:
        """Yield assistant-message text deltas as they arrive. The gateway
        streams every response (text/event-stream) regardless of the
        `stream` request param, so this is the lowest-overhead consumer.

        Pass `api_key` to override the instance-level key for this single
        call — useful for validating user-supplied bearers without
        mutating shared client state."""
        req = self._build_chat_request(
            model=model, messages=messages, api_key=api_key, params=params
        )
        with self._client.stream(**req) as response:
            if response.is_error:
                detail = response.read().decode("utf-8", errors="replace")[:240]
                raise TrustedRouterError(response.status_code, detail)
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
        **params: Any,
    ) -> Iterator[dict[str, Any]]:
        """Yield parsed OpenAI chat.completion.chunk dicts as they arrive.
        Use this when you need access to fields beyond the text delta
        (e.g. `finish_reason`, `model`, `id`) — for instance when
        translating to a different SSE shape."""
        req = self._build_chat_request(
            model=model, messages=messages, api_key=api_key, params=params
        )
        with self._client.stream(**req) as response:
            if response.is_error:
                detail = response.read().decode("utf-8", errors="replace")[:240]
                raise TrustedRouterError(response.status_code, detail)
            yield from _iter_sse_chunks(response)

    def chat_completions(
        self,
        *,
        model: str = AUTO_MODEL,
        messages: list[Mapping[str, Any]],
        api_key: str | None = None,
        **params: Any,
    ) -> dict[str, Any]:
        """Collect the streamed response into a single OpenAI-shape
        chat.completion dict. Use chat_completions_stream() if you want
        to stream tokens to the user instead."""
        req = self._build_chat_request(
            model=model, messages=messages, api_key=api_key, params=params
        )
        with self._client.stream(**req) as response:
            if response.is_error:
                detail = response.read().decode("utf-8", errors="replace")[:240]
                raise TrustedRouterError(response.status_code, detail)
            chunks = list(_iter_sse_chunks(response))
        return _collect_completion(chunks)

    def models(self) -> dict[str, Any]:
        return self.request("GET", "/models")

    def providers(self) -> dict[str, Any]:
        return self.request("GET", "/providers")

    def regions(self) -> dict[str, Any]:
        return self.request("GET", "/regions")

    def credits(self) -> dict[str, Any]:
        return self.request("GET", "/credits")

    def billing_checkout(
        self,
        *,
        amount: int | str,
        payment_method: str | None = None,
        workspace_id: str | None = None,
        success_url: str | None = None,
        cancel_url: str | None = None,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {"amount": amount}
        if payment_method is not None:
            body["payment_method"] = payment_method
        if workspace_id is not None:
            body["workspace_id"] = workspace_id
        if success_url is not None:
            body["success_url"] = success_url
        if cancel_url is not None:
            body["cancel_url"] = cancel_url
        return self.request("POST", "/billing/checkout", json=body)

    def stablecoin_checkout(self, *, amount: int | str, **params: Any) -> dict[str, Any]:
        return self.billing_checkout(amount=amount, payment_method="stablecoin", **params)

    def wallet_challenge(self, address: str) -> dict[str, Any]:
        return self.request("POST", "/auth/wallet/challenge", json={"address": address})

    def wallet_verify(self, *, address: str, message: str, signature: str) -> dict[str, Any]:
        return self.request(
            "POST",
            "/auth/wallet/verify",
            json={"address": address, "message": message, "signature": signature},
        )

    def auth_session(self) -> dict[str, Any]:
        return self.request("GET", "/auth/session")

    def logout(self) -> dict[str, Any]:
        return self.request("POST", "/auth/logout")

    def activity(self, **params: Any) -> dict[str, Any]:
        query = httpx.QueryParams({k: v for k, v in params.items() if v is not None})
        suffix = f"?{query}" if query else ""
        return self.request("GET", f"/activity{suffix}")

    def attestation(self) -> bytes:
        """Fetch the gateway's live attestation document. Returns the raw
        JWT bytes (Confidential Space mints an OIDC JWT). Caller can
        verify via Google's JWKS, then check audience + image_digest +
        cert-fingerprint nonce against the trust release."""
        # /attestation lives at the API root, not under /v1
        url = self.base_url.rsplit("/v1", 1)[0] + "/attestation"
        response = self._client.get(url)
        if response.is_error:
            raise TrustedRouterError(response.status_code, response.text[:240])
        return response.content

    def trust_release(self, url: str = DEFAULT_TRUST_RELEASE_URL) -> dict[str, Any]:
        response = self._client.get(url)
        return _json_or_raise(response)


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
        base_url: str = DEFAULT_API_BASE_URL,
        timeout: float = 120.0,
        headers: Mapping[str, str] | None = None,
        verify: bool | str = True,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        if client is not None:
            # Caller is responsible for the client's lifecycle (timeouts,
            # transport, verify, event hooks for cert pinning, etc.).
            # aclose() becomes a no-op.
            self._client = client
            self._owns_client = False
        else:
            self._client = httpx.AsyncClient(
                timeout=timeout, headers=dict(headers or {}), verify=verify
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
    ) -> dict[str, Any]:
        merged_headers = dict(headers or {})
        if self.api_key:
            merged_headers["authorization"] = f"Bearer {self.api_key}"
        response = await self._client.request(
            method,
            f"{self.base_url}/{path.lstrip('/')}",
            json=json,
            headers=merged_headers,
        )
        return _json_or_raise(response)

    def _build_chat_request(
        self,
        *,
        model: str,
        messages: list[Mapping[str, Any]],
        api_key: str | None,
        params: Mapping[str, Any],
    ) -> dict[str, Any]:
        body = {"model": model, "messages": messages, "stream": True, **params}
        return _build_stream_request(
            "POST",
            f"{self.base_url}/chat/completions",
            body=body,
            api_key=api_key if api_key is not None else self.api_key,
            extra_headers=None,
        )

    async def chat_completions_stream(
        self,
        *,
        model: str,
        messages: list[Mapping[str, Any]],
        api_key: str | None = None,
        **params: Any,
    ) -> AsyncIterator[str]:
        """Yield assistant-message text deltas as they arrive. Pass
        `api_key` to override the instance key for this single call."""
        req = self._build_chat_request(
            model=model, messages=messages, api_key=api_key, params=params
        )
        async with self._client.stream(**req) as response:
            if response.is_error:
                detail = (await response.aread()).decode("utf-8", errors="replace")[:240]
                raise TrustedRouterError(response.status_code, detail)
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
        **params: Any,
    ) -> AsyncIterator[dict[str, Any]]:
        """Yield parsed OpenAI chat.completion.chunk dicts as they arrive.
        Use this when you need access to fields beyond the text delta
        (e.g. `finish_reason`, `model`, `id`) — for instance when
        translating to a different SSE shape."""
        req = self._build_chat_request(
            model=model, messages=messages, api_key=api_key, params=params
        )
        async with self._client.stream(**req) as response:
            if response.is_error:
                detail = (await response.aread()).decode("utf-8", errors="replace")[:240]
                raise TrustedRouterError(response.status_code, detail)
            async for chunk in _aiter_sse_chunks(response):
                yield chunk

    async def chat_completions_raw_stream(
        self,
        *,
        model: str,
        messages: list[Mapping[str, Any]],
        api_key: str | None = None,
        **params: Any,
    ) -> AsyncIterator[bytes]:
        """Pass-through SSE bytes. For relays that need to forward the
        raw `data: {...}\\n\\n` framing without decoding (e.g. an HTTP
        proxy in front of the gateway)."""
        req = self._build_chat_request(
            model=model, messages=messages, api_key=api_key, params=params
        )
        async with self._client.stream(**req) as response:
            if response.is_error:
                detail = (await response.aread()).decode("utf-8", errors="replace")[:240]
                raise TrustedRouterError(response.status_code, detail)
            async for chunk in response.aiter_bytes():
                yield chunk

    async def chat_completions(
        self,
        *,
        model: str = AUTO_MODEL,
        messages: list[Mapping[str, Any]],
        api_key: str | None = None,
        **params: Any,
    ) -> dict[str, Any]:
        req = self._build_chat_request(
            model=model, messages=messages, api_key=api_key, params=params
        )
        chunks: list[dict[str, Any]] = []
        async with self._client.stream(**req) as response:
            if response.is_error:
                detail = (await response.aread()).decode("utf-8", errors="replace")[:240]
                raise TrustedRouterError(response.status_code, detail)
            async for chunk in _aiter_sse_chunks(response):
                chunks.append(chunk)
        return _collect_completion(chunks)

    async def models(self) -> dict[str, Any]:
        return await self.request("GET", "/models")

    async def providers(self) -> dict[str, Any]:
        return await self.request("GET", "/providers")

    async def regions(self) -> dict[str, Any]:
        return await self.request("GET", "/regions")

    async def credits(self) -> dict[str, Any]:
        return await self.request("GET", "/credits")

    async def billing_checkout(
        self,
        *,
        amount: int | str,
        payment_method: str | None = None,
        workspace_id: str | None = None,
        success_url: str | None = None,
        cancel_url: str | None = None,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {"amount": amount}
        if payment_method is not None:
            body["payment_method"] = payment_method
        if workspace_id is not None:
            body["workspace_id"] = workspace_id
        if success_url is not None:
            body["success_url"] = success_url
        if cancel_url is not None:
            body["cancel_url"] = cancel_url
        return await self.request("POST", "/billing/checkout", json=body)

    async def stablecoin_checkout(self, *, amount: int | str, **params: Any) -> dict[str, Any]:
        return await self.billing_checkout(amount=amount, payment_method="stablecoin", **params)

    async def wallet_challenge(self, address: str) -> dict[str, Any]:
        return await self.request("POST", "/auth/wallet/challenge", json={"address": address})

    async def wallet_verify(self, *, address: str, message: str, signature: str) -> dict[str, Any]:
        return await self.request(
            "POST",
            "/auth/wallet/verify",
            json={"address": address, "message": message, "signature": signature},
        )

    async def auth_session(self) -> dict[str, Any]:
        return await self.request("GET", "/auth/session")

    async def logout(self) -> dict[str, Any]:
        return await self.request("POST", "/auth/logout")

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
