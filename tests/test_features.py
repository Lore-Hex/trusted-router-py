"""Coverage for the v0.2 feature set: typed errors, retries, apex failover,
per-call extras (headers/idempotency/timeout), embeddings, messages,
User-Agent header, async activity()."""

from __future__ import annotations

import asyncio
import json as jsonlib
from typing import Any

import httpx
import pytest

from trustedrouter import (
    AUTO_MODEL,
    AsyncTrustedRouter,
    AuthenticationError,
    BadRequestError,
    EndpointNotSupportedError,
    InternalError,
    NotFoundError,
    PermissionDeniedError,
    ProviderPreferences,
    RateLimitError,
    TrustedRouter,
    TrustedRouterError,
)
from trustedrouter.client import _retry_sleep, _user_agent

# ---- typed errors -------------------------------------------------------


@pytest.mark.parametrize(
    "status,exc_class",
    [
        (400, BadRequestError),
        (401, AuthenticationError),
        (403, PermissionDeniedError),
        (404, NotFoundError),
        (422, BadRequestError),  # 4xx not otherwise classified
        (429, RateLimitError),
        (501, EndpointNotSupportedError),
        (500, InternalError),
        (503, InternalError),
    ],
)
def test_status_codes_map_to_typed_subclasses(
    status: int,
    exc_class: type[TrustedRouterError],
) -> None:
    """Every typed subclass also IS a TrustedRouterError, so old `except
    TrustedRouterError` blocks keep working."""

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, json={"error": {"message": "boom"}})

    sdk = TrustedRouter(
        api_key="k",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        max_retries=0,  # disable retries for tested 429/5xx
    )
    with pytest.raises(exc_class) as exc_info:
        sdk.models()
    assert exc_info.value.status_code == status
    assert isinstance(exc_info.value, TrustedRouterError)
    sdk.close()


def test_rate_limit_error_carries_retry_after() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            429, headers={"Retry-After": "7"}, json={"error": {"message": "slow"}}
        )

    sdk = TrustedRouter(
        api_key="k",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        max_retries=0,
    )
    with pytest.raises(RateLimitError) as exc_info:
        sdk.models()
    assert exc_info.value.retry_after == 7.0
    sdk.close()


def test_rate_limit_error_with_no_retry_after_header_is_none() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, json={"error": {"message": "slow"}})

    sdk = TrustedRouter(
        api_key="k",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        max_retries=0,
    )
    with pytest.raises(RateLimitError) as exc_info:
        sdk.models()
    assert exc_info.value.retry_after is None
    sdk.close()


def test_workspace_id_header_can_be_set_on_client_or_per_call() -> None:
    seen: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers.get("x-trustedrouter-workspace"))
        return httpx.Response(200, json={"data": {}})

    sdk = TrustedRouter(
        api_key="k",
        workspace_id="ws_default",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )

    sdk.credits()
    sdk.credits(workspace_id="ws_override")

    assert seen == ["ws_default", "ws_override"]
    sdk.close()


def test_rate_limit_error_with_invalid_retry_after_is_none() -> None:
    """Some servers send Retry-After as a date — we don't honor that
    form; fall back to None (and our exponential backoff)."""

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            429,
            headers={"Retry-After": "Tue, 15 Nov 2025 12:00:00 GMT"},
            json={"error": {"message": "x"}},
        )

    sdk = TrustedRouter(
        api_key="k",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        max_retries=0,
    )
    with pytest.raises(RateLimitError) as exc_info:
        sdk.models()
    assert exc_info.value.retry_after is None
    sdk.close()


def test_typed_errors_also_raised_by_streaming_chat() -> None:
    """A 401 during stream open must raise AuthenticationError, not the
    generic TrustedRouterError (regression target for our typed-error
    rollout in the streaming path)."""

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": {"message": "bad key"}})

    sdk = TrustedRouter(
        api_key="bad",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        max_retries=0,
    )
    with pytest.raises(AuthenticationError):
        sdk.chat_completions(model="m", messages=[{"role": "user", "content": "x"}])
    sdk.close()


# ---- retry middleware ---------------------------------------------------


def test_request_retries_on_429_then_succeeds() -> None:
    """429 → 200 must succeed transparently when max_retries >= 1."""
    state = {"calls": 0}

    def handler(_request: httpx.Request) -> httpx.Response:
        state["calls"] += 1
        if state["calls"] < 3:
            return httpx.Response(
                429, headers={"Retry-After": "0"}, json={"error": {"message": "x"}}
            )
        return httpx.Response(200, json={"data": [{"id": "ok", "name": "ok"}]})

    sdk = TrustedRouter(
        api_key="k",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        max_retries=3,
    )
    out = sdk.models()
    assert out.data[0].id == "ok"
    assert state["calls"] == 3
    sdk.close()


def test_request_retries_on_5xx_then_gives_up() -> None:
    """After max_retries+1 attempts of 5xx, the final response is raised."""
    state = {"calls": 0}

    def handler(_request: httpx.Request) -> httpx.Response:
        state["calls"] += 1
        return httpx.Response(
            503, headers={"Retry-After": "0"}, json={"error": {"message": "down"}}
        )

    sdk = TrustedRouter(
        api_key="k",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        max_retries=2,
    )
    with pytest.raises(InternalError) as exc_info:
        sdk.models()
    assert state["calls"] == 3  # 1 initial + 2 retries
    assert exc_info.value.status_code == 503
    sdk.close()


def test_inference_request_failover_retries_apex_on_503(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("trustedrouter.client._retry_sleep", lambda *_args, **_kwargs: 0.0)
    seen_hosts: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_hosts.append(request.url.host or "")
        if len(seen_hosts) == 1:
            return httpx.Response(503, json={"error": {"message": "region down"}})
        return httpx.Response(200, json={"data": []})

    sdk = TrustedRouter(
        api_key="k",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        max_retries=1,
        regional_failover=True,
    )

    result = sdk.embeddings(model="embed", input="hello")

    assert result.data == []
    assert seen_hosts == ["api.trustedrouter.com", "api.trustedrouter.com"]
    sdk.close()


def test_request_transport_error_fails_over_then_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("trustedrouter.client._retry_sleep", lambda *_args, **_kwargs: 0.0)
    calls = {"count": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["count"] += 1
        raise httpx.ConnectError("dns failure", request=request)

    sdk = TrustedRouter(
        api_key="k",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        max_retries=1,
        regional_failover=True,
    )
    with pytest.raises(InternalError) as exc_info:
        sdk.embeddings(model="embed", input="hello")
    assert exc_info.value.status_code == 503
    assert calls["count"] == 2
    sdk.close()


def test_control_request_retries_without_regional_failover(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("trustedrouter.client._retry_sleep", lambda *_args, **_kwargs: 0.0)
    seen_hosts: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_hosts.append(request.url.host or "")
        if len(seen_hosts) == 1:
            return httpx.Response(503, json={"error": {"message": "control down"}})
        return httpx.Response(200, json={"data": []})

    sdk = TrustedRouter(
        api_key="k",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        max_retries=1,
        regional_failover=True,
    )

    assert sdk.models().data == []
    assert seen_hosts == ["trustedrouter.com", "trustedrouter.com"]
    sdk.close()


def test_async_control_request_retries_without_regional_failover(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("trustedrouter.client._retry_sleep", lambda *_args, **_kwargs: 0.0)
    seen_hosts: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_hosts.append(request.url.host or "")
        if len(seen_hosts) == 1:
            return httpx.Response(503, json={"error": {"message": "control down"}})
        return httpx.Response(200, json={"data": []})

    async def run() -> None:
        sdk = AsyncTrustedRouter(
            api_key="k",
            client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
            max_retries=1,
            regional_failover=True,
        )
        assert (await sdk.models()).data == []
        await sdk._client.aclose()

    asyncio.run(run())
    assert seen_hosts == ["trustedrouter.com", "trustedrouter.com"]


def test_chat_stream_fails_over_before_returning_chunks(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("trustedrouter.client._retry_sleep", lambda *_args, **_kwargs: 0.0)
    seen_hosts: list[str] = []
    seen_idempotency_keys: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_hosts.append(request.url.host or "")
        seen_idempotency_keys.append(request.headers.get("idempotency-key"))
        if len(seen_hosts) == 1:
            return httpx.Response(503, text="regional gateway unavailable")
        return httpx.Response(
            200,
            headers={"content-type": "text/event-stream"},
            content=b'data: {"choices":[{"delta":{"content":"OK"}}]}\n\n',
        )

    sdk = TrustedRouter(
        api_key="k",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        max_retries=1,
        regional_failover=True,
    )

    assert list(
        sdk.chat_completions_stream(model="m", messages=[{"role": "user", "content": "x"}])
    ) == ["OK"]
    assert seen_hosts == ["api.trustedrouter.com", "api.trustedrouter.com"]
    assert seen_idempotency_keys[0] is not None
    assert seen_idempotency_keys[0].startswith("tr-req-")
    assert seen_idempotency_keys == [seen_idempotency_keys[0], seen_idempotency_keys[0]]
    sdk.close()


def test_chat_stream_transport_error_before_response_retries_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("trustedrouter.client._retry_sleep", lambda *_args, **_kwargs: 0.0)
    seen_hosts: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_hosts.append(request.url.host or "")
        if len(seen_hosts) == 1:
            raise httpx.ConnectError("connection refused", request=request)
        return httpx.Response(
            200,
            headers={"content-type": "text/event-stream"},
            content=b'data: {"choices":[{"delta":{"content":"ok"}}]}\n\n'
            b"data: [DONE]\n\n",
        )

    sdk = TrustedRouter(
        api_key="k",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        max_retries=1,
        regional_failover=True,
    )
    assert list(
        sdk.chat_completions_stream(model="m", messages=[{"role": "user", "content": "x"}])
    ) == ["ok"]
    assert seen_hosts == ["api.trustedrouter.com", "api.trustedrouter.com"]
    sdk.close()


def test_max_retries_zero_disables_retry_loop_entirely() -> None:
    state = {"calls": 0}

    def handler(_request: httpx.Request) -> httpx.Response:
        state["calls"] += 1
        return httpx.Response(503, headers={"Retry-After": "0"}, json={"error": {"message": "x"}})

    sdk = TrustedRouter(
        api_key="k",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        max_retries=0,
    )
    with pytest.raises(InternalError):
        sdk.models()
    assert state["calls"] == 1
    sdk.close()


@pytest.mark.parametrize("status", [400, 401, 404])
def test_4xx_other_than_429_is_not_retried(status: int) -> None:
    """We should not retry 400/401/403/404 — those won't change."""
    state = {"calls": 0}

    def handler(_request: httpx.Request) -> httpx.Response:
        state["calls"] += 1
        return httpx.Response(status, json={"error": {"message": "x"}})

    sdk = TrustedRouter(
        api_key="k",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        max_retries=5,
    )
    with pytest.raises(TrustedRouterError):
        sdk.models()
    assert state["calls"] == 1
    sdk.close()


def test_async_request_retries_on_503() -> None:
    state = {"calls": 0}

    def handler(_request: httpx.Request) -> httpx.Response:
        state["calls"] += 1
        if state["calls"] < 2:
            return httpx.Response(
                503, headers={"Retry-After": "0"}, json={"error": {"message": "x"}}
            )
        return httpx.Response(200, json={"data": []})

    async def run() -> None:
        sdk = AsyncTrustedRouter(
            api_key="k",
            client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
            max_retries=3,
        )
        result = await sdk.models()
        assert result.data == []
        await sdk._client.aclose()

    asyncio.run(run())
    assert state["calls"] == 2


def test_async_request_failover_retries_apex_on_503(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("trustedrouter.client._retry_sleep", lambda *_args, **_kwargs: 0.0)
    seen_hosts: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_hosts.append(request.url.host or "")
        if len(seen_hosts) == 1:
            return httpx.Response(503, json={"error": {"message": "region down"}})
        return httpx.Response(200, json={"data": []})

    async def run() -> None:
        sdk = AsyncTrustedRouter(
            api_key="k",
            client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
            max_retries=1,
            regional_failover=True,
        )
        result = await sdk.embeddings(model="embed", input="hello")
        assert result.data == []
        await sdk._client.aclose()

    asyncio.run(run())
    assert seen_hosts == ["api.trustedrouter.com", "api.trustedrouter.com"]


def test_async_request_transport_error_fails_over_then_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("trustedrouter.client._retry_sleep", lambda *_args, **_kwargs: 0.0)
    calls = {"count": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["count"] += 1
        raise httpx.ConnectError("dns failure", request=request)

    async def run() -> None:
        sdk = AsyncTrustedRouter(
            api_key="k",
            client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
            max_retries=1,
            regional_failover=True,
        )
        with pytest.raises(InternalError) as exc_info:
            await sdk.embeddings(model="embed", input="hello")
        assert exc_info.value.status_code == 503
        await sdk._client.aclose()

    asyncio.run(run())
    assert calls["count"] == 2


def test_retry_sleep_returns_at_least_retry_after() -> None:
    """retry_after acts as a floor — even if jitter would pick a smaller
    value, we never poll faster than the server's hint."""
    for attempt in range(4):
        for retry_after in (None, 0.1, 5.0):
            d = _retry_sleep(attempt, retry_after=retry_after)
            assert d >= 0
            if retry_after is not None:
                assert d >= retry_after


def test_retry_sleep_caps_at_30_seconds() -> None:
    """High attempt count must not balloon — base is capped at 30s."""
    for attempt in range(20, 30):
        d = _retry_sleep(attempt, retry_after=None)
        assert d <= 30.0


# ---- per-call extras ----------------------------------------------------


def test_extra_headers_propagate_to_chat_request() -> None:
    seen: list[dict[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(dict(request.headers))
        return httpx.Response(
            200,
            headers={"content-type": "text/event-stream"},
            content=b'data: {"choices":[{"delta":{"content":"x"},'
            b'"finish_reason":"stop"}]}\n\ndata: [DONE]\n\n',
        )

    sdk = TrustedRouter(
        api_key="k",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        max_retries=0,
    )
    sdk.chat_completions(
        model="m",
        messages=[{"role": "user", "content": "x"}],
        extra_headers={"x-trace-id": "abc-123"},
    )
    assert seen[0]["x-trace-id"] == "abc-123"
    sdk.close()


def test_idempotency_key_is_sent_on_request_and_chat() -> None:
    seen_keys: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_keys.append(request.headers.get("idempotency-key", ""))
        return httpx.Response(200, json={"data": {"ok": True}})

    sdk = TrustedRouter(
        api_key="k",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    sdk.billing_checkout(amount=10, idempotency_key="key-123")
    assert seen_keys == ["key-123"]
    sdk.close()


def test_chat_completions_preserves_explicit_idempotency_key() -> None:
    seen: list[tuple[str | None, dict[str, object]]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(
            (
                request.headers.get("idempotency-key"),
                jsonlib.loads(request.content.decode()),
            )
        )
        return httpx.Response(
            200,
            headers={"content-type": "text/event-stream"},
            content=b'data: {"choices":[{"delta":{"content":"x"},"finish_reason":"stop"}]}\n\n',
        )

    sdk = TrustedRouter(
        api_key="k",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        max_retries=0,
    )
    sdk.chat_completions(
        model="m",
        messages=[{"role": "user", "content": "hi"}],
        idempotency_key="caller-key-1",
        tags={"team": "legal"},
        session_id="matter_456",
    )
    assert seen[0][0] == "caller-key-1"
    assert "idempotency_key" not in seen[0][1]
    assert seen[0][1]["tags"] == {"team": "legal"}
    assert seen[0][1]["session_id"] == "matter_456"
    sdk.close()


def test_chat_completions_drops_reserved_kwargs_from_body() -> None:
    """If a caller spreads a dict into **params that includes our
    reserved kwargs (api_key, idempotency_key, etc.), they must not
    leak into the JSON body sent to the gateway."""
    bodies: list[dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        bodies.append(jsonlib.loads(request.content.decode()))
        return httpx.Response(
            200,
            headers={"content-type": "text/event-stream"},
            content=b'data: {"choices":[{"delta":{"content":"x"}}]}\n\ndata: [DONE]\n\n',
        )

    sdk = TrustedRouter(
        api_key="k",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        max_retries=0,
    )
    extra: dict[str, Any] = {
        "temperature": 0.5,
        "api_key": "leaked",
        "idempotency_key": "leaked",
    }
    sdk.chat_completions(model="m", messages=[{"role": "user", "content": "hi"}], **extra)
    assert bodies[0]["temperature"] == 0.5
    assert "api_key" not in bodies[0]
    assert "idempotency_key" not in bodies[0]
    sdk.close()


def test_chat_completions_workspace_override_is_header_not_body() -> None:
    seen: list[tuple[str | None, dict[str, object]]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(
            (
                request.headers.get("x-trustedrouter-workspace"),
                jsonlib.loads(request.content.decode()),
            )
        )
        return httpx.Response(
            200,
            headers={"content-type": "text/event-stream"},
            content=b'data: {"choices":[{"delta":{"content":"x"},"finish_reason":"stop"}]}\n\n',
        )

    sdk = TrustedRouter(
        api_key="k",
        workspace_id="ws_default",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        max_retries=0,
    )
    sdk.chat_completions(
        model="m",
        messages=[{"role": "user", "content": "hi"}],
        workspace_id="ws_override",
    )
    sdk.chat_completions(model="m", messages=[{"role": "user", "content": "hi"}])

    assert seen[0][0] == "ws_override"
    assert "workspace_id" not in seen[0][1]
    assert seen[1][0] == "ws_default"
    assert "workspace_id" not in seen[1][1]
    sdk.close()


def test_chat_completions_chunk_stream_returns_typed_chunks() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "text/event-stream"},
            content=(
                b'data: {"id":"chatcmpl_1","object":"chat.completion.chunk","model":"m",'
                b'"choices":[{"index":0,"delta":{"content":"hello"}}]}\n\n'
                b"data: [DONE]\n\n"
            ),
        )

    sdk = TrustedRouter(
        api_key="k",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        max_retries=0,
    )
    chunks = list(
        sdk.chat_completions_chunk_stream(
            model="m",
            messages=[{"role": "user", "content": "hi"}],
        )
    )
    assert chunks[0].id == "chatcmpl_1"
    assert chunks[0].choices[0].delta.content == "hello"
    sdk.close()


# ---- embeddings + messages wrappers ------------------------------------


def test_sync_embeddings_only_sends_provided_optional_fields() -> None:
    bodies: list[dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        bodies.append(jsonlib.loads(request.content.decode()))
        return httpx.Response(200, json={"data": [{"embedding": [0.1]}]})

    sdk = TrustedRouter(api_key="k", client=httpx.Client(transport=httpx.MockTransport(handler)))
    sdk.embeddings(model="text-embed", input="hello")
    sdk.embeddings(
        model="text-embed",
        input=["a", "b"],
        encoding_format="base64",
        dimensions=512,
        user="u_42",
        session_id="matter_456",
        trace={"source": "eval"},
        tags={"team": "legal"},
        provider=ProviderPreferences.confidential(),
    )
    sdk.close()

    assert bodies[0] == {"model": "text-embed", "input": "hello"}
    assert bodies[1] == {
        "model": "text-embed",
        "input": ["a", "b"],
        "encoding_format": "base64",
        "dimensions": 512,
        "user": "u_42",
        "session_id": "matter_456",
        "trace": {"source": "eval"},
        "tags": {"team": "legal"},
        "provider": {"min_privacy": "confidential", "data_collection": "deny"},
    }


def test_embeddings_not_supported_maps_to_typed_error() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            501,
            json={
                "error": {
                    "message": "Endpoint is not supported",
                    "type": "endpoint_not_supported",
                }
            },
        )

    sdk = TrustedRouter(
        api_key="k",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        max_retries=0,
    )

    with pytest.raises(EndpointNotSupportedError):
        sdk.embeddings(model="openai/gpt-4o-mini", input="hello")
    sdk.close()


def test_sync_messages_anthropic_shape() -> None:
    bodies: list[dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        bodies.append(jsonlib.loads(request.content.decode()))
        return httpx.Response(
            200, json={"id": "msg_x", "content": [{"type": "text", "text": "hi"}]}
        )

    sdk = TrustedRouter(api_key="k", client=httpx.Client(transport=httpx.MockTransport(handler)))
    sdk.messages(
        model="anthropic/claude-3-5-sonnet",
        messages=[{"role": "user", "content": "hello"}],
        max_tokens=64,
        system="You are helpful.",
        tags={"team": "legal"},
    )
    sdk.close()

    assert bodies[0]["max_tokens"] == 64
    assert bodies[0]["system"] == "You are helpful."
    assert bodies[0]["messages"][0]["role"] == "user"
    assert bodies[0]["tags"] == {"team": "legal"}


def test_sync_responses_wrapper_sends_workspace_header_not_body() -> None:
    seen: list[tuple[str | None, str | None, dict[str, object]]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(
            (
                request.headers.get("x-trustedrouter-workspace"),
                request.headers.get("idempotency-key"),
                jsonlib.loads(request.content.decode()),
            )
        )
        return httpx.Response(
            200,
            json={
                "id": "resp_1",
                "object": "response",
                "status": "completed",
                "output": [
                    {
                        "type": "message",
                        "content": [{"type": "output_text", "text": "pong"}],
                    }
                ],
                "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2},
            },
        )

    sdk = TrustedRouter(
        api_key="k",
        workspace_id="ws_default",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    result = sdk.responses(
        input="ping",
        workspace_id="ws_override",
        instructions="reply tersely",
        metadata={"source": "test"},
        tags={"team": "legal"},
        user="user-123",
        session_id="matter-456",
    )
    sdk.close()

    assert result.id == "resp_1"
    assert seen[0][0] == "ws_override"
    assert seen[0][1] is not None
    assert seen[0][1].startswith("tr-req-")
    assert seen[0][2]["model"] == AUTO_MODEL
    assert seen[0][2]["input"] == "ping"
    assert seen[0][2]["stream"] is False
    assert seen[0][2]["tags"] == {"team": "legal"}
    assert seen[0][2]["user"] == "user-123"
    assert seen[0][2]["session_id"] == "matter-456"
    assert "workspace_id" not in seen[0][2]


def test_sync_responses_stream_yields_responses_sse_events() -> None:
    seen_bodies: list[dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_bodies.append(jsonlib.loads(request.content.decode()))
        return httpx.Response(
            200,
            headers={"content-type": "text/event-stream"},
            content=(
                b"event: response.created\n"
                b'data: {"type":"response.created","response":{"id":"resp_1"}}\n\n'
                b"event: response.output_text.delta\n"
                b'data: {"type":"response.output_text.delta","delta":"pong"}\n\n'
                b"data: [DONE]\n\n"
            ),
        )

    sdk = TrustedRouter(api_key="k", client=httpx.Client(transport=httpx.MockTransport(handler)))
    events = list(sdk.responses_stream(input="ping"))
    sdk.close()

    assert seen_bodies[0]["stream"] is True
    assert events[0]["event"] == "response.created"
    assert events[1]["delta"] == "pong"


def test_sync_responses_stream_fails_over_with_same_idempotency_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("trustedrouter.client._retry_sleep", lambda *_args, **_kwargs: 0.0)
    seen: list[tuple[str, str | None]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.url.host or "", request.headers.get("idempotency-key")))
        if len(seen) == 1:
            return httpx.Response(503, json={"error": {"message": "region down"}})
        return httpx.Response(
            200,
            headers={"content-type": "text/event-stream"},
            content=b"event: response.completed\n"
            b'data: {"type":"response.completed","response":{"id":"resp_2"}}\n\n'
            b"data: [DONE]\n\n",
        )

    sdk = TrustedRouter(
        api_key="k",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        max_retries=1,
        regional_failover=True,
    )
    events = list(sdk.responses_stream(input="ping"))
    sdk.close()

    assert events[0]["event"] == "response.completed"
    assert seen[0][0] == "api.trustedrouter.com"
    assert seen[1][0] == "api.trustedrouter.com"
    assert seen[0][1] is not None
    assert seen[0][1] == seen[1][1]


def test_sync_responses_raw_stream_passes_through_bytes_and_fails_over(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("trustedrouter.client._retry_sleep", lambda *_args, **_kwargs: 0.0)
    seen_hosts: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_hosts.append(request.url.host or "")
        if len(seen_hosts) == 1:
            return httpx.Response(503, json={"error": {"message": "region down"}})
        return httpx.Response(
            200,
            headers={"content-type": "text/event-stream"},
            content=b"event: response.created\n"
            b'data: {"type":"response.created"}\n\n'
            b"data: [DONE]\n\n",
        )

    sdk = TrustedRouter(
        api_key="k",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        max_retries=1,
        regional_failover=True,
    )
    raw = b"".join(sdk.responses_raw_stream(input="ping"))
    sdk.close()

    assert seen_hosts == ["api.trustedrouter.com", "api.trustedrouter.com"]
    assert b"response.created" in raw
    assert b"[DONE]" in raw


def test_sync_responses_raw_stream_raises_typed_error() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, headers={"Retry-After": "0"}, text="slow down")

    sdk = TrustedRouter(
        api_key="k",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        max_retries=0,
    )
    with pytest.raises(RateLimitError) as exc_info:
        list(sdk.responses_raw_stream(input="ping"))
    assert exc_info.value.status_code == 429
    sdk.close()


def test_sync_responses_raw_stream_transport_error_fails_over(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("trustedrouter.client._retry_sleep", lambda *_args, **_kwargs: 0.0)
    seen_hosts: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_hosts.append(request.url.host or "")
        if len(seen_hosts) == 1:
            raise httpx.ConnectError("connection refused", request=request)
        return httpx.Response(
            200,
            headers={"content-type": "text/event-stream"},
            content=b"event: response.completed\n"
            b'data: {"type":"response.completed"}\n\n'
            b"data: [DONE]\n\n",
        )

    sdk = TrustedRouter(
        api_key="k",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        max_retries=1,
        regional_failover=True,
    )
    assert b"response.completed" in b"".join(sdk.responses_raw_stream(input="ping"))
    assert seen_hosts == ["api.trustedrouter.com", "api.trustedrouter.com"]
    sdk.close()


def test_sync_responses_input_tokens_wrapper() -> None:
    seen_paths: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_paths.append(request.url.path)
        return httpx.Response(200, json={"input_tokens": 7, "total_tokens": 7})

    sdk = TrustedRouter(api_key="k", client=httpx.Client(transport=httpx.MockTransport(handler)))
    result = sdk.responses_input_tokens(input="count me")
    sdk.close()

    assert seen_paths == ["/v1/responses/input_tokens"]
    assert result.input_tokens == 7


def test_sync_broadcast_destination_helpers_and_status() -> None:
    seen: list[tuple[str, str, str | None, dict[str, object] | None]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = jsonlib.loads(request.content.decode()) if request.content else None
        seen.append(
            (
                request.method,
                request.url.path,
                request.headers.get("x-trustedrouter-workspace"),
                body,
            )
        )
        if request.url.host == "status.example":
            return httpx.Response(200, json={"status": "ok"})
        return httpx.Response(200, json={"data": {"id": "bdst_1"}})

    sdk = TrustedRouter(
        api_key="k",
        workspace_id="ws_default",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    sdk.broadcast_destinations()
    sdk.create_broadcast_destination(
        type="webhook",
        name="OTLP",
        endpoint="https://hook.example/otlp",
        headers={"Authorization": "Bearer x"},
        workspace_id="ws_override",
    )
    sdk.test_broadcast_destination("bdst_1")
    assert sdk.status("https://status.example/status.json")["status"] == "ok"
    sdk.close()

    assert seen[0] == ("GET", "/v1/broadcast/destinations", "ws_default", None)
    assert seen[1][0:3] == ("POST", "/v1/broadcast/destinations", "ws_override")
    assert seen[1][3] is not None
    assert seen[1][3]["headers"] == {"Authorization": "Bearer x"}
    assert seen[2][0:3] == ("POST", "/v1/broadcast/destinations/bdst_1/test", "ws_default")
    assert seen[3][1] == "/status.json"


def test_sync_broadcast_update_delete_auth_logout_and_stablecoin_checkout() -> None:
    seen: list[tuple[str, str, dict[str, object] | None]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = jsonlib.loads(request.content.decode()) if request.content else None
        seen.append((request.method, request.url.path, body))
        if request.url.path == "/v1/billing/checkout":
            return httpx.Response(200, json={"data": {"url": "https://stripe.test/session"}})
        return httpx.Response(200, json={"data": {"ok": True}})

    sdk = TrustedRouter(api_key="k", client=httpx.Client(transport=httpx.MockTransport(handler)))
    sdk.update_broadcast_destination("bdst_1", enabled=False, endpoint=None, name="Events")
    sdk.delete_broadcast_destination("bdst_1")
    sdk.auth_session()
    sdk.logout()
    sdk.stablecoin_checkout(amount="25", workspace_id="ws_1")
    sdk.close()

    assert seen[0] == (
        "PATCH",
        "/v1/broadcast/destinations/bdst_1",
        {"enabled": False, "name": "Events"},
    )
    assert seen[1][0:2] == ("DELETE", "/v1/broadcast/destinations/bdst_1")
    assert seen[2][0:2] == ("GET", "/v1/auth/session")
    assert seen[3][0:2] == ("POST", "/v1/auth/logout")
    assert seen[4][2] == {
        "amount": "25",
        "payment_method": "stablecoin",
        "workspace_id": "ws_1",
    }


def test_sync_create_broadcast_destination_includes_optional_api_key_and_endpoint() -> None:
    seen_body: list[dict[str, object]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_body.append(jsonlib.loads(request.content.decode()))
        return httpx.Response(200, json={"data": {"id": "bdst_1"}})

    sdk = TrustedRouter(api_key="k", client=httpx.Client(transport=httpx.MockTransport(handler)))
    sdk.create_broadcast_destination(
        type="posthog",
        name="PostHog",
        endpoint="https://us.i.posthog.com",
        api_key="phc_secret",
        include_content=True,
    )
    sdk.close()

    assert seen_body == [
        {
            "type": "posthog",
            "name": "PostHog",
            "enabled": True,
            "include_content": True,
            "method": "POST",
            "endpoint": "https://us.i.posthog.com",
            "api_key": "phc_secret",
        }
    ]


def test_async_embeddings_and_messages() -> None:
    seen_paths: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_paths.append(request.url.path)
        return httpx.Response(200, json={"ok": True})

    async def run() -> None:
        sdk = AsyncTrustedRouter(
            api_key="k",
            client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        )
        await sdk.embeddings(model="e", input="x")
        await sdk.messages(
            model="anthropic/claude-3-5-sonnet", messages=[{"role": "user", "content": "x"}]
        )
        await sdk._client.aclose()

    asyncio.run(run())
    assert seen_paths == ["/v1/embeddings", "/v1/messages"]


def test_async_responses_wrapper_and_stream() -> None:
    seen: list[tuple[str, str | None, str | None, dict[str, object]]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = jsonlib.loads(request.content.decode())
        seen.append(
            (
                request.url.path,
                request.headers.get("x-trustedrouter-workspace"),
                request.headers.get("idempotency-key"),
                body,
            )
        )
        if body.get("stream") is True:
            return httpx.Response(
                200,
                headers={"content-type": "text/event-stream"},
                content=b"event: response.completed\n"
                b'data: {"type":"response.completed","response":{"id":"resp_2"}}\n\n'
                b"data: [DONE]\n\n",
            )
        return httpx.Response(
            200,
            json={"id": "resp_1", "object": "response", "status": "completed"},
        )

    async def run() -> list[dict[str, object]]:
        sdk = AsyncTrustedRouter(
            api_key="k",
            workspace_id="ws_default",
            client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        )
        await sdk.responses(input="ping", workspace_id="ws_override")
        events = [event async for event in sdk.responses_stream(input="ping")]
        await sdk._client.aclose()
        return events

    events = asyncio.run(run())
    assert seen[0][0] == "/v1/responses"
    assert seen[0][1] == "ws_override"
    assert seen[0][2] is not None
    assert seen[0][2].startswith("tr-req-")
    assert "workspace_id" not in seen[0][3]
    assert seen[1][1] == "ws_default"
    assert seen[1][2] is not None
    assert seen[1][2].startswith("tr-req-")
    assert events[0]["event"] == "response.completed"


def test_async_chat_stream_and_chunk_stream_fail_over_before_first_byte(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("trustedrouter.client._retry_sleep", lambda *_args, **_kwargs: 0.0)
    seen: list[tuple[str, str | None]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.url.host or "", request.headers.get("idempotency-key")))
        if len(seen) in {1, 3}:
            return httpx.Response(503, json={"error": {"message": "region down"}})
        return httpx.Response(
            200,
            headers={"content-type": "text/event-stream"},
            content=(
                b'data: {"id":"chatcmpl_1","object":"chat.completion.chunk",'
                b'"choices":[{"index":0,"delta":{"content":"OK"}}]}\n\n'
                b"data: [DONE]\n\n"
            ),
        )

    async def run() -> tuple[list[str], int]:
        sdk = AsyncTrustedRouter(
            api_key="k",
            client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
            max_retries=1,
            regional_failover=True,
        )
        text = [
            token
            async for token in sdk.chat_completions_stream(
                model="m",
                messages=[{"role": "user", "content": "x"}],
            )
        ]
        chunks = [
            chunk
            async for chunk in sdk.chat_completions_chunk_stream(
                model="m",
                messages=[{"role": "user", "content": "x"}],
            )
        ]
        await sdk._client.aclose()
        return text, len(chunks)

    text, chunk_count = asyncio.run(run())

    assert text == ["OK"]
    assert chunk_count == 1
    assert [host for host, _ in seen] == [
        "api.trustedrouter.com",
        "api.trustedrouter.com",
        "api.trustedrouter.com",
        "api.trustedrouter.com",
    ]
    assert seen[0][1] == seen[1][1]
    assert seen[2][1] == seen[3][1]
    assert seen[0][1] != seen[2][1]


def test_async_responses_raw_stream_and_input_tokens_and_status() -> None:
    seen: list[tuple[str, str, dict[str, object] | None]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = jsonlib.loads(request.content.decode()) if request.content else None
        seen.append((request.method, request.url.path, body))
        if request.url.host == "status.example":
            return httpx.Response(200, json={"status": "ok"})
        if request.url.path == "/v1/responses/input_tokens":
            return httpx.Response(200, json={"input_tokens": 9, "total_tokens": 9})
        return httpx.Response(
            200,
            headers={"content-type": "text/event-stream"},
            content=b"event: response.created\n"
            b'data: {"type":"response.created"}\n\n'
            b"data: [DONE]\n\n",
        )

    async def run() -> tuple[bytes, int, str]:
        sdk = AsyncTrustedRouter(
            api_key="k",
            client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        )
        raw = b"".join([chunk async for chunk in sdk.responses_raw_stream(input="ping")])
        tokens = await sdk.responses_input_tokens(input="count me")
        status = await sdk.status("https://status.example/status.json")
        await sdk._client.aclose()
        return raw, tokens.input_tokens, str(status["status"])

    raw, input_tokens, status = asyncio.run(run())

    assert b"response.created" in raw
    assert input_tokens == 9
    assert status == "ok"
    assert seen[0][1] == "/v1/responses"
    assert seen[0][2] is not None
    assert seen[0][2]["stream"] is True
    assert seen[1][1] == "/v1/responses/input_tokens"
    assert seen[2][1] == "/status.json"


def test_async_responses_raw_stream_regional_failover_and_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("trustedrouter.client._retry_sleep", lambda *_args, **_kwargs: 0.0)
    seen_hosts: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_hosts.append(request.url.host or "")
        if len(seen_hosts) == 1:
            return httpx.Response(503, json={"error": {"message": "region down"}})
        return httpx.Response(
            200,
            headers={"content-type": "text/event-stream"},
            content=b"event: response.created\n"
            b'data: {"type":"response.created"}\n\n'
            b"data: [DONE]\n\n",
        )

    async def ok() -> bytes:
        sdk = AsyncTrustedRouter(
            api_key="k",
            client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
            max_retries=1,
            regional_failover=True,
        )
        raw = b"".join([chunk async for chunk in sdk.responses_raw_stream(input="ping")])
        await sdk._client.aclose()
        return raw

    assert b"response.created" in asyncio.run(ok())
    assert seen_hosts == ["api.trustedrouter.com", "api.trustedrouter.com"]

    def error_handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(501, json={"error": {"message": "nope"}})

    async def err() -> None:
        sdk = AsyncTrustedRouter(
            api_key="k",
            client=httpx.AsyncClient(transport=httpx.MockTransport(error_handler)),
            max_retries=0,
        )
        with pytest.raises(EndpointNotSupportedError):
            _ = [chunk async for chunk in sdk.responses_raw_stream(input="ping")]
        await sdk._client.aclose()

    asyncio.run(err())


def test_async_responses_stream_regional_failover_preserves_idempotency(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("trustedrouter.client._retry_sleep", lambda *_args, **_kwargs: 0.0)
    seen: list[tuple[str, str | None]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.url.host or "", request.headers.get("idempotency-key")))
        if len(seen) == 1:
            return httpx.Response(503, json={"error": {"message": "region down"}})
        return httpx.Response(
            200,
            headers={"content-type": "text/event-stream"},
            content=b"event: response.completed\n"
            b'data: {"type":"response.completed","response":{"id":"resp_1"}}\n\n'
            b"data: [DONE]\n\n",
        )

    async def run() -> list[dict[str, object]]:
        sdk = AsyncTrustedRouter(
            api_key="k",
            client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
            max_retries=1,
            regional_failover=True,
        )
        events = [event async for event in sdk.responses_stream(input="ping")]
        await sdk._client.aclose()
        return events

    events = asyncio.run(run())

    assert events[0]["event"] == "response.completed"
    assert seen[0] == ("api.trustedrouter.com", seen[0][1])
    assert seen[1] == ("api.trustedrouter.com", seen[0][1])


def test_async_broadcast_destination_helpers() -> None:
    seen: list[tuple[str, str, str | None]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(
            (
                request.method,
                request.url.path,
                request.headers.get("x-trustedrouter-workspace"),
            )
        )
        return httpx.Response(200, json={"data": {"id": "bdst_1"}})

    async def run() -> None:
        sdk = AsyncTrustedRouter(
            api_key="k",
            workspace_id="ws_default",
            client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        )
        await sdk.get_broadcast_destination("bdst_1", workspace_id="ws_override")
        await sdk.delete_broadcast_destination("bdst_1")
        await sdk._client.aclose()

    asyncio.run(run())
    assert seen == [
        ("GET", "/v1/broadcast/destinations/bdst_1", "ws_override"),
        ("DELETE", "/v1/broadcast/destinations/bdst_1", "ws_default"),
    ]


def test_async_broadcast_update_and_test_helpers() -> None:
    seen: list[tuple[str, str, dict[str, object] | None]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = jsonlib.loads(request.content.decode()) if request.content else None
        seen.append((request.method, request.url.path, body))
        return httpx.Response(200, json={"data": {"id": "bdst_1"}})

    async def run() -> None:
        sdk = AsyncTrustedRouter(
            api_key="k",
            client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        )
        await sdk.update_broadcast_destination("bdst_1", endpoint=None, enabled=True)
        await sdk.test_broadcast_destination("bdst_1")
        await sdk._client.aclose()

    asyncio.run(run())
    assert seen == [
        ("PATCH", "/v1/broadcast/destinations/bdst_1", {"enabled": True}),
        ("POST", "/v1/broadcast/destinations/bdst_1/test", None),
    ]


def test_async_activity_drops_none_params() -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(200, json={"data": []})

    async def run() -> None:
        sdk = AsyncTrustedRouter(
            api_key="k",
            client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        )
        await sdk.activity(since="2026-01-01", until=None, limit=5)
        await sdk._client.aclose()

    asyncio.run(run())
    assert "since=2026-01-01" in seen[0]
    assert "limit=5" in seen[0]
    assert "until=" not in seen[0]


# ---- User-Agent ---------------------------------------------------------


def test_user_agent_string_includes_sdk_python_httpx() -> None:
    ua = _user_agent()
    assert ua.startswith("trusted-router-py/")
    assert "python/" in ua
    assert "httpx/" in ua


def test_user_agent_sent_on_request() -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers.get("user-agent", ""))
        return httpx.Response(200, json={"data": []})

    sdk = TrustedRouter(api_key="k", client=httpx.Client(transport=httpx.MockTransport(handler)))
    sdk.models()
    sdk.close()
    assert seen[0].startswith("trusted-router-py/")
