"""Coverage for the v0.2 feature set: typed errors, retries, region
shortcut, per-call extras (headers/idempotency/timeout), embeddings,
messages, User-Agent header, async activity()."""
from __future__ import annotations

import asyncio
import json as jsonlib

import httpx
import pytest

from trustedrouter import (
    AsyncTrustedRouter,
    AuthenticationError,
    BadRequestError,
    InternalError,
    NotFoundError,
    PermissionDeniedError,
    RateLimitError,
    TrustedRouter,
    TrustedRouterError,
    region_base_url,
)
from trustedrouter.client import _retry_sleep, _user_agent

# ---- region shortcut ----------------------------------------------------


def test_region_base_url_known_regions() -> None:
    assert region_base_url("europe-west4") == "https://api-europe-west4.quillrouter.com/v1"
    assert region_base_url("us-central1") == "https://api.quillrouter.com/v1"


def test_region_base_url_rejects_unknown_region() -> None:
    with pytest.raises(ValueError, match="unknown TrustedRouter region"):
        region_base_url("mars-1")


def test_constructor_region_shortcut_sets_base_url() -> None:
    sdk = TrustedRouter(region="europe-west4")
    assert sdk.base_url == "https://api-europe-west4.quillrouter.com/v1"
    assert sdk.region == "europe-west4"
    sdk.close()


def test_constructor_region_and_base_url_collision_is_an_error() -> None:
    with pytest.raises(ValueError, match="OR base_url"):
        TrustedRouter(region="us-central1", base_url="https://custom.example/v1")


def test_async_constructor_region_shortcut() -> None:
    async def run() -> None:
        sdk = AsyncTrustedRouter(region="europe-west4")
        assert sdk.region == "europe-west4"
        assert sdk.base_url.endswith("api-europe-west4.quillrouter.com/v1")
        await sdk.aclose()

    asyncio.run(run())


def test_async_constructor_region_collision() -> None:
    with pytest.raises(ValueError, match="OR base_url"):
        AsyncTrustedRouter(region="us-central1", base_url="https://x/v1")


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
        (500, InternalError),
        (503, InternalError),
    ],
)
def test_status_codes_map_to_typed_subclasses(status: int, exc_class: type) -> None:
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


def test_rate_limit_error_with_invalid_retry_after_is_none() -> None:
    """Some servers send Retry-After as a date — we don't honor that
    form; fall back to None (and our exponential backoff)."""
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            429, headers={"Retry-After": "Tue, 15 Nov 2025 12:00:00 GMT"},
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
            return httpx.Response(429, headers={"Retry-After": "0"},
                                  json={"error": {"message": "x"}})
        return httpx.Response(200, json={"data": ["ok"]})

    sdk = TrustedRouter(
        api_key="k",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        max_retries=3,
    )
    out = sdk.models()
    assert out == {"data": ["ok"]}
    assert state["calls"] == 3
    sdk.close()


def test_request_retries_on_5xx_then_gives_up() -> None:
    """After max_retries+1 attempts of 5xx, the final response is raised."""
    state = {"calls": 0}

    def handler(_request: httpx.Request) -> httpx.Response:
        state["calls"] += 1
        return httpx.Response(503, headers={"Retry-After": "0"},
                              json={"error": {"message": "down"}})

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


def test_max_retries_zero_disables_retry_loop_entirely() -> None:
    state = {"calls": 0}

    def handler(_request: httpx.Request) -> httpx.Response:
        state["calls"] += 1
        return httpx.Response(503, headers={"Retry-After": "0"},
                              json={"error": {"message": "x"}})

    sdk = TrustedRouter(
        api_key="k",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        max_retries=0,
    )
    with pytest.raises(InternalError):
        sdk.models()
    assert state["calls"] == 1
    sdk.close()


def test_4xx_other_than_429_is_not_retried() -> None:
    """We should not retry 400/401/403/404 — those won't change."""
    state = {"calls": 0}

    def handler(_request: httpx.Request) -> httpx.Response:
        state["calls"] += 1
        return httpx.Response(401, json={"error": {"message": "x"}})

    sdk = TrustedRouter(
        api_key="k",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        max_retries=5,
    )
    with pytest.raises(AuthenticationError):
        sdk.models()
    assert state["calls"] == 1
    sdk.close()


def test_async_request_retries_on_503() -> None:
    state = {"calls": 0}

    def handler(_request: httpx.Request) -> httpx.Response:
        state["calls"] += 1
        if state["calls"] < 2:
            return httpx.Response(503, headers={"Retry-After": "0"},
                                  json={"error": {"message": "x"}})
        return httpx.Response(200, json={"data": []})

    async def run() -> None:
        sdk = AsyncTrustedRouter(
            api_key="k",
            client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
            max_retries=3,
        )
        result = await sdk.models()
        assert result == {"data": []}
        await sdk._client.aclose()

    asyncio.run(run())
    assert state["calls"] == 2


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
            200, headers={"content-type": "text/event-stream"},
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


def test_chat_completions_drops_reserved_kwargs_from_body() -> None:
    """If a caller spreads a dict into **params that includes our
    reserved kwargs (api_key, idempotency_key, etc.), they must not
    leak into the JSON body sent to the gateway."""
    bodies: list[dict[str, object]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        bodies.append(jsonlib.loads(request.content.decode()))
        return httpx.Response(
            200, headers={"content-type": "text/event-stream"},
            content=b'data: {"choices":[{"delta":{"content":"x"}}]}\n\ndata: [DONE]\n\n',
        )

    sdk = TrustedRouter(
        api_key="k",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        max_retries=0,
    )
    extra = {"temperature": 0.5, "api_key": "leaked", "idempotency_key": "leaked"}
    sdk.chat_completions(model="m", messages=[{"role": "user", "content": "hi"}], **extra)
    assert bodies[0]["temperature"] == 0.5
    assert "api_key" not in bodies[0]
    assert "idempotency_key" not in bodies[0]
    sdk.close()


# ---- embeddings + messages wrappers ------------------------------------


def test_sync_embeddings_only_sends_provided_optional_fields() -> None:
    bodies: list[dict[str, object]] = []

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
    )
    sdk.close()

    assert bodies[0] == {"model": "text-embed", "input": "hello"}
    assert bodies[1] == {
        "model": "text-embed",
        "input": ["a", "b"],
        "encoding_format": "base64",
        "dimensions": 512,
        "user": "u_42",
    }


def test_sync_messages_anthropic_shape() -> None:
    bodies: list[dict[str, object]] = []

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
    )
    sdk.close()

    assert bodies[0]["max_tokens"] == 64
    assert bodies[0]["system"] == "You are helpful."
    assert bodies[0]["messages"][0]["role"] == "user"


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
        await sdk.messages(model="anthropic/claude-3-5-sonnet",
                           messages=[{"role": "user", "content": "x"}])
        await sdk._client.aclose()

    asyncio.run(run())
    assert seen_paths == ["/v1/embeddings", "/v1/messages"]


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
