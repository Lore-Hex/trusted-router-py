from __future__ import annotations

import asyncio
import json as jsonlib

import httpx
import pytest

from trustedrouter import (
    AUTO_MODEL,
    DEFAULT_API_BASE_URL,
    AsyncTrustedRouter,
    TrustedRouter,
)
from trustedrouter.client import TrustedRouterError


def test_client_normalizes_base_url() -> None:
    client = TrustedRouter(base_url=DEFAULT_API_BASE_URL + "/")
    assert client.base_url == DEFAULT_API_BASE_URL
    client.close()


def test_request_sends_bearer_token() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["authorization"] == "Bearer sk-tr-test"
        assert str(request.url) == f"{DEFAULT_API_BASE_URL}/models"
        return httpx.Response(200, json={"data": []})

    client = TrustedRouter(api_key="sk-tr-test")
    client._client = httpx.Client(transport=httpx.MockTransport(handler))

    assert client.models().data == []
    client.close()


def test_auto_model_constant_and_region_provider_helpers() -> None:
    seen: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.method, str(request.url)))
        if str(request.url).endswith("/regions"):
            return httpx.Response(
                200,
                json={"data": [{"id": "us-central1"}, {"id": "europe-west4"}]},
            )
        if str(request.url).endswith("/providers"):
            return httpx.Response(200, json={"data": [{"id": "vertex"}]})
        return httpx.Response(404, json={"error": {"message": "missing"}})

    client = TrustedRouter(api_key="sk-tr-test")
    client._client = httpx.Client(transport=httpx.MockTransport(handler))

    assert AUTO_MODEL == "trustedrouter/auto"
    assert client.regions().data[1].id == "europe-west4"
    assert client.providers().data[0].id == "vertex"
    assert seen == [
        ("GET", f"{DEFAULT_API_BASE_URL}/regions"),
        ("GET", f"{DEFAULT_API_BASE_URL}/providers"),
    ]
    client.close()


def test_checkout_and_auth_helpers_send_expected_shapes() -> None:
    calls: list[tuple[str, str, dict[str, object]]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = jsonlib.loads(request.content.decode() or "{}")
        calls.append((request.method, str(request.url), body))
        return httpx.Response(200, json={"data": {"ok": True}})

    client = TrustedRouter(api_key="session")
    client._client = httpx.Client(transport=httpx.MockTransport(handler))

    client.stablecoin_checkout(amount=25, workspace_id="ws_1")
    client.auth_session()
    client.logout()

    assert calls[0] == (
        "POST",
        f"{DEFAULT_API_BASE_URL}/billing/checkout",
        {"amount": 25, "payment_method": "stablecoin", "workspace_id": "ws_1"},
    )
    assert calls[1][1] == f"{DEFAULT_API_BASE_URL}/auth/session"
    assert calls[2] == (
        "POST",
        f"{DEFAULT_API_BASE_URL}/auth/logout",
        {},
    )
    client.close()


def test_error_payload_raises_trusted_router_error() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": {"message": "bad key"}})

    client = TrustedRouter(api_key="sk-tr-test")
    client._client = httpx.Client(transport=httpx.MockTransport(handler))

    with pytest.raises(TrustedRouterError) as exc_info:
        client.models()

    assert exc_info.value.status_code == 401
    assert str(exc_info.value) == "bad key"
    client.close()


# ---- client= injection ---------------------------------------------------


def test_caller_owned_client_not_closed_by_close() -> None:
    """When the caller passes their own httpx.Client, close() is a no-op
    so the caller can keep using the client after the SDK wrapper is done."""
    transport = httpx.MockTransport(lambda _r: httpx.Response(200, json={"ok": True}))
    external = httpx.Client(transport=transport)

    sdk = TrustedRouter(client=external)
    assert sdk._owns_client is False
    sdk.close()
    assert not external.is_closed, "caller-owned client must survive sdk.close()"
    external.close()


def test_async_caller_owned_client_not_closed_by_aclose() -> None:
    transport = httpx.MockTransport(lambda _r: httpx.Response(200, json={"ok": True}))
    external = httpx.AsyncClient(transport=transport)

    async def run() -> None:
        sdk = AsyncTrustedRouter(client=external)
        assert sdk._owns_client is False
        await sdk.aclose()
        assert not external.is_closed, "caller-owned async client must survive aclose"
        await external.aclose()

    asyncio.run(run())


def test_owned_client_closed_by_close() -> None:
    """Conversely, the SDK's auto-created client IS closed by close()."""
    sdk = TrustedRouter()
    assert sdk._owns_client is True
    underlying = sdk._client
    sdk.close()
    assert underlying.is_closed


# ---- per-call api_key override ------------------------------------------


def test_chat_completions_per_call_api_key_overrides_instance_key() -> None:
    """Passing `api_key=` to a chat method must use that key for the
    single call without mutating self.api_key. This is the threadsafe
    path the device's validate_bearer relies on."""
    seen_auth: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_auth.append(request.headers.get("authorization", ""))
        body = b'data: {"choices":[{"delta":{"content":"hi"}}]}\n\n' b"data: [DONE]\n\n"
        return httpx.Response(
            200, headers={"content-type": "text/event-stream"}, content=body
        )

    client = TrustedRouter(api_key="instance-key")
    client._client = httpx.Client(transport=httpx.MockTransport(handler))

    list(
        client.chat_completions_chunk_stream(
            model="m", messages=[{"role": "user", "content": "x"}], api_key="override-key"
        )
    )
    list(
        client.chat_completions_chunk_stream(
            model="m", messages=[{"role": "user", "content": "x"}]
        )
    )

    assert seen_auth == ["Bearer override-key", "Bearer instance-key"]
    assert client.api_key == "instance-key", "instance key must be untouched"
    client.close()


# ---- sync chat_completions_chunk_stream ---------------------------------


def test_chat_completions_chunk_stream_yields_parsed_chunks() -> None:
    chunks_sse = (
        b'data: {"id":"1","choices":[{"delta":{"content":"hello"}}]}\n\n'
        b'data: {"id":"1","choices":[{"delta":{"content":" world"},"finish_reason":"stop"}]}\n\n'
        b"data: [DONE]\n\n"
    )

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, headers={"content-type": "text/event-stream"}, content=chunks_sse
        )

    client = TrustedRouter(api_key="k")
    client._client = httpx.Client(transport=httpx.MockTransport(handler))

    out = list(
        client.chat_completions_chunk_stream(
            model="m", messages=[{"role": "user", "content": "hi"}]
        )
    )
    assert len(out) == 2
    assert out[0].choices[0].delta.content == "hello"
    assert out[1].choices[0].finish_reason == "stop"
    client.close()


def test_chat_completions_chunk_stream_raises_on_error_status() -> None:
    """4xx during stream-open must raise TrustedRouterError before any
    chunk is yielded — so callers can surface auth failures synchronously
    instead of mid-stream."""

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": {"message": "Invalid API key"}})

    client = TrustedRouter(api_key="bad")
    client._client = httpx.Client(transport=httpx.MockTransport(handler))

    with pytest.raises(TrustedRouterError) as exc_info:
        list(
            client.chat_completions_chunk_stream(
                model="m", messages=[{"role": "user", "content": "hi"}]
            )
        )
    assert exc_info.value.status_code == 401
    client.close()


# ---- async chat_completions_chunk_stream --------------------------------


def test_async_chat_completions_chunk_stream_yields_and_errors() -> None:
    chunks_sse = (
        b'data: {"choices":[{"delta":{"content":"a"}}]}\n\n'
        b'data: {"choices":[{"delta":{"content":"b"},"finish_reason":"stop"}]}\n\n'
        b"data: [DONE]\n\n"
    )

    def ok_handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, headers={"content-type": "text/event-stream"}, content=chunks_sse
        )

    def err_handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": {"message": "nope"}})

    async def run() -> None:
        ok = AsyncTrustedRouter(
            api_key="k", client=httpx.AsyncClient(transport=httpx.MockTransport(ok_handler))
        )
        chunks = [
            c
            async for c in ok.chat_completions_chunk_stream(
                model="m", messages=[{"role": "user", "content": "x"}]
            )
        ]
        assert [c.choices[0].delta.content for c in chunks] == ["a", "b"]
        await ok._client.aclose()

        bad = AsyncTrustedRouter(
            api_key="k", client=httpx.AsyncClient(transport=httpx.MockTransport(err_handler))
        )
        with pytest.raises(TrustedRouterError) as exc_info:
            async for _ in bad.chat_completions_chunk_stream(
                model="m", messages=[{"role": "user", "content": "x"}]
            ):
                pass
        assert exc_info.value.status_code == 401
        await bad._client.aclose()

    asyncio.run(run())
