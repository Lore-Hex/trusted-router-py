"""Coverage for the code-review fixes:

- streaming stream-open errors now retry on the full _retryable set
  (429 + all 5xx), matching the non-streaming request() path, not just
  the {502,503,504} regional-failover subset;
- mutating non-stream POSTs (billing_checkout, messages) auto-generate
  an idempotency key so a retried 5xx can't double-charge / duplicate;
- attestation() threads a caller-supplied nonce as a query param and
  classifies error responses into the typed error hierarchy;
- sync/async public surface parity (chat_completions_raw_stream on the
  sync client, trust_release on the async client).

These follow the MockTransport style used across the suite."""
from __future__ import annotations

import asyncio
import inspect

import httpx
import pytest

from trustedrouter import (
    AsyncTrustedRouter,
    AuthenticationError,
    TrustedRouter,
)
from trustedrouter.client import TrustedRouterError


# ---- streaming retries on a plain 500 (not just 502/503/504) ------------


def test_chat_stream_retries_on_500_then_succeeds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A 500 during stream open is _retryable but NOT _regional_failoverable;
    before the fix the streaming path raised immediately. It must now retry
    (same key, same host since 500 doesn't failover) and then succeed."""
    monkeypatch.setattr("trustedrouter.client._retry_sleep", lambda *_a, **_k: 0.0)
    state = {"calls": 0}
    seen_hosts: list[str] = []
    seen_keys: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        state["calls"] += 1
        seen_hosts.append(request.url.host or "")
        seen_keys.append(request.headers.get("idempotency-key"))
        if state["calls"] == 1:
            return httpx.Response(500, text="boom")
        return httpx.Response(
            200,
            headers={"content-type": "text/event-stream"},
            content=b'data: {"choices":[{"delta":{"content":"OK"}}]}\n\n'
            b"data: [DONE]\n\n",
        )

    sdk = TrustedRouter(
        api_key="k",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        max_retries=2,
    )
    out = list(
        sdk.chat_completions_stream(model="m", messages=[{"role": "user", "content": "x"}])
    )
    sdk.close()
    assert out == ["OK"]
    assert state["calls"] == 2
    # 500 is not regional-failoverable, so the host must not change.
    assert seen_hosts == ["api.quillrouter.com", "api.quillrouter.com"]
    # Auto-keyed and stable across the retry so the retry is safe.
    assert seen_keys[0] is not None and seen_keys[0].startswith("tr-req-")
    assert seen_keys == [seen_keys[0], seen_keys[0]]


def test_async_chat_stream_retries_on_500_then_succeeds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("trustedrouter.client._retry_sleep", lambda *_a, **_k: 0.0)
    state = {"calls": 0}

    def handler(_request: httpx.Request) -> httpx.Response:
        state["calls"] += 1
        if state["calls"] == 1:
            return httpx.Response(500, text="boom")
        return httpx.Response(
            200,
            headers={"content-type": "text/event-stream"},
            content=b'data: {"choices":[{"delta":{"content":"OK"}}]}\n\n'
            b"data: [DONE]\n\n",
        )

    async def run() -> None:
        sdk = AsyncTrustedRouter(
            api_key="k",
            client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
            max_retries=2,
        )
        out = [
            t
            async for t in sdk.chat_completions_stream(
                model="m", messages=[{"role": "user", "content": "x"}]
            )
        ]
        await sdk._client.aclose()
        assert out == ["OK"]

    asyncio.run(run())
    assert state["calls"] == 2


def test_chat_stream_still_does_not_retry_4xx(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A 400 stream-open error is not _retryable — it must raise on the
    first attempt even with retries available (the fix must not widen
    retries to non-5xx/429 errors)."""
    monkeypatch.setattr("trustedrouter.client._retry_sleep", lambda *_a, **_k: 0.0)
    state = {"calls": 0}

    def handler(_request: httpx.Request) -> httpx.Response:
        state["calls"] += 1
        return httpx.Response(400, json={"error": {"message": "nope"}})

    sdk = TrustedRouter(
        api_key="k",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        max_retries=3,
    )
    with pytest.raises(TrustedRouterError) as exc_info:
        list(sdk.chat_completions_stream(model="m", messages=[{"role": "user", "content": "x"}]))
    sdk.close()
    assert exc_info.value.status_code == 400
    assert state["calls"] == 1


# ---- auto idempotency key on mutating non-stream POSTs ------------------


def test_billing_checkout_auto_keys_and_retries_5xx(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """billing_checkout must auto-generate an idempotency key and send the
    SAME key on the retried 5xx so the gateway can't double-charge."""
    monkeypatch.setattr("trustedrouter.client._retry_sleep", lambda *_a, **_k: 0.0)
    state = {"calls": 0}
    seen_keys: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        state["calls"] += 1
        seen_keys.append(request.headers.get("idempotency-key"))
        if state["calls"] == 1:
            return httpx.Response(503, text="stripe hiccup")
        return httpx.Response(200, json={"data": {"id": "cs_1", "url": "https://pay"}})

    sdk = TrustedRouter(
        api_key="k",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        max_retries=2,
    )
    sdk.billing_checkout(amount=2500)
    sdk.close()
    assert state["calls"] == 2
    assert seen_keys[0] is not None and seen_keys[0].startswith("tr-req-")
    assert seen_keys == [seen_keys[0], seen_keys[0]]


def test_billing_checkout_keeps_explicit_idempotency_key() -> None:
    seen_keys: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_keys.append(request.headers.get("idempotency-key"))
        return httpx.Response(200, json={"data": {"id": "cs_1", "url": "https://pay"}})

    sdk = TrustedRouter(
        api_key="k",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    sdk.billing_checkout(amount=10, idempotency_key="caller-key")
    sdk.close()
    assert seen_keys == ["caller-key"]


def test_messages_auto_keys_and_retries_5xx(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("trustedrouter.client._retry_sleep", lambda *_a, **_k: 0.0)
    state = {"calls": 0}
    seen_keys: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        state["calls"] += 1
        seen_keys.append(request.headers.get("idempotency-key"))
        if state["calls"] == 1:
            return httpx.Response(500, text="model hiccup")
        return httpx.Response(
            200,
            json={
                "id": "msg_1",
                "type": "message",
                "role": "assistant",
                "model": "m",
                "content": [{"type": "text", "text": "hi"}],
            },
        )

    sdk = TrustedRouter(
        api_key="k",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        max_retries=2,
    )
    sdk.messages(model="m", messages=[{"role": "user", "content": "hi"}])
    sdk.close()
    assert state["calls"] == 2
    assert seen_keys[0] is not None and seen_keys[0].startswith("tr-req-")
    assert seen_keys == [seen_keys[0], seen_keys[0]]


def test_async_messages_auto_keys() -> None:
    seen_keys: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_keys.append(request.headers.get("idempotency-key"))
        return httpx.Response(
            200,
            json={
                "id": "msg_1",
                "type": "message",
                "role": "assistant",
                "model": "m",
                "content": [{"type": "text", "text": "hi"}],
            },
        )

    async def run() -> None:
        sdk = AsyncTrustedRouter(
            api_key="k",
            client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        )
        await sdk.messages(model="m", messages=[{"role": "user", "content": "hi"}])
        await sdk._client.aclose()

    asyncio.run(run())
    assert seen_keys[0] is not None and seen_keys[0].startswith("tr-req-")


# ---- attestation nonce threading + error classification -----------------


def test_attestation_sends_nonce_query_param() -> None:
    seen_urls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_urls.append(str(request.url))
        assert request.url.path == "/attestation"
        return httpx.Response(200, content=b"<JWT>")

    sdk = TrustedRouter(
        api_key="k",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    nonce = "deadbeef" * 4
    assert sdk.attestation(nonce=nonce) == b"<JWT>"
    sdk.close()
    assert f"nonce={nonce}" in seen_urls[0]


def test_attestation_without_nonce_sends_no_query() -> None:
    seen_urls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_urls.append(str(request.url))
        return httpx.Response(200, content=b"<JWT>")

    sdk = TrustedRouter(
        api_key="k",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    sdk.attestation()
    sdk.close()
    assert "nonce=" not in seen_urls[0]
    assert seen_urls[0].endswith("/attestation")


def test_attestation_401_raises_authentication_error() -> None:
    """attestation() must classify a 401 into AuthenticationError (a typed
    subclass) instead of the bare TrustedRouterError base."""

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, text="missing bearer")

    sdk = TrustedRouter(
        api_key="bad",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    with pytest.raises(AuthenticationError) as exc_info:
        sdk.attestation()
    sdk.close()
    assert exc_info.value.status_code == 401


def test_async_attestation_sends_nonce_and_classifies_401() -> None:
    nonce = "cafebabe" * 4

    def ok_handler(request: httpx.Request) -> httpx.Response:
        assert f"nonce={nonce}" in str(request.url)
        return httpx.Response(200, content=b"<JWT>")

    def err_handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, text="missing bearer")

    async def run() -> None:
        ok = AsyncTrustedRouter(
            api_key="k",
            client=httpx.AsyncClient(transport=httpx.MockTransport(ok_handler)),
        )
        assert await ok.attestation(nonce=nonce) == b"<JWT>"
        await ok._client.aclose()

        bad = AsyncTrustedRouter(
            api_key="bad",
            client=httpx.AsyncClient(transport=httpx.MockTransport(err_handler)),
        )
        with pytest.raises(AuthenticationError) as exc_info:
            await bad.attestation()
        await bad._client.aclose()
        assert exc_info.value.status_code == 401

    asyncio.run(run())


# ---- sync/async public-surface parity -----------------------------------


def _public_method_names(cls: type) -> set[str]:
    names: set[str] = set()
    for name, member in inspect.getmembers(cls):
        if name.startswith("_"):
            continue
        if inspect.isfunction(member) or inspect.iscoroutinefunction(member):
            names.add(name)
    return names


def test_sync_and_async_clients_expose_matching_public_methods() -> None:
    """Every public method on TrustedRouter must have an async twin on
    AsyncTrustedRouter and vice versa (modulo sync/async). Guards against
    the surface drifting again (sync lacked chat_completions_raw_stream;
    async lacked trust_release)."""
    sync_only = {"close"}  # async equivalent is `aclose`
    async_only = {"aclose"}

    sync_names = _public_method_names(TrustedRouter) - sync_only
    async_names = _public_method_names(AsyncTrustedRouter) - async_only

    assert sync_names == async_names, {
        "sync_only": sorted(sync_names - async_names),
        "async_only": sorted(async_names - sync_names),
    }
    # The two specific gaps the fix closed must now be present.
    assert "chat_completions_raw_stream" in sync_names
    assert "trust_release" in async_names


def test_sync_chat_completions_raw_stream_passes_through_bytes() -> None:
    raw = b'data: {"choices":[{"delta":{"content":"hi"}}]}\n\n' b"data: [DONE]\n\n"

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, headers={"content-type": "text/event-stream"}, content=raw
        )

    sdk = TrustedRouter(
        api_key="k",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    out = b"".join(
        sdk.chat_completions_raw_stream(
            model="m", messages=[{"role": "user", "content": "x"}]
        )
    )
    sdk.close()
    assert out == raw


def test_async_trust_release_returns_parsed_json() -> None:
    payload = {"image_digest": "sha256:abc", "source_commit": "deadbeef"}

    def handler(request: httpx.Request) -> httpx.Response:
        assert "test-trust" in str(request.url)
        return httpx.Response(200, json=payload)

    async def run() -> None:
        sdk = AsyncTrustedRouter(
            api_key="k",
            client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        )
        out = await sdk.trust_release(url="https://test-trust.example/release.json")
        await sdk._client.aclose()
        assert out.image_digest == "sha256:abc"

    asyncio.run(run())
