"""Coverage for AsyncTrustedRouter's request-shaped wrappers.

Each test mounts a tiny MockTransport handler that records the inbound
request shape and returns a canned 200, then asserts both the URL/body
the SDK sent AND the parsed response shape it returns. This is the
contract the production gateway expects — if either side drifts, these
tests catch it before a customer does.

The async streaming methods (chunk_stream, error path, client= injection)
are exercised in test_client.py; this file focuses on every NON-streaming
async surface that previously had zero coverage."""
from __future__ import annotations

import asyncio
import json as jsonlib

import httpx
import pytest

from trustedrouter import AUTO_MODEL, DEFAULT_API_BASE_URL, AsyncTrustedRouter
from trustedrouter.client import TrustedRouterError


def _run(coro):  # type: ignore[no-untyped-def]
    return asyncio.run(coro)


def _async_client(handler):  # type: ignore[no-untyped-def]
    return AsyncTrustedRouter(
        api_key="sk-tr-async",
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )


# ---- non-streaming GET wrappers -----------------------------------------


def test_async_models_providers_regions_credits_send_get_with_bearer() -> None:
    """All four GET wrappers route through the same `request()` plumbing
    that injects the bearer header and resolves the URL relative to
    base_url. We assert all four in one test to keep the noise down."""
    seen: list[tuple[str, str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.method, str(request.url), request.headers.get("authorization", "")))
        return httpx.Response(200, json={"data": [{"id": "stub"}]})

    sdk = _async_client(handler)

    async def run() -> None:
        assert (await sdk.models())["data"][0]["id"] == "stub"
        assert (await sdk.providers())["data"][0]["id"] == "stub"
        assert (await sdk.regions())["data"][0]["id"] == "stub"
        assert (await sdk.credits())["data"][0]["id"] == "stub"
        await sdk._client.aclose()

    _run(run())

    expected_paths = ["/models", "/providers", "/regions", "/credits"]
    assert [p for _, url, _ in seen for p in expected_paths if url.endswith(p)] == expected_paths
    # Every call sent the bearer.
    assert all(auth == "Bearer sk-tr-async" for _, _, auth in seen)


def test_async_attestation_returns_raw_bytes_and_raises_on_error() -> None:
    """attestation() must return the response body verbatim (the JWT
    bytes) and translate non-2xx into TrustedRouterError so callers can
    surface gateway outages cleanly."""
    state: dict[str, int] = {"calls": 0}

    def ok(_request: httpx.Request) -> httpx.Response:
        state["calls"] += 1
        # The endpoint is at the API root, NOT under /v1.
        assert _request.url.path == "/attestation"
        return httpx.Response(200, content=b"<JWT-BYTES>")

    sdk = _async_client(ok)

    async def good() -> None:
        doc = await sdk.attestation()
        assert doc == b"<JWT-BYTES>"
        await sdk._client.aclose()

    _run(good())
    assert state["calls"] == 1

    def bad(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, text="enclave booting")

    sdk2 = _async_client(bad)

    async def err() -> None:
        with pytest.raises(TrustedRouterError) as exc_info:
            await sdk2.attestation()
        assert exc_info.value.status_code == 503
        assert "enclave booting" in str(exc_info.value)
        await sdk2._client.aclose()

    _run(err())


# ---- non-streaming POST wrappers ----------------------------------------


def test_async_billing_checkout_only_sends_provided_fields() -> None:
    """The wrapper omits None fields so the gateway sees a minimal body
    rather than `{"workspace_id": null}` — matters because Stripe would
    treat null differently from absent."""
    seen_bodies: list[dict[str, object]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_bodies.append(jsonlib.loads(request.content.decode() or "{}"))
        return httpx.Response(200, json={"data": {"url": "https://stripe.test/sess_abc"}})

    sdk = _async_client(handler)

    async def run() -> None:
        # Minimal: only required `amount`
        await sdk.billing_checkout(amount=10)
        # Maximal: every optional present
        await sdk.billing_checkout(
            amount=25,
            payment_method="stablecoin",
            workspace_id="ws_x",
            success_url="https://app.test/ok",
            cancel_url="https://app.test/cancel",
        )
        await sdk._client.aclose()

    _run(run())

    assert seen_bodies[0] == {"amount": 10}
    assert seen_bodies[1] == {
        "amount": 25,
        "payment_method": "stablecoin",
        "workspace_id": "ws_x",
        "success_url": "https://app.test/ok",
        "cancel_url": "https://app.test/cancel",
    }


def test_async_stablecoin_checkout_pins_payment_method() -> None:
    """stablecoin_checkout is a one-line shorthand — verify it always
    pins payment_method=stablecoin so callers can't accidentally route
    a stablecoin charge through the card processor."""
    seen: list[dict[str, object]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(jsonlib.loads(request.content.decode()))
        return httpx.Response(200, json={"data": {"ok": True}})

    sdk = _async_client(handler)

    async def run() -> None:
        await sdk.stablecoin_checkout(amount=50, workspace_id="ws_y")
        await sdk._client.aclose()

    _run(run())

    assert seen == [{"amount": 50, "payment_method": "stablecoin", "workspace_id": "ws_y"}]


def test_async_auth_session_and_logout_target_correct_paths() -> None:
    seen: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.method, request.url.path))
        return httpx.Response(200, json={"data": {"who": "you"}})

    sdk = _async_client(handler)

    async def run() -> None:
        await sdk.auth_session()
        await sdk.logout()
        await sdk._client.aclose()

    _run(run())

    assert seen == [("GET", "/v1/auth/session"), ("POST", "/v1/auth/logout")]


# ---- async chat_completions (collected, non-streaming) ------------------


def test_async_chat_completions_collected_uses_default_auto_model() -> None:
    """If model is omitted, AUTO_MODEL is used — that's the SDK's
    "Just Work" default. Also verifies the SSE→single-dict collation
    path is wired correctly for the async client."""
    seen_bodies: list[dict[str, object]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_bodies.append(jsonlib.loads(request.content.decode()))
        body = (
            b'data: {"id":"x","model":"a","choices":[{"delta":{"content":"hello"}}]}\n\n'
            b'data: {"id":"x","model":"a","choices":[{"delta":{"content":" world"},'
            b'"finish_reason":"stop"}]}\n\n'
            b"data: [DONE]\n\n"
        )
        return httpx.Response(
            200, headers={"content-type": "text/event-stream"}, content=body
        )

    sdk = _async_client(handler)

    async def run() -> dict[str, object]:
        result = await sdk.chat_completions(
            messages=[{"role": "user", "content": "hi"}],
        )
        await sdk._client.aclose()
        return result

    result = _run(run())
    assert seen_bodies[0]["model"] == AUTO_MODEL
    assert seen_bodies[0]["stream"] is True
    assert result["object"] == "chat.completion"
    assert result["choices"][0]["message"]["content"] == "hello world"
    assert result["choices"][0]["finish_reason"] == "stop"


def test_async_chat_completions_collected_raises_on_4xx() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, json={"error": {"message": "bad model"}})

    sdk = _async_client(handler)

    async def run() -> None:
        with pytest.raises(TrustedRouterError) as exc_info:
            await sdk.chat_completions(messages=[{"role": "user", "content": "x"}])
        assert exc_info.value.status_code == 400
        await sdk._client.aclose()

    _run(run())


# ---- async raw stream pass-through --------------------------------------


def test_async_chat_completions_raw_stream_passes_through_bytes() -> None:
    """raw_stream must hand back the underlying SSE bytes verbatim —
    used by HTTP proxy frontends that want zero parsing overhead."""
    body = b"data: {\"x\":1}\n\ndata: [DONE]\n\n"

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, headers={"content-type": "text/event-stream"}, content=body
        )

    sdk = _async_client(handler)

    async def run() -> bytes:
        chunks: list[bytes] = []
        async for c in sdk.chat_completions_raw_stream(
            model=AUTO_MODEL, messages=[{"role": "user", "content": "x"}]
        ):
            chunks.append(c)
        await sdk._client.aclose()
        return b"".join(chunks)

    assembled = _run(run())
    assert b"data: {\"x\":1}" in assembled
    assert b"[DONE]" in assembled


def test_async_chat_completions_raw_stream_raises_on_error() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, text="rate limited")

    sdk = _async_client(handler)

    async def run() -> None:
        with pytest.raises(TrustedRouterError) as exc_info:
            async for _ in sdk.chat_completions_raw_stream(
                model=AUTO_MODEL, messages=[{"role": "user", "content": "x"}]
            ):
                pass
        assert exc_info.value.status_code == 429
        await sdk._client.aclose()

    _run(run())


# ---- async constructor: verify owned-client branch ---------------------


def test_async_owned_client_aclose_closes_underlying_transport() -> None:
    """When AsyncTrustedRouter creates its own client (no client= passed),
    aclose() must close it. Mirror of the sync owned-close test."""

    async def run() -> None:
        sdk = AsyncTrustedRouter(api_key="k", base_url=DEFAULT_API_BASE_URL)
        assert sdk._owns_client is True
        underlying = sdk._client
        await sdk.aclose()
        assert underlying.is_closed

    _run(run())


def test_async_context_manager_aclose_runs_on_exit() -> None:
    """`async with AsyncTrustedRouter(...)` should aclose owned client."""

    async def run() -> None:
        async with AsyncTrustedRouter(api_key="k") as sdk:
            assert sdk._owns_client is True
            underlying = sdk._client
        assert underlying.is_closed

    _run(run())
