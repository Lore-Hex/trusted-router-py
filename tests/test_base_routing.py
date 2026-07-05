from __future__ import annotations

import asyncio

import httpx

from trustedrouter import (
    AsyncTrustedRouter,
    TrustedRouter,
    exchange_oauth_key,
    exchange_oauth_key_async,
)


def _routing_response(request: httpx.Request) -> httpx.Response:
    path = request.url.path
    if path == "/v1/chat/completions":
        return httpx.Response(
            200,
            headers={"content-type": "text/event-stream"},
            content=b'data: {"choices":[{"delta":{"content":"ok"}}]}\n\ndata: [DONE]\n\n',
        )
    if path == "/v1/messages":
        return httpx.Response(200, json={"id": "msg_1", "content": []})
    if path == "/v1/responses":
        return httpx.Response(200, json={"id": "resp_1", "object": "response"})
    if path == "/v1/embeddings":
        return httpx.Response(200, json={"data": []})
    if path in {"/v1/models", "/v1/providers"}:
        return httpx.Response(200, json={"data": []})
    if path == "/v1/credits":
        return httpx.Response(200, json={"data": {}})
    if path == "/v1/broadcast/destinations":
        return httpx.Response(200, json={"data": []})
    if path == "/v1/billing/checkout":
        return httpx.Response(200, json={"data": {"url": "https://checkout.example"}})
    if path == "/v1/auth/keys":
        return httpx.Response(200, json={"key": "sk-tr-v1-test", "user_id": "user_1"})
    return httpx.Response(404, json={"error": {"message": f"unexpected path {path}"}})


def test_sync_methods_route_to_inference_or_control_base() -> None:
    seen: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.url.host or "", request.url.path))
        return _routing_response(request)

    raw_client = httpx.Client(transport=httpx.MockTransport(handler))
    sdk = TrustedRouter(
        api_key="k",
        base_url="https://inference.example/v1",
        control_base_url="https://control.example/v1",
        client=raw_client,
    )

    list(sdk.chat_completions_stream(model="m", messages=[{"role": "user", "content": "x"}]))
    sdk.messages(model="m", messages=[{"role": "user", "content": "x"}])
    sdk.responses(input="x")
    sdk.embeddings(model="e", input="x")
    sdk.models()
    sdk.providers()
    sdk.credits()
    sdk.broadcast_destinations()
    sdk.billing_checkout(amount=10)
    exchange_oauth_key(code="code", base_url="https://control.example/v1", client=raw_client)
    raw_client.close()

    assert seen == [
        ("inference.example", "/v1/chat/completions"),
        ("inference.example", "/v1/messages"),
        ("inference.example", "/v1/responses"),
        ("inference.example", "/v1/embeddings"),
        ("control.example", "/v1/models"),
        ("control.example", "/v1/providers"),
        ("control.example", "/v1/credits"),
        ("control.example", "/v1/broadcast/destinations"),
        ("control.example", "/v1/billing/checkout"),
        ("control.example", "/v1/auth/keys"),
    ]


def test_async_methods_route_to_inference_or_control_base() -> None:
    seen: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.url.host or "", request.url.path))
        return _routing_response(request)

    async def run() -> None:
        raw_client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        sdk = AsyncTrustedRouter(
            api_key="k",
            base_url="https://inference.example/v1",
            control_base_url="https://control.example/v1",
            client=raw_client,
        )

        _ = [
            token
            async for token in sdk.chat_completions_stream(
                model="m", messages=[{"role": "user", "content": "x"}]
            )
        ]
        await sdk.messages(model="m", messages=[{"role": "user", "content": "x"}])
        await sdk.responses(input="x")
        await sdk.embeddings(model="e", input="x")
        await sdk.models()
        await sdk.providers()
        await sdk.credits()
        await sdk.broadcast_destinations()
        await sdk.billing_checkout(amount=10)
        await exchange_oauth_key_async(
            code="code",
            base_url="https://control.example/v1",
            client=raw_client,
        )
        await raw_client.aclose()

    asyncio.run(run())

    assert seen == [
        ("inference.example", "/v1/chat/completions"),
        ("inference.example", "/v1/messages"),
        ("inference.example", "/v1/responses"),
        ("inference.example", "/v1/embeddings"),
        ("control.example", "/v1/models"),
        ("control.example", "/v1/providers"),
        ("control.example", "/v1/credits"),
        ("control.example", "/v1/broadcast/destinations"),
        ("control.example", "/v1/billing/checkout"),
        ("control.example", "/v1/auth/keys"),
    ]
