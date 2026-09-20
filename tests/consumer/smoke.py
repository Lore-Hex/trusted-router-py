"""Standalone, strictly typed consumer of the installed public API."""
import asyncio

import httpx

from trustedrouter import (
    AUTO_MODEL,
    AsyncTrustedRouter,
    ChatCompletion,
    ProviderPreferences,
    TrustedRouter,
    create_oauth_authorization,
    fusion_tool,
)


def respond(request: httpx.Request) -> httpx.Response:
    assert request.url.path == "/v1/chat/completions"
    return httpx.Response(200, headers={"content-type": "text/event-stream"}, content=(
        b'data: {"id":"consumer","choices":[{"index":0,"delta":'
        b'{"role":"assistant","content":"hello consumer"},"finish_reason":"stop"}]}\n\n'
        b'data: [DONE]\n\n'
    ))


with httpx.Client(transport=httpx.MockTransport(respond)) as transport:
    with TrustedRouter(api_key="fake", client=transport, telemetry=False) as client:
        response: ChatCompletion = client.chat_completions(
            model=AUTO_MODEL, messages=[{"role": "user", "content": "hello"}],
            provider=ProviderPreferences.confidential(),
        )
        content: str | None = response.choices[0].message.content
        assert content == "hello consumer"
        assert client.chat_completions.__doc__


async def main() -> None:
    async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as transport:
        async with AsyncTrustedRouter(api_key="fake", client=transport, telemetry=False) as client:
            response: ChatCompletion = await client.chat_completions(
                messages=[{"role": "user", "content": "hello"}],
            )
            assert response.choices[0].message.content == "hello consumer"


assert create_oauth_authorization(callback_url="https://example.com/callback").url
assert fusion_tool(preset="budget")
asyncio.run(main())
print("installed consumer passed")
