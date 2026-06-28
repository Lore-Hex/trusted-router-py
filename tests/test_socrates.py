from __future__ import annotations

import json as jsonlib

import httpx
import pytest

from trustedrouter import (
    ADVISOR_MODEL,
    SOCRATES_MODEL,
    AsyncTrustedRouter,
    TrustedRouter,
    advisor_tool,
)

_SSE = (
    b'data: {"id":"r","model":"m","choices":[{"delta":{"content":"ok"},'
    b'"finish_reason":"stop"}]}\n\n'
    b"data: [DONE]\n\n"
)


def test_advisor_tool_only_sets_provided_fields() -> None:
    assert advisor_tool(
        depth=2,
        worker_models=["cerebras/gpt-oss-120b"],
        advisor_models=["anthropic/claude-opus-4.8"],
        max_get_advice_calls=1,
        advisor_max_tokens=4096,
        advisor_timeout_ms=90000,
    ) == {
        "type": "trustedrouter:advisor",
        "parameters": {
            "depth": 2,
            "worker_models": ["cerebras/gpt-oss-120b"],
            "advisor_models": ["anthropic/claude-opus-4.8"],
            "max_get_advice_calls": 1,
            "advisor_max_tokens": 4096,
            "advisor_timeout_ms": 90000,
        },
    }


def test_advisor_tool_empty_by_default() -> None:
    assert advisor_tool()["parameters"] == {}


def test_sync_socrates_posts_socrates_model_with_tool() -> None:
    seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen.update(jsonlib.loads(request.content.decode()))
        return httpx.Response(
            200, headers={"content-type": "text/event-stream"}, content=_SSE
        )

    sdk = TrustedRouter(
        api_key="sk-tr-sync",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    resp = sdk.socrates(
        messages=[{"role": "user", "content": "hi"}],
        depth=2,
        advisor_models=[ADVISOR_MODEL],
        max_get_advice_calls=1,
    )
    assert seen["model"] == SOCRATES_MODEL
    assert len(seen["tools"]) == 1
    assert seen["tools"][0]["type"] == "trustedrouter:advisor"
    assert seen["tools"][0]["parameters"] == {
        "depth": 2,
        "advisor_models": [ADVISOR_MODEL],
        "max_get_advice_calls": 1,
    }
    assert resp.choices[0].message.content == "ok"
    sdk.close()


@pytest.mark.asyncio
async def test_async_socrates_posts_socrates_model_with_tool() -> None:
    seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen.update(jsonlib.loads(request.content.decode()))
        return httpx.Response(
            200, headers={"content-type": "text/event-stream"}, content=_SSE
        )

    sdk = AsyncTrustedRouter(
        api_key="sk-tr-async",
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )
    resp = await sdk.socrates(
        messages=[{"role": "user", "content": "hi"}],
        worker_models=["cerebras/gpt-oss-120b"],
        advisor_timeout_ms=90000,
    )
    assert seen["model"] == SOCRATES_MODEL
    assert seen["tools"][0]["type"] == "trustedrouter:advisor"
    assert seen["tools"][0]["parameters"] == {
        "worker_models": ["cerebras/gpt-oss-120b"],
        "advisor_timeout_ms": 90000,
    }
    assert resp.choices[0].message.content == "ok"
    await sdk.aclose()
