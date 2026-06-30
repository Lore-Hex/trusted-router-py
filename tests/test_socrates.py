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


def test_sync_chat_completions_lifts_direct_advisor_options_into_tool() -> None:
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
    resp = sdk.chat_completions(
        model=ADVISOR_MODEL,
        messages=[{"role": "user", "content": "hi"}],
        worker_models=["moonshotai/kimi-k2.7-code"],
        advisor_models=["z-ai/glm-5.2"],
        max_get_advice_calls=1,
    )
    assert seen["model"] == ADVISOR_MODEL
    assert seen["tools"] == [
        {
            "type": "trustedrouter:advisor",
            "parameters": {
                "worker_models": ["moonshotai/kimi-k2.7-code"],
                "advisor_models": ["z-ai/glm-5.2"],
                "max_get_advice_calls": 1,
            },
        }
    ]
    assert "worker_models" not in seen
    assert "advisor_models" not in seen
    assert "max_get_advice_calls" not in seen
    assert resp.choices[0].message.content == "ok"
    sdk.close()


def test_sync_chat_completions_lifts_direct_synth_options_into_tool() -> None:
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
    sdk.chat_completions(
        model="trustedrouter/synth",
        messages=[{"role": "user", "content": "hi"}],
        analysis_models=["moonshotai/kimi-k2.7-code", "z-ai/glm-5.2"],
        judge_model="moonshotai/kimi-k2.7-code",
        fallback_final_models=["z-ai/glm-5.2"],
    )
    assert seen["tools"] == [
        {
            "type": "trustedrouter:fusion",
            "parameters": {
                "analysis_models": ["moonshotai/kimi-k2.7-code", "z-ai/glm-5.2"],
                "model": "moonshotai/kimi-k2.7-code",
                "fallback_final_models": ["z-ai/glm-5.2"],
            },
        }
    ]
    assert "analysis_models" not in seen
    assert "judge_model" not in seen
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


@pytest.mark.asyncio
async def test_async_chat_completions_lifts_direct_advisor_options_into_tool() -> None:
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
    resp = await sdk.chat_completions(
        model=ADVISOR_MODEL,
        messages=[{"role": "user", "content": "hi"}],
        worker_models=["moonshotai/kimi-k2.7-code"],
        advisor_models=["z-ai/glm-5.2"],
    )
    assert seen["tools"][0]["type"] == "trustedrouter:advisor"
    assert seen["tools"][0]["parameters"] == {
        "worker_models": ["moonshotai/kimi-k2.7-code"],
        "advisor_models": ["z-ai/glm-5.2"],
    }
    assert "worker_models" not in seen
    assert "advisor_models" not in seen
    assert resp.choices[0].message.content == "ok"
    await sdk.aclose()
