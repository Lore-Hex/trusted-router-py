"""Coverage for the TrustedRouter Fusion helper: the ``fusion_tool()`` builder
and the sync/async ``fusion(...)`` client methods. No real network — a MockTransport
records the request body and we assert the fusion tool shape."""
from __future__ import annotations

import json as jsonlib

import httpx
import pytest

from trustedrouter import (
    FUSION_FREEDOM_FALLBACK_JUDGES,
    FUSION_FREEDOM_PANEL,
    FUSION_MODEL,
    AsyncTrustedRouter,
    TrustedRouter,
    fusion_tool,
)

_SSE = (
    b'data: {"id":"r","model":"m","choices":[{"delta":{"content":"ok"},'
    b'"finish_reason":"stop"}]}\n\n'
    b"data: [DONE]\n\n"
)


def test_fusion_tool_only_sets_provided_fields() -> None:
    tool = fusion_tool(
        analysis_models=["a", "b"],
        model="z-ai/glm-5.1",
        selection_strategy="first_non_refusal",
        fallback_judges=["j1", "j2"],
        max_completion_tokens=2048,
    )
    assert tool == {
        "type": "trustedrouter:fusion",
        "parameters": {
            "analysis_models": ["a", "b"],
            "model": "z-ai/glm-5.1",
            "selection_strategy": "first_non_refusal",
            "fallback_judges": ["j1", "j2"],
            "max_completion_tokens": 2048,
        },
    }


def test_fusion_tool_empty_by_default() -> None:
    assert fusion_tool()["parameters"] == {}


def test_fusion_tool_preset_and_extras() -> None:
    params = fusion_tool(
        preset="quality", fallback_final_models=["f1"], max_tool_calls=4
    )["parameters"]
    assert params == {
        "preset": "quality",
        "fallback_final_models": ["f1"],
        "max_tool_calls": 4,
    }


def test_sync_fusion_posts_fusion_model_with_tool() -> None:
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
    resp = sdk.fusion(
        messages=[{"role": "user", "content": "hi"}],
        analysis_models=FUSION_FREEDOM_PANEL,
        model="z-ai/glm-5.1",
        selection_strategy="first_non_refusal",
        fallback_judges=FUSION_FREEDOM_FALLBACK_JUDGES,
        max_completion_tokens=2048,
        max_tokens=512,
    )
    assert seen["model"] == FUSION_MODEL
    assert seen["max_tokens"] == 512  # passthrough
    assert len(seen["tools"]) == 1
    params = seen["tools"][0]["parameters"]
    assert seen["tools"][0]["type"] == "trustedrouter:fusion"
    assert params["analysis_models"] == list(FUSION_FREEDOM_PANEL)
    assert params["model"] == "z-ai/glm-5.1"
    assert params["selection_strategy"] == "first_non_refusal"
    assert params["fallback_judges"] == list(FUSION_FREEDOM_FALLBACK_JUDGES)
    assert resp.choices[0].message.content == "ok"
    sdk.close()


@pytest.mark.asyncio
async def test_async_fusion_posts_fusion_model_with_tool() -> None:
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
    resp = await sdk.fusion(
        messages=[{"role": "user", "content": "hi"}],
        analysis_models=FUSION_FREEDOM_PANEL,
        model="z-ai/glm-5.1",
    )
    assert seen["model"] == FUSION_MODEL
    assert seen["tools"][0]["parameters"]["model"] == "z-ai/glm-5.1"
    assert resp.choices[0].message.content == "ok"
    await sdk.aclose()
