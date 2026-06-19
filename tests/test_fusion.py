"""Coverage for the TrustedRouter Fusion helper: the ``fusion_tool()`` builder
and the sync/async ``fusion(...)`` client methods. No real network — a MockTransport
records the request body and we assert the fusion tool shape."""
from __future__ import annotations

import json as jsonlib

import httpx
import pytest

from trustedrouter import (
    DEFAULT_FUSION_TIMEOUT_SECONDS,
    FUSION_FREEDOM_FALLBACK_FINALS,
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


def _read_timeout(request: httpx.Request) -> float:
    timeout = request.extensions.get("timeout")
    assert isinstance(timeout, dict)
    read_timeout = timeout.get("read")
    assert isinstance(read_timeout, float | int)
    return float(read_timeout)


def test_fusion_tool_only_sets_provided_fields() -> None:
    tool = fusion_tool(
        analysis_models=["a", "b"],
        model="~zai/glm-latest",
        selection_strategy="first_non_refusal",
        fallback_judges=["j1", "j2"],
        max_completion_tokens=2048,
    )
    assert tool == {
        "type": "trustedrouter:fusion",
        "parameters": {
            "analysis_models": ["a", "b"],
            "model": "~zai/glm-latest",
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
        model="~zai/glm-latest",
        selection_strategy="first_non_refusal",
        fallback_judges=FUSION_FREEDOM_FALLBACK_JUDGES,
        fallback_final_models=FUSION_FREEDOM_FALLBACK_FINALS,
        max_completion_tokens=2048,
        max_tokens=512,
    )
    assert seen["model"] == FUSION_MODEL
    assert seen["max_tokens"] == 512  # passthrough
    assert len(seen["tools"]) == 1
    params = seen["tools"][0]["parameters"]
    assert seen["tools"][0]["type"] == "trustedrouter:fusion"
    assert params["analysis_models"] == list(FUSION_FREEDOM_PANEL)
    assert params["model"] == "~zai/glm-latest"
    assert params["selection_strategy"] == "first_non_refusal"
    assert params["fallback_judges"] == list(FUSION_FREEDOM_FALLBACK_JUDGES)
    assert params["fallback_final_models"] == list(FUSION_FREEDOM_FALLBACK_FINALS)
    assert resp.choices[0].message.content == "ok"
    sdk.close()


def test_sync_fusion_uses_long_default_timeout_even_with_external_client() -> None:
    seen: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["read_timeout"] = _read_timeout(request)
        return httpx.Response(
            200, headers={"content-type": "text/event-stream"}, content=_SSE
        )

    sdk = TrustedRouter(
        api_key="sk-tr-sync",
        client=httpx.Client(timeout=5.0, transport=httpx.MockTransport(handler)),
    )

    sdk.fusion(messages=[{"role": "user", "content": "hi"}])

    assert seen["read_timeout"] == DEFAULT_FUSION_TIMEOUT_SECONDS
    sdk.close()


def test_sync_fusion_allows_explicit_timeout_override() -> None:
    seen: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["read_timeout"] = _read_timeout(request)
        return httpx.Response(
            200, headers={"content-type": "text/event-stream"}, content=_SSE
        )

    sdk = TrustedRouter(
        api_key="sk-tr-sync",
        client=httpx.Client(timeout=5.0, transport=httpx.MockTransport(handler)),
    )

    sdk.fusion(messages=[{"role": "user", "content": "hi"}], timeout=42.0)

    assert seen["read_timeout"] == 42.0
    sdk.close()


def test_sync_fusion_freedom_panel_defers_fuser_and_strategy_to_gateway() -> None:
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

    sdk.fusion(
        messages=[{"role": "user", "content": "hi"}],
        analysis_models=FUSION_FREEDOM_PANEL,
    )

    params = seen["tools"][0]["parameters"]
    assert params == {"analysis_models": list(FUSION_FREEDOM_PANEL)}
    assert params["analysis_models"][0] == "minimax/minimax-m3"
    assert "model" not in params
    assert "selection_strategy" not in params
    assert "fallback_final_models" not in params
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
        model="~zai/glm-latest",
    )
    assert seen["model"] == FUSION_MODEL
    assert seen["tools"][0]["parameters"]["model"] == "~zai/glm-latest"
    assert resp.choices[0].message.content == "ok"
    await sdk.aclose()


@pytest.mark.asyncio
async def test_async_fusion_uses_long_default_timeout_even_with_external_client() -> None:
    seen: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["read_timeout"] = _read_timeout(request)
        return httpx.Response(
            200, headers={"content-type": "text/event-stream"}, content=_SSE
        )

    sdk = AsyncTrustedRouter(
        api_key="sk-tr-async",
        client=httpx.AsyncClient(timeout=5.0, transport=httpx.MockTransport(handler)),
    )

    await sdk.fusion(messages=[{"role": "user", "content": "hi"}])

    assert seen["read_timeout"] == DEFAULT_FUSION_TIMEOUT_SECONDS
    await sdk.aclose()
