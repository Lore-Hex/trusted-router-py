from __future__ import annotations

import asyncio

import httpx
import pytest

from trustedrouter import InternalError, TrustedRouter
from trustedrouter._collect import _collect_completion
from trustedrouter._requests import _aenforce_reserved_headers, _enforce_reserved_headers
from trustedrouter.oauth import exchange_oauth_key, exchange_oauth_key_async


def _sse(content: str) -> httpx.Response:
    return httpx.Response(200, content=content.encode())


def test_chat_collection_rejects_truncated_and_malformed_sse() -> None:
    for body in (
        'data: {"choices":[{"delta":{"content":"partial"}}]}\n\n',
        "data: {not-json}\n\ndata: [DONE]\n\n",
    ):
        sdk = TrustedRouter(
            client=httpx.Client(
                transport=httpx.MockTransport(lambda _request, body=body: _sse(body))
            ),
            max_retries=0,
        )
        with pytest.raises(InternalError):
            sdk.chat_completions(messages=[{"role": "user", "content": "hi"}])


def test_collector_preserves_multiple_choices_reasoning_and_envelope_fields() -> None:
    result = _collect_completion(
        [
            {
                "id": "chat-1",
                "model": "m",
                "system_fingerprint": "fp_1",
                "choices": [
                    {
                        "index": 1,
                        "delta": {"role": "assistant", "reasoning": "think "},
                    },
                    {"index": 0, "delta": {"role": "assistant", "content": "hel"}},
                ],
            },
            {
                "id": "chat-1",
                "model": "m",
                "choices": [
                    {
                        "index": 0,
                        "delta": {"content": "lo"},
                        "finish_reason": "stop",
                        "logprobs": {"content": []},
                    },
                    {
                        "index": 1,
                        "delta": {"reasoning": "carefully", "refusal": "cannot"},
                        "finish_reason": "content_filter",
                    },
                ],
            },
        ]
    )

    assert result["system_fingerprint"] == "fp_1"
    assert [choice["index"] for choice in result["choices"]] == [0, 1]
    assert result["choices"][0]["message"]["content"] == "hello"
    assert result["choices"][0]["logprobs"] == {"content": []}
    assert result["choices"][1]["message"]["reasoning"] == "think carefully"
    assert result["choices"][1]["message"]["refusal"] == "cannot"


def test_injected_follow_redirects_client_cannot_replay_cross_origin() -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.host or "")
        if request.url.host == "api.example":
            return httpx.Response(
                307,
                headers={"location": "https://sink.example/capture"},
                json={"redirect": True},
            )
        return httpx.Response(200, json={"captured": True})

    client = httpx.Client(
        transport=httpx.MockTransport(handler),
        follow_redirects=True,
    )
    sdk = TrustedRouter(base_url="https://api.example/v1", client=client, max_retries=0)
    with pytest.raises(Exception) as exc_info:
        sdk.request(
            "POST",
            "/generic",
            json={"secret": "prompt"},
            headers={"x-custom-secret": "secret"},
        )
    assert getattr(exc_info.value, "status_code", None) == 307
    assert seen == ["api.example"]


def test_generic_unkeyed_post_does_not_retry_ambiguous_disconnect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("trustedrouter.client._retry_sleep", lambda *_args, **_kwargs: 0.0)
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        assert request.content == b'{"paid":true}'
        raise httpx.ReadError("peer reset after request body", request=request)

    sdk = TrustedRouter(
        base_url="https://private.example/v1",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        max_retries=3,
    )
    with pytest.raises(InternalError):
        sdk.request("POST", "/generic", json={"paid": True})
    assert calls == 1


def test_high_level_chat_retries_with_one_stable_generated_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("trustedrouter.client._retry_sleep", lambda *_args, **_kwargs: 0.0)
    keys: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        keys.append(request.headers.get("idempotency-key"))
        if len(keys) == 1:
            return httpx.Response(503, text="retry")
        return _sse(
            'data: {"id":"c","choices":[{"index":0,"delta":{"content":"ok"},'
            '"finish_reason":"stop"}]}\n\ndata: [DONE]\n\n'
        )

    sdk = TrustedRouter(
        base_url="https://private.example/v1",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        max_retries=1,
    )
    result = sdk.chat_completions(messages=[{"role": "user", "content": "hi"}])
    assert result.choices[0].message.content == "ok"
    assert keys[0] is not None and keys == [keys[0], keys[0]]


def test_constructor_headers_apply_to_injected_client_without_mutating_it() -> None:
    seen: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers.get("x-sdk-default"))
        return httpx.Response(200, json={"data": []})

    injected = httpx.Client(
        headers={"x-existing": "keep"},
        transport=httpx.MockTransport(handler),
    )
    original = dict(injected.headers)
    sdk = TrustedRouter(client=injected, headers={"x-sdk-default": "yes"})
    sdk.models()
    assert seen == ["yes"]
    assert dict(injected.headers) == original


def test_oauth_exchange_terminal_scrub_is_scoped_and_installed_once_sync() -> None:
    sensitive_headers = {
        "authorization": "Bearer ambient",
        "cookie": "session=ambient",
        "idempotency-key": "stale-key",
        "proxy-authorization": "Basic ambient",
        "x-api-key": "ambient-api-key",
        "x-tr-client": "stale-telemetry",
        "x-trustedrouter-workspace": "stale-workspace",
    }
    sensitive_names = set(sensitive_headers)
    seen: list[tuple[str, set[str]]] = []

    def readd_credentials(request: httpx.Request) -> None:
        request.headers.update(sensitive_headers)

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.url.path, set(request.headers) & sensitive_names))
        return httpx.Response(200, json={"key": "sk-delegated"})

    with httpx.Client(
        headers=sensitive_headers,
        transport=httpx.MockTransport(handler),
        follow_redirects=True,
        event_hooks={"request": [readd_credentials]},
    ) as client:
        assert exchange_oauth_key(code="code", client=client).key == "sk-delegated"
        assert client.event_hooks["request"].count(_enforce_reserved_headers) == 1

        # The hook is marker-scoped: sharing this client must not scrub the
        # caller's own, unmarked request.
        assert client.get("https://caller.example/unmarked").status_code == 200

        assert exchange_oauth_key(code="again", client=client).key == "sk-delegated"
        assert client.event_hooks["request"].count(_enforce_reserved_headers) == 1

    assert seen == [
        ("/v1/auth/keys", set()),
        ("/unmarked", sensitive_names),
        ("/v1/auth/keys", set()),
    ]


def test_oauth_exchange_terminal_scrub_is_scoped_and_installed_once_async() -> None:
    sensitive_headers = {
        "authorization": "Bearer ambient",
        "cookie": "session=ambient",
        "idempotency-key": "stale-key",
        "proxy-authorization": "Basic ambient",
        "x-api-key": "ambient-api-key",
        "x-tr-client": "stale-telemetry",
        "x-trustedrouter-workspace": "stale-workspace",
    }
    sensitive_names = set(sensitive_headers)
    seen: list[tuple[str, set[str]]] = []

    async def readd_credentials(request: httpx.Request) -> None:
        request.headers.update(sensitive_headers)

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.url.path, set(request.headers) & sensitive_names))
        return httpx.Response(200, json={"key": "sk-delegated"})

    async def run() -> None:
        async with httpx.AsyncClient(
            headers=sensitive_headers,
            transport=httpx.MockTransport(handler),
            follow_redirects=True,
            event_hooks={"request": [readd_credentials]},
        ) as client:
            token = await exchange_oauth_key_async(code="code", client=client)
            assert token.key == "sk-delegated"
            assert client.event_hooks["request"].count(_aenforce_reserved_headers) == 1

            assert (await client.get("https://caller.example/unmarked")).status_code == 200

            token = await exchange_oauth_key_async(code="again", client=client)
            assert token.key == "sk-delegated"
            assert client.event_hooks["request"].count(_aenforce_reserved_headers) == 1

    asyncio.run(run())
    assert seen == [
        ("/v1/auth/keys", set()),
        ("/unmarked", sensitive_names),
        ("/v1/auth/keys", set()),
    ]


def test_successful_malformed_json_is_typed() -> None:
    from trustedrouter._errors import _json_or_raise

    with pytest.raises(InternalError, match="Malformed JSON"):
        _json_or_raise(httpx.Response(200, content=b"{broken"))


@pytest.mark.parametrize("choices", [None, 7, {}, "text", [None], [[]], [{"delta": []}],
                                     [{"delta": None}], [{"delta": 7}]])
def test_text_delta_shapes(choices) -> None:
    from trustedrouter._sse import _delta_text

    with pytest.raises(InternalError):
        _delta_text({"choices": choices})
    assert _delta_text({"choices": [{"delta": {"content": "ok", "future": []}}]}) == "ok"


@pytest.mark.parametrize("choices", [None, 7, {}, "text", [None], [[]], [{"delta": []}],
                                     [{"delta": None}], [{"delta": 7}]])
def test_collector_shapes(choices) -> None:
    # A good neighboring choice must not hide the malformed one.
    with pytest.raises(InternalError):
        _collect_completion([{"choices": [{"delta": {"content": "ok"}}]}, {"choices": choices}])


@pytest.mark.parametrize("delta", [
    {"tool_calls": 7}, {"tool_calls": [None]}, {"tool_calls": [{"function": []}]},
    {"tool_calls": [{"function": {"arguments": 7}}]},
    {"function_call": []}, {"function_call": {"arguments": 7}},
])
def test_collector_tool_shapes(delta) -> None:
    with pytest.raises(InternalError):
        _collect_completion([{"choices": [{"delta": delta}]}])


@pytest.mark.parametrize("value", [[], "x", 7, False])
def test_stream_options_shape(value) -> None:
    from trustedrouter._collect import _with_usage

    with pytest.raises(InternalError):
        _with_usage({"stream_options": value})


def test_retry_headers_any_case() -> None:
    from trustedrouter._retry import _retry_after_seconds, _should_retry_header

    assert _should_retry_header({"X-SHOULD-RETRY": "false"}) is False
    assert _retry_after_seconds({"RETRY-AFTER": "2"}) == 2
    assert _retry_after_seconds({"RETRY-AFTER-MS": "1250"}) == 1.25


def _assert_boundary_headers(request: httpx.Request) -> httpx.Response:
    assert request.headers.get_list("authorization") == ["Bearer key"]
    assert request.headers.get_list("x-repeat") == ["a", "b"]
    assert request.headers.get_list("user-agent") == ["custom"]
    if request.headers.get("accept") == "text/event-stream":
        return _sse('data: {"choices":[{"delta":{"content":"ok"}}]}\n\ndata: [DONE]\n\n')
    return httpx.Response(200, json={"data": []})


def test_header_merges_sync() -> None:
    headers = httpx.Headers([
        ("X-Repeat", "a"), ("x-repeat", "b"), ("User-Agent", "custom"),
        ("Authorization", "stale"),
    ])
    with httpx.Client(transport=httpx.MockTransport(_assert_boundary_headers)) as client:
        sdk = TrustedRouter(api_key="key", client=client, headers=headers,
                            base_url="https://example.test/v1", telemetry=False)
        sdk.models()
        assert list(sdk.chat_completions_stream(model="m", messages=[])) == ["ok"]
        sdk.request("GET", "/models", headers={"AUTHORIZATION": "stale2"})
        assert headers.get_list("x-repeat") == ["a", "b"]


@pytest.mark.asyncio
async def test_header_merges_async() -> None:
    from trustedrouter import AsyncTrustedRouter

    headers = httpx.Headers([
        ("X-Repeat", "a"), ("x-repeat", "b"), ("User-Agent", "custom"),
        ("Authorization", "stale"),
    ])
    async with httpx.AsyncClient(transport=httpx.MockTransport(_assert_boundary_headers)) as client:
        sdk = AsyncTrustedRouter(api_key="key", client=client, headers=headers,
                                 base_url="https://example.test/v1", telemetry=False)
        await sdk.models()
        stream = sdk.chat_completions_stream(model="m", messages=[])
        assert [text async for text in stream] == ["ok"]
        await sdk.request("GET", "/models", headers={"AUTHORIZATION": "stale2"})
        assert headers.get_list("x-repeat") == ["a", "b"]


def test_stream_header_assembly() -> None:
    from trustedrouter._requests import _build_stream_request

    request = _build_stream_request(
        "POST", "https://example.test", body={}, api_key="key",
        extra_headers=httpx.Headers([("Authorization", "stale"), ("x", "a"), ("x", "b")]),
    )
    assert request["headers"].get_list("authorization") == ["Bearer key"]
    assert request["headers"].get_list("x") == ["a", "b"]


@pytest.mark.parametrize("helper", ["user_agent", "sdk_identity"])
def test_metadata_fallback_is_narrow(helper, monkeypatch) -> None:
    import importlib.metadata

    from trustedrouter._requests import _user_agent
    from trustedrouter._telemetry import sdk_identity

    def broken(_name):
        raise RuntimeError("metadata bug")

    monkeypatch.setattr(importlib.metadata, "version", broken)
    with pytest.raises(RuntimeError, match="metadata bug"):
        (_user_agent if helper == "user_agent" else sdk_identity)()
