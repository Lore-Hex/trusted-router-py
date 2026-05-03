"""Coverage for the sync TrustedRouter request wrappers that the existing
test_client.py file doesn't reach (collected chat_completions, attestation,
trust_release, activity, the request() error branches)."""
from __future__ import annotations

import json as jsonlib

import httpx
import pytest

from trustedrouter import AUTO_MODEL, DEFAULT_API_BASE_URL, TrustedRouter, fetch_trust_release
from trustedrouter.client import TrustedRouterError


def _client(handler):  # type: ignore[no-untyped-def]
    return TrustedRouter(
        api_key="sk-tr-sync",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )


# ---- chat_completions (collected) ---------------------------------------


def test_sync_chat_completions_collected_aggregates_stream() -> None:
    body = (
        b'data: {"id":"r","model":"m","choices":[{"delta":{"content":"PI"}}]}\n\n'
        b'data: {"id":"r","model":"m","choices":[{"delta":{"content":"NG"},'
        b'"finish_reason":"stop"}]}\n\n'
        b"data: [DONE]\n\n"
    )

    def handler(request: httpx.Request) -> httpx.Response:
        # Verify the request body shape the SDK builds
        sent = jsonlib.loads(request.content.decode())
        assert sent["model"] == "m"
        assert sent["stream"] is True
        return httpx.Response(
            200, headers={"content-type": "text/event-stream"}, content=body
        )

    sdk = _client(handler)
    resp = sdk.chat_completions(model="m", messages=[{"role": "user", "content": "hi"}])
    assert resp["choices"][0]["message"]["content"] == "PING"
    assert resp["choices"][0]["finish_reason"] == "stop"
    sdk.close()


def test_sync_chat_completions_raises_trusted_router_error_on_4xx() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, json={"error": {"message": "no such model"}})

    sdk = _client(handler)
    with pytest.raises(TrustedRouterError) as exc_info:
        sdk.chat_completions(model="nope", messages=[{"role": "user", "content": "x"}])
    assert exc_info.value.status_code == 400
    sdk.close()


def test_sync_chat_completions_default_model_is_auto() -> None:
    """When `model=` is omitted the SDK uses AUTO_MODEL — this is the
    "Just Work" entry path most casual users hit first."""
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(jsonlib.loads(request.content.decode())["model"])
        return httpx.Response(
            200,
            headers={"content-type": "text/event-stream"},
            content=(
                b'data: {"choices":[{"delta":{"content":"x"},'
                b'"finish_reason":"stop"}]}\n\n'
                b"data: [DONE]\n\n"
            ),
        )

    sdk = _client(handler)
    sdk.chat_completions(messages=[{"role": "user", "content": "x"}])
    assert seen == [AUTO_MODEL]
    sdk.close()


# ---- attestation (sync) -------------------------------------------------


def test_sync_attestation_returns_response_content_verbatim() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        # /attestation lives at the API root, not under /v1
        assert request.url.path == "/attestation"
        return httpx.Response(200, content=b"<JWT>")

    sdk = _client(handler)
    assert sdk.attestation() == b"<JWT>"
    sdk.close()


def test_sync_attestation_raises_on_5xx() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, text="cold KMS")

    sdk = _client(handler)
    with pytest.raises(TrustedRouterError) as exc_info:
        sdk.attestation()
    assert exc_info.value.status_code == 503
    assert "cold KMS" in str(exc_info.value)
    sdk.close()


# ---- trust release ------------------------------------------------------


def test_sync_trust_release_returns_parsed_json() -> None:
    payload = {"image_digest": "sha256:abc", "source_commit": "deadbeef"}

    def handler(request: httpx.Request) -> httpx.Response:
        # trust release URL is whatever was passed to trust_release()
        assert "test-trust" in str(request.url)
        return httpx.Response(200, json=payload)

    sdk = _client(handler)
    out = sdk.trust_release(url="https://test-trust.example/release.json")
    assert out["image_digest"] == "sha256:abc"
    sdk.close()


def test_module_level_fetch_trust_release_uses_its_own_client() -> None:
    """The module function `fetch_trust_release` is meant to be callable
    without instantiating TrustedRouter (e.g. boot-time pin checks).
    It builds its own httpx.Client; we patch the global httpx Client to
    verify it's actually used and the response is parsed."""
    # We can't easily inject a transport into the function's internal
    # client without monkeypatching, but we CAN drive it against a
    # transport-mocked client by temporarily swapping httpx.Client.
    import trustedrouter.client as mod

    captured: dict[str, object] = {}

    real_client = mod.httpx.Client

    def factory(*args, **kwargs):  # type: ignore[no-untyped-def]
        kwargs["transport"] = httpx.MockTransport(
            lambda _r: httpx.Response(200, json={"image_digest": "sha256:zzz"})
        )
        captured["called"] = True
        return real_client(*args, **kwargs)

    mod.httpx.Client = factory  # type: ignore[assignment]
    try:
        out = fetch_trust_release(url="https://t.example/r.json")
    finally:
        mod.httpx.Client = real_client  # type: ignore[assignment]

    assert out == {"image_digest": "sha256:zzz"}
    assert captured.get("called") is True


# ---- activity -----------------------------------------------------------


def test_sync_activity_omits_none_query_params() -> None:
    """activity() takes **params; None values must be dropped so we
    don't send `?since=None` to the gateway."""
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(200, json={"data": []})

    sdk = _client(handler)
    sdk.activity(since="2026-01-01", until=None, limit=10)
    sdk.close()
    url = seen[0]
    assert "since=2026-01-01" in url
    assert "limit=10" in url
    assert "until=" not in url


def test_sync_activity_with_no_params_drops_query_string() -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(200, json={"data": []})

    sdk = _client(handler)
    sdk.activity()
    sdk.close()
    assert seen[0].endswith("/activity")  # no `?` suffix


# ---- request() — uncommon branches --------------------------------------


def test_sync_request_merges_extra_headers_and_keeps_bearer() -> None:
    seen_headers: list[dict[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_headers.append(dict(request.headers))
        return httpx.Response(200, json={"ok": True})

    sdk = _client(handler)
    sdk.request("GET", "/models", headers={"x-trace-id": "abc-123"})
    sdk.close()
    assert seen_headers[0]["x-trace-id"] == "abc-123"
    assert seen_headers[0]["authorization"] == "Bearer sk-tr-sync"


def test_sync_request_without_api_key_omits_bearer() -> None:
    """If no api_key was set, the SDK must not invent one."""
    seen_auth: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_auth.append(request.headers.get("authorization", ""))
        return httpx.Response(200, json={"ok": True})

    # No api_key kwarg
    sdk = TrustedRouter(client=httpx.Client(transport=httpx.MockTransport(handler)))
    sdk.request("GET", "/regions")
    sdk.close()
    assert seen_auth == [""]


# ---- _json_or_raise edge branches ---------------------------------------


def test_non_json_error_response_raises_with_text_body_truncated() -> None:
    """If the gateway returns 502 with HTML (not JSON), the SDK should
    still raise TrustedRouterError with the truncated text body — never
    let a JSON parse error mask the actual upstream failure."""
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(502, content=b"<html>Bad Gateway</html>")

    sdk = _client(handler)
    with pytest.raises(TrustedRouterError) as exc_info:
        sdk.models()
    assert exc_info.value.status_code == 502
    assert "Bad Gateway" in str(exc_info.value)
    sdk.close()


def test_non_object_json_response_raises_expected_object() -> None:
    """If the gateway returns valid JSON but it's an array (or a string),
    the SDK should refuse rather than silently misuse it as a dict."""
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=["not", "an", "object"])

    sdk = _client(handler)
    with pytest.raises(TrustedRouterError) as exc_info:
        sdk.models()
    assert "Expected JSON object" in str(exc_info.value)
    sdk.close()


def test_error_message_falls_back_to_type_then_default() -> None:
    """Test the _error_message helper indirectly: when the body has an
    error.type but no error.message, raise with the type as the message.
    When neither is present, fall back to "TrustedRouter error"."""
    def handler_type_only(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, json={"error": {"type": "invalid_request"}})

    def handler_no_error(_request: httpx.Request) -> httpx.Response:
        # Valid JSON object, error status, but no `error` key at all.
        return httpx.Response(400, json={"unrelated": True})

    def handler_top_level_message(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, json={"message": "top-level-msg"})

    sdk1 = _client(handler_type_only)
    with pytest.raises(TrustedRouterError) as e1:
        sdk1.models()
    assert "invalid_request" in str(e1.value)
    sdk1.close()

    sdk2 = _client(handler_no_error)
    with pytest.raises(TrustedRouterError) as e2:
        sdk2.models()
    assert str(e2.value) == "TrustedRouter error"
    sdk2.close()

    sdk3 = _client(handler_top_level_message)
    with pytest.raises(TrustedRouterError) as e3:
        sdk3.models()
    assert "top-level-msg" in str(e3.value)
    sdk3.close()


# ---- _delta_text edge branches -----------------------------------------


def test_delta_text_handles_missing_choices_and_non_string_content() -> None:
    """Indirect coverage via the chunk_stream: a chunk with no choices,
    or with non-string content, must not produce a yielded text token
    in chat_completions_stream (the text-deltas-only variant)."""
    body = (
        b'data: {}\n\n'                                      # no choices
        b'data: {"choices":[]}\n\n'                          # empty choices
        b'data: {"choices":[{"delta":{"content":null}}]}\n\n'  # null content
        b'data: {"choices":[{"delta":{"content":"OK"}}]}\n\n'  # finally a real one
        b"data: [DONE]\n\n"
    )

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, headers={"content-type": "text/event-stream"}, content=body
        )

    sdk = _client(handler)
    out = list(sdk.chat_completions_stream(model="m", messages=[{"role": "user", "content": "x"}]))
    assert out == ["OK"]
    sdk.close()


# ---- defaults: base_url normalization with explicit trailing slash ------


def test_default_api_base_url_used_when_not_specified() -> None:
    """Catches a regression where the constructor accidentally drops
    DEFAULT_API_BASE_URL — the most-used path in production."""
    sdk = TrustedRouter()
    assert sdk.base_url == DEFAULT_API_BASE_URL
    sdk.close()
