from __future__ import annotations

import re
import socket
import ssl
from collections.abc import Iterator
from typing import Any

import httpx
import pytest

from trustedrouter import AsyncTrustedRouter, InternalError, TrustedRouter
from trustedrouter._constants import ALIAS_API_BASE_URLS, DEFAULT_API_BASE_URL, REGION_BASE_URLS
from trustedrouter._retry import RetryController
from trustedrouter._telemetry import (
    RecordingSink,
    RequestRecorder,
    classify_transport_error,
    endpoint_enum,
    host_enum,
    latency_bucket,
    resolve_telemetry_enabled,
    status_class,
    timeout_floor_met,
)
from trustedrouter._transport import request_with_retry

_REQUEST_ID = "rlog_0123456789abcdef0123456789abcdef"


def _client(
    handler: Any,
    sink: RecordingSink,
    **kwargs: Any,
) -> TrustedRouter:
    return TrustedRouter(
        api_key="sk-test",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        regional_affinity=False,
        telemetry=True,
        _telemetry_sink=sink,
        **kwargs,
    )


def test_buffered_retry_header_and_record_capture_client_observations(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("trustedrouter.client._retry_sleep", lambda *_args, **_kwargs: 0.0)
    sink = RecordingSink()
    seen: list[tuple[str, str | None]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.url.host or "", request.headers.get("x-tr-client")))
        if len(seen) == 1:
            return httpx.Response(
                503,
                headers={"x-should-retry": "true"},
                json={"error": {"message": "unavailable"}},
            )
        return httpx.Response(200, headers={"x-request-id": _REQUEST_ID}, json={"ok": True})

    sdk = _client(handler, sink, max_retries=1)
    assert sdk.request(
        "POST",
        "/chat/completions",
        json={"model": "model/a", "provider": {"allow_fallbacks": False}},
    ) == {"ok": True}

    assert seen[0] == ("api.trustedrouter.com", "v=1;a=0;s=0")
    assert seen[1][0] == "api.allyrouter.com"
    retry_header = seen[1][1]
    assert retry_header is not None
    assert ";po=http_error;pc=none;ph=apex;" in retry_header
    assert ";s=0;fo=1" in retry_header
    assert len(retry_header.encode("ascii")) <= 160
    assert all(
        re.fullmatch(r"[a-z0-9_]{1,24}", item.split("=", 1)[1])
        for item in retry_header.split(";")
    )

    assert len(sink.events) == 1
    event = sink.events[0]
    assert event["endpoint"] == "chat_completions"
    assert event["provider_pinned"] is True
    assert event["model"] == "model/a"
    assert event["final_outcome"] == "ok"
    assert event["failover_used"] is True
    assert len(event["attempts"]) == 2
    assert event["attempts"][0]["moved"] is True
    assert event["attempts"][0]["should_retry"] == "true"
    assert event["attempts"][1]["request_id"] == _REQUEST_ID
    assert len(sink.counters) == 3
    assert sink.counters[0][0][0] == "request"
    assert sink.counters[0][1]["first_attempt_success"] == 0
    assert [counter[0][0] for counter in sink.counters[1:]] == ["attempt", "attempt"]


def test_forced_retry_of_a_success_reports_po_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A sub-400 response retried on x-should-retry: true leaves the previous
    outcome "ok" -- outside the po vocabulary of contract v1 section 3.2 --
    so the retry attempt's header must map it to po=none;pc=none rather than
    shipping a value the enclave drops the whole header for."""
    monkeypatch.setattr("trustedrouter.client._retry_sleep", lambda *_args, **_kwargs: 0.0)
    sink = RecordingSink()
    seen: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers.get("x-tr-client"))
        if len(seen) == 1:
            return httpx.Response(
                200,
                headers={"x-should-retry": "true"},
                json={"retry": True},
            )
        return httpx.Response(200, json={"ok": True})

    sdk = _client(handler, sink, max_retries=1)
    assert sdk.request("POST", "/responses", json={"model": "m"}) == {"ok": True}

    assert seen[0] == "v=1;a=0;s=0"
    retry_header = seen[1]
    assert retry_header is not None
    assert ";a=1;" in retry_header
    assert ";po=none;pc=none;" in retry_header


def test_exhausted_retryable_status_is_recorded_before_the_error_is_raised(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("trustedrouter.client._retry_sleep", lambda *_args, **_kwargs: 0.0)
    sink = RecordingSink()

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, json={"error": {"message": "unavailable"}})

    sdk = _client(handler, sink, max_retries=1)
    with pytest.raises(InternalError):
        sdk.request("POST", "/responses", json={"model": "m"})

    assert sink.events[0]["final_outcome"] == "exhausted"
    assert sink.events[0]["final_http_status"] == 503
    assert sink.counters[0][0][4] == "http_error"


@pytest.mark.parametrize(
    ("base_url", "telemetry"),
    [
        ("https://private.example/v1", None),
        (DEFAULT_API_BASE_URL, False),
    ],
)
def test_custom_base_and_opt_out_send_no_header_or_sink_call(
    base_url: str,
    telemetry: bool | None,
) -> None:
    sink = RecordingSink()
    headers: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        headers.append(request.headers.get("x-tr-client"))
        return httpx.Response(200, json={"ok": True})

    sdk = TrustedRouter(
        base_url=base_url,
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        regional_affinity=False,
        telemetry=telemetry,
        _telemetry_sink=sink,
    )
    assert sdk.request("GET", "/models") == {"ok": True}
    assert headers == [None]
    assert sink.events == []
    assert sink.counters == []


_STALE_CLIENT_HEADER = "v=1;a=7;po=http_error;pc=none;ph=apex;pm=1;sm=1;s=0;fo=0"


@pytest.mark.parametrize("vector", ["per_call_headers", "injected_client_headers"])
@pytest.mark.parametrize(
    "path",
    ["opt_out", "custom_base", "control_plane", "recording"],
)
def test_reserved_header_stripped_on_every_path(vector: str, path: str) -> None:
    """x-tr-client is SDK-reserved: only the recorder may set it.

    A stale or forged caller value -- from client default headers, per-call
    headers, or an injected client's own headers -- never reaches the gateway
    on any path, and an active recorder's value replaces it.
    """
    seen: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers.get("x-tr-client"))
        return httpx.Response(200, json={"ok": True, "data": []})

    stale = {"x-tr-client": _STALE_CLIENT_HEADER}
    sdk = TrustedRouter(
        api_key="sk-test",
        base_url="https://private.example/v1" if path == "custom_base" else None,
        client=httpx.Client(
            transport=httpx.MockTransport(handler),
            headers=stale if vector == "injected_client_headers" else None,
        ),
        regional_affinity=False,
        telemetry={"opt_out": False, "recording": True}.get(path),
        _telemetry_sink=RecordingSink(),
    )
    per_call = stale if vector == "per_call_headers" else None
    if path == "control_plane":
        assert sdk._control_request("GET", "/models", headers=per_call) == {
            "ok": True,
            "data": [],
        }
    else:
        assert sdk.request(
            "POST", "/responses", json={"model": "m"}, headers=per_call
        ) == {"ok": True, "data": []}

    expected = ["v=1;a=0;s=0"] if path == "recording" else [None]
    assert seen == expected


def test_reserved_header_is_scrubbed_from_client_default_headers() -> None:
    """The strip also has to hold in the client's own header store.

    httpx merges client default headers UNDER the per-request ones, and a
    request-level dict has no way to delete what it merged, so a caller value
    configured as a default (or carried by an injected client) is removed at
    construction. Unreserved caller headers are untouched.
    """
    stale = {"x-tr-client": _STALE_CLIENT_HEADER, "x-caller-kept": "yes"}
    sync_sdk = TrustedRouter(api_key="sk-test", regional_affinity=False, headers=stale)
    async_sdk = AsyncTrustedRouter(
        api_key="sk-test", regional_affinity=False, headers=stale
    )
    injected = TrustedRouter(
        api_key="sk-test",
        regional_affinity=False,
        client=httpx.Client(headers=stale),
    )
    for client in (sync_sdk._client, async_sdk._client, injected._client):
        assert "x-tr-client" not in client.headers
        assert client.headers["x-caller-kept"] == "yes"


def _forge(request: httpx.Request) -> None:
    request.headers["x-tr-client"] = "alice@example.com"


async def _aforge(request: httpx.Request) -> None:
    _forge(request)


class _ForgingAuth(httpx.Auth):
    """A caller Auth flow that writes the reserved header."""

    def auth_flow(self, request: httpx.Request) -> Iterator[httpx.Request]:
        _forge(request)
        yield request


@pytest.mark.parametrize("vector", ["late_default_mutation", "request_hook", "auth_flow"])
@pytest.mark.parametrize("recording", [False, True])
def test_reservation_holds_against_writers_downstream_of_the_scrub(
    vector: str, recording: bool
) -> None:
    """The three writers that beat a per-request scrub must still lose.

    httpx merges client defaults under the per-request headers, and runs the
    caller's ``Auth`` flow and request event hooks INSIDE ``send()`` -- after
    ``build_request()`` and after anything the driver wrote. So the reservation
    is re-asserted by a terminal hook installed at construction: with telemetry
    off the header must be absent, and with an active recorder the recorder's
    value must survive rather than the forged one.
    """
    seen: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers.get("x-tr-client"))
        return httpx.Response(200, json={"ok": True, "data": []})

    client = httpx.Client(
        transport=httpx.MockTransport(handler),
        event_hooks={"request": [_forge]} if vector == "request_hook" else None,
        auth=_ForgingAuth() if vector == "auth_flow" else None,
    )
    sdk = TrustedRouter(
        api_key="sk-test",
        client=client,
        regional_affinity=False,
        telemetry=recording,
        _telemetry_sink=RecordingSink(),
    )
    if vector == "late_default_mutation":
        # Set AFTER construction, so the construction-time scrub cannot help.
        client.headers["x-tr-client"] = "alice@example.com"

    sdk.request("POST", "/responses", json={"model": "m"})

    assert seen == (["v=1;a=0;s=0"] if recording else [None])


def test_reservation_hook_ignores_requests_the_sdk_did_not_build() -> None:
    """The terminal hook is scoped by an extensions marker, not global.

    An injected client is usually shared with the caller's own traffic; the
    reservation must not reach into requests the SDK never issued.
    """
    seen: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers.get("x-tr-client"))
        return httpx.Response(200, json={"ok": True})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    TrustedRouter(api_key="sk-test", client=client, regional_affinity=False, telemetry=False)

    client.get("https://elsewhere.example/", headers={"x-tr-client": "callers-own-business"})

    assert seen == ["callers-own-business"]


def test_reservation_holds_on_the_stream_driver_and_async_facade() -> None:
    """The two drivers the PR deliberately did not restructure, plus async.

    Both get the reservation from the same terminal hook, so a caller request
    hook cannot forge the header on a stream open or on the async facade.
    """
    seen: list[str | None] = []

    def stream_handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers.get("x-tr-client"))
        return httpx.Response(
            200,
            headers={"content-type": "text/event-stream"},
            content=b'data: {"choices":[{"delta":{"content":"hi"}}]}\n\ndata: [DONE]\n\n',
        )

    def json_handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers.get("x-tr-client"))
        return httpx.Response(200, json={"ok": True, "data": []})

    sync_sdk = TrustedRouter(
        api_key="sk-test",
        client=httpx.Client(
            transport=httpx.MockTransport(stream_handler), event_hooks={"request": [_forge]}
        ),
        regional_affinity=False,
        telemetry=False,
    )
    list(
        sync_sdk.chat_completions_chunk_stream(
            model="m", messages=[{"role": "user", "content": "x"}]
        )
    )
    assert seen == [None]

    seen.clear()

    async def drive() -> None:
        async_sdk = AsyncTrustedRouter(
            api_key="sk-test",
            client=httpx.AsyncClient(
                transport=httpx.MockTransport(json_handler), event_hooks={"request": [_aforge]}
            ),
            regional_affinity=False,
            telemetry=False,
        )
        await async_sdk.request("GET", "/models")

    import asyncio

    asyncio.run(drive())
    assert seen == [None]


def test_control_plane_call_is_never_traced() -> None:
    sink = RecordingSink()
    headers: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        headers.append(request.headers.get("x-tr-client"))
        return httpx.Response(200, json={"data": []})

    sdk = _client(handler, sink)
    assert sdk.models().data == []
    assert headers == [None]
    assert sink.events == []


@pytest.mark.parametrize(
    ("explicit", "environ", "base_url", "control_url", "expected"),
    [
        (True, {"TRUSTEDROUTER_TELEMETRY": "0", "DO_NOT_TRACK": "1"}, "x", "x", True),
        (False, {"TRUSTEDROUTER_TELEMETRY": "1"}, DEFAULT_API_BASE_URL, "x", False),
        (None, {"TRUSTEDROUTER_TELEMETRY": "OFF"}, DEFAULT_API_BASE_URL, "x", False),
        (None, {"TRUSTEDROUTER_TELEMETRY": "yes", "DO_NOT_TRACK": "1"}, "x", "x", True),
        (None, {"TRUSTEDROUTER_TELEMETRY": "maybe", "DO_NOT_TRACK": "1"}, "x", "x", False),
        (None, {}, DEFAULT_API_BASE_URL, "https://telemetry.trustedrouter.com/v1", True),
        (None, {}, "https://private.example/v1", "https://trustedrouter.com/v1", False),
        (None, {}, DEFAULT_API_BASE_URL, "https://control.example/v1", False),
    ],
)
def test_telemetry_enablement_precedence(
    explicit: bool | None,
    environ: dict[str, str],
    base_url: str,
    control_url: str,
    expected: bool,
) -> None:
    assert (
        resolve_telemetry_enabled(
            explicit,
            base_url=base_url,
            control_base_url=control_url,
            environ=environ,
        )
        is expected
    )


@pytest.mark.parametrize(
    ("exc", "expected"),
    [
        (httpx.ConnectTimeout("connect"), ("connect_timeout", "connect")),
        (httpx.ReadTimeout("read"), ("read_timeout", "first_byte")),
        (httpx.WriteTimeout("write"), ("write_timeout", "first_byte")),
        (httpx.PoolTimeout("pool"), ("pool_timeout", "none")),
        (httpx.ConnectError("connect"), ("connect_error", "none")),
        (httpx.RemoteProtocolError("protocol"), ("protocol_error", "none")),
        (httpx.ReadError("read"), ("io_error", "none")),
        (httpx.ProxyError("proxy"), ("proxy_error", "none")),
        (ConnectionRefusedError(), ("connect_refused", "none")),
        (ConnectionResetError(), ("reset", "none")),
        (RuntimeError("other"), ("unknown", "none")),
    ],
)
def test_transport_error_classification(
    exc: BaseException,
    expected: tuple[str, str],
) -> None:
    assert classify_transport_error(exc) == expected


@pytest.mark.parametrize(
    ("cause", "expected"),
    [
        (ssl.SSLError("certificate"), ("tls", "none")),
        (socket.gaierror("dns"), ("dns", "none")),
    ],
)
def test_transport_error_classification_walks_causes(
    cause: BaseException,
    expected: tuple[str, str],
) -> None:
    exc = httpx.ConnectError("wrapped")
    exc.__cause__ = cause
    assert classify_transport_error(exc) == expected


def test_host_endpoint_bucket_status_and_timeout_helpers_are_closed() -> None:
    assert host_enum("HTTPS://API.TRUSTEDROUTER.COM/other/path") == "apex"
    assert host_enum(ALIAS_API_BASE_URLS[0]) == "ally"
    assert host_enum(ALIAS_API_BASE_URLS[1]) == "uptime"
    assert [host_enum(url) for url in REGION_BASE_URLS] == [
        "us_central1",
        "us_east4",
        "europe_west4",
    ]
    assert host_enum("https://trust.trustedrouter.com/anything") == "control"
    assert host_enum("not a url") == "custom"
    assert endpoint_enum("/images/generations?x=1") == "images"
    assert endpoint_enum("/fusion") == "fusion"
    assert endpoint_enum("/unknown") == "inference_other"
    assert latency_bucket(99) == "lt100"
    assert latency_bucket(100) == "lt200"
    assert latency_bucket(200_000) == "ge102400"
    assert [status_class(status) for status in (None, 200, 302, 400, 429, 503)] == [
        "none",
        "2xx",
        "none",
        "4xx",
        "429",
        "5xx",
    ]
    assert timeout_floor_met("connect", 10_000) is True
    assert timeout_floor_met("first_byte", 59_999) is False
    assert timeout_floor_met("idle", None) is False


def test_timeout_record_uses_phase_specific_configuration_and_is_idempotent() -> None:
    sink = RecordingSink()
    recorder = RequestRecorder(
        sink,
        endpoint="responses",
        method="POST",
        streaming=True,
        provider_pinned=False,
        model="bad model with spaces",
        configured_timeout=httpx.Timeout(connect=10, read=60, write=60, pool=5),
    )
    recorder.begin_attempt(DEFAULT_API_BASE_URL)
    recorder.on_transport_error(
        httpx.ReadTimeout("stalled"),
        response_opened=True,
        body_started=True,
    )
    recorder.finish(exhausted=False)
    recorder.finish(exhausted=True)

    assert len(sink.events) == 1
    event = sink.events[0]
    assert event["model"] is None
    assert event["final_outcome"] == "timeout"
    assert event["attempts"][0]["error_class"] == "stream_stalled"
    assert event["timeout_phase"] == "idle"
    assert event["configured_timeout_ms"] == 60_000
    assert sink.counters[0][0][8] is True


def test_retry_header_since_first_works_when_monotonic_clock_starts_at_zero(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ticks = iter((0.0, 0.1, 0.2))
    monkeypatch.setattr("trustedrouter._telemetry.time.perf_counter", lambda: next(ticks))
    recorder = RequestRecorder(
        RecordingSink(),
        endpoint="responses",
        method="POST",
        streaming=False,
        provider_pinned=False,
        model="m",
        configured_timeout=120.0,
    )
    recorder.begin_attempt(DEFAULT_API_BASE_URL)
    recorder.on_response(503, {})
    recorder.on_moved()
    recorder.begin_attempt(ALIAS_API_BASE_URLS[0])
    assert ";sm=200;" in (recorder.header_value() or "")


def test_retry_header_is_suppressed_above_the_attempt_grammar_bound() -> None:
    recorder = RequestRecorder(
        RecordingSink(),
        endpoint="responses",
        method="POST",
        streaming=False,
        provider_pinned=False,
        model="m",
        configured_timeout=120.0,
    )
    for _ in range(99):
        recorder.begin_attempt(DEFAULT_API_BASE_URL)
        recorder.on_response(503, {})
    recorder.begin_attempt(DEFAULT_API_BASE_URL)
    assert ";a=99;" in (recorder.header_value() or "")
    recorder.on_response(503, {})
    for _ in range(2):
        recorder.begin_attempt(DEFAULT_API_BASE_URL)
        assert recorder.header_value() is None
        recorder.on_response(503, {})
    recorder.finish(exhausted=True)


class _BrokenBody(httpx.SyncByteStream):
    def __iter__(self) -> Iterator[bytes]:
        yield b'data: {"choices":[{"delta":{"content":"first"}}]}\n\n'
        raise httpx.ReadError("body broke")


def test_stream_first_event_and_mid_body_failure_emit_one_record() -> None:
    sink = RecordingSink()
    seen_headers: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_headers.append(request.headers.get("x-tr-client"))
        return httpx.Response(
            200,
            headers={"content-type": "text/event-stream"},
            stream=_BrokenBody(),
        )

    sdk = _client(handler, sink, max_retries=2)
    with pytest.raises(InternalError):
        list(sdk.chat_completions_stream(model="m", messages=[]))

    assert seen_headers == ["v=1;a=0;s=1"]
    assert len(sink.events) == 1
    event = sink.events[0]
    assert event["ttft_ms"] is not None
    assert event["final_outcome"] == "stream_broken"
    assert len(event["attempts"]) == 1


def test_closing_stream_generator_records_aborted_once() -> None:
    sink = RecordingSink()

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "text/event-stream"},
            content=(
                b'data: {"choices":[{"delta":{"content":"one"}}]}\n\n'
                b'data: {"choices":[{"delta":{"content":"two"}}]}\n\n'
            ),
        )

    sdk = _client(handler, sink)
    stream = sdk.chat_completions_stream(model="m", messages=[])
    assert next(stream) == "one"
    stream.close()
    assert len(sink.events) == 1
    assert sink.events[0]["final_outcome"] == "aborted"


def test_engine_without_recorder_preserves_requests_and_does_not_mutate_headers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("trustedrouter.client._retry_sleep", lambda *_args, **_kwargs: 0.0)
    original_kwargs: dict[str, Any] = {"headers": {"x-user": "value"}}
    seen: list[tuple[str, str | None]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.url.host or "", request.headers.get("x-tr-client")))
        status = 503 if len(seen) == 1 else 200
        return httpx.Response(status, json={"ok": status == 200})

    controller = RetryController(
        lambda: [DEFAULT_API_BASE_URL, ALIAS_API_BASE_URLS[0]],
        max_retries=1,
        regional_failover=True,
    )
    client = httpx.Client(transport=httpx.MockTransport(handler))
    response = request_with_retry(client, controller, "GET", "/models", original_kwargs)
    assert response.status_code == 200
    assert seen == [
        ("api.trustedrouter.com", None),
        ("api.allyrouter.com", None),
    ]
    assert original_kwargs == {"headers": {"x-user": "value"}}


class _RaisingSink:
    def on_request(
        self,
        event: dict[str, Any],
        counters: list[tuple[tuple[Any, ...], dict[str, Any]]],
    ) -> None:
        raise RuntimeError("sink failed")


@pytest.mark.parametrize("strict", [False, True])
def test_sink_failure_is_only_visible_in_strict_mode(
    monkeypatch: pytest.MonkeyPatch,
    strict: bool,
) -> None:
    if strict:
        monkeypatch.setenv("TRUSTEDROUTER_TELEMETRY_STRICT", "1")
    else:
        monkeypatch.delenv("TRUSTEDROUTER_TELEMETRY_STRICT", raising=False)

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"ok": True})

    sdk = TrustedRouter(
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        regional_affinity=False,
        telemetry=True,
        _telemetry_sink=_RaisingSink(),
    )
    if strict:
        with pytest.raises(RuntimeError, match="sink failed"):
            sdk.request("GET", "/models")
    else:
        assert sdk.request("GET", "/models") == {"ok": True}


@pytest.mark.asyncio
async def test_async_buffered_and_stream_drivers_record() -> None:
    sink = RecordingSink()
    headers: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        headers.append(request.headers.get("x-tr-client"))
        if request.url.path.endswith("/chat/completions"):
            return httpx.Response(
                200,
                headers={"content-type": "text/event-stream"},
                content=b'data: {"choices":[{"delta":{"content":"ok"}}]}\n\n',
            )
        return httpx.Response(200, json={"ok": True})

    sdk = AsyncTrustedRouter(
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        regional_affinity=False,
        telemetry=True,
        _telemetry_sink=sink,
    )
    assert await sdk.request("GET", "/models") == {"ok": True}
    assert [
        item
        async for item in sdk.chat_completions_stream(model="m", messages=[])
    ] == ["ok"]
    assert headers == ["v=1;a=0;s=0", "v=1;a=0;s=1"]
    assert [event["streaming"] for event in sink.events] == [False, True]
