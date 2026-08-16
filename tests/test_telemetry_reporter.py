from __future__ import annotations

import itertools
import json
import re
import time
from collections.abc import Callable, Iterator
from typing import Any

import httpx
import pytest

from trustedrouter import AsyncTrustedRouter, TrustedRouter
from trustedrouter._constants import (
    TELEMETRY_ENDPOINTS,
    TELEMETRY_ERROR_CLASSES,
    TELEMETRY_FINAL_OUTCOMES,
    TELEMETRY_HOSTS,
    TELEMETRY_TIMEOUT_PHASES,
)
from trustedrouter._telemetry import TelemetryReporter, sdk_identity

_SDK = {
    "name": "tr-py",
    "version": "0.6.0",
    "lang": "python",
    "runtime": "cpython/3.12.0",
    "os": "macos",
    "arch": "arm64",
}
_REQUEST_ID = "rlog_0123456789abcdef0123456789abcdef"


class _Clock:
    def __init__(self, value: float = 0.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


@pytest.fixture
def reporter_factory() -> Iterator[Callable[..., TelemetryReporter]]:
    reporters: list[TelemetryReporter] = []

    def make(**kwargs: Any) -> TelemetryReporter:
        kwargs.setdefault("control_base_url", "https://trustedrouter.com/v1")
        kwargs.setdefault("api_key_provider", lambda: None)
        kwargs.setdefault("workspace_id", None)
        kwargs.setdefault("sdk_identity", dict(_SDK))
        reporter = TelemetryReporter(**kwargs)
        reporters.append(reporter)
        return reporter

    yield make
    for reporter in reporters:
        reporter.close(0.1)


def _attempt(**overrides: Any) -> dict[str, Any]:
    attempt = {
        "index": 0,
        "host": "apex",
        "outcome": "ok",
        "http_status": 200,
        "error_class": None,
        "error_source": None,
        "should_retry": "absent",
        "retry_after_ms": None,
        "elapsed_ms": 25,
        "ttfb_ms": 20,
        "request_id": _REQUEST_ID,
        "moved": False,
    }
    attempt.update(overrides)
    return attempt


def _event(**overrides: Any) -> dict[str, Any]:
    event = {
        "age_ms": 0,
        "plane": "inference",
        "endpoint": "responses",
        "method": "POST",
        "streaming": False,
        "provider_pinned": False,
        "model": "model/a",
        "attempts": [_attempt()],
        "final_outcome": "ok",
        "final_http_status": 200,
        "total_ms": 25,
        "ttft_ms": None,
        "failover_used": False,
        "timeout_phase": "none",
        "configured_timeout_ms": 120_000,
    }
    event.update(overrides)
    return event


def _counter_key(**overrides: Any) -> tuple[Any, ...]:
    values = {
        "level": "request",
        "endpoint": "responses",
        "streaming": False,
        "host": "apex",
        "outcome": "ok",
        "error_class": None,
        "http_status_class": "2xx",
        "timeout_phase": "none",
        "timeout_floor_met": False,
        "provider_pinned": False,
    }
    values.update(overrides)
    return tuple(values.values())


def _counter_increment(**overrides: Any) -> dict[str, Any]:
    increment = {
        "requests": 1,
        "attempts": 1,
        "failover_used": 0,
        "first_attempt_success": 1,
        "total_ms_hist": {"lt100": 1},
        "first_event_ms_hist": {"lt100": 1},
    }
    increment.update(overrides)
    return increment


def _record(
    reporter: TelemetryReporter,
    event: dict[str, Any] | None = None,
    key: tuple[Any, ...] | None = None,
) -> None:
    reporter.on_request(
        event or _event(),
        [(key or _counter_key(), _counter_increment())],
    )


def test_sampling_keeps_failures_retries_slow_calls_and_sampled_random_successes(
    reporter_factory: Callable[..., TelemetryReporter],
) -> None:
    reporter = reporter_factory(success_sample_rate=0.0)
    reporter.on_request(
        _event(final_outcome="http_error", attempts=[_attempt(outcome="http_error")]), []
    )
    reporter.on_request(_event(attempts=[_attempt(), _attempt(index=1)]), [])
    reporter.on_request(_event(total_ms=30_001), [])
    reporter.on_request(_event(), [])
    assert [event["sample_reason"] for event in reporter._events] == [
        "failure",
        "retried",
        "slow",
    ]
    assert all(event["sample_rate"] == 1.0 for event in reporter._events)

    sampled = reporter_factory(success_sample_rate=1.0)
    sampled.on_request(_event(), [])
    assert sampled._events[0]["sample_reason"] == "random"
    assert sampled._events[0]["sample_rate"] == 1.0


def test_bounded_events_drop_oldest_success_before_oldest_failure(
    reporter_factory: Callable[..., TelemetryReporter],
) -> None:
    reporter = reporter_factory(success_sample_rate=1.0)
    reporter.on_request(_event(final_outcome="http_error", model="failure"), [])
    for index in range(999):
        reporter.on_request(_event(model=f"ok-{index}"), [])
    reporter.on_request(_event(final_outcome="http_error", model="new-failure"), [])
    assert len(reporter._events) == 1000
    assert reporter._events[0]["model"] == "failure"
    assert all(item.get("model") != "ok-0" for item in reporter._events)
    assert reporter._dropped_since_last == 1

    failures = reporter_factory(success_sample_rate=0.0)
    for index in range(1001):
        failures.on_request(
            _event(final_outcome="http_error", model=f"failure-{index}"), []
        )
    assert failures._events[0]["model"] == "failure-1"
    assert failures._dropped_since_last == 1


def test_counters_fold_at_256_keys_and_close_when_the_minute_changes(
    reporter_factory: Callable[..., TelemetryReporter],
) -> None:
    clock = _Clock(1.0)
    reporter = reporter_factory(clock=clock, success_sample_rate=0.0)
    combinations = itertools.product(
        TELEMETRY_ENDPOINTS,
        TELEMETRY_ERROR_CLASSES,
        ("none", "2xx", "4xx", "429", "5xx"),
    )
    for endpoint, error_class, status in itertools.islice(combinations, 257):
        reporter.on_request(
            _event(),
            [
                (
                    _counter_key(
                        endpoint=endpoint,
                        error_class=error_class,
                        http_status_class=status,
                    ),
                    _counter_increment(),
                )
            ],
        )
    assert len(reporter._current_counters) == 256
    assert sum(row["requests"] for row in reporter._current_counters.values()) == 257
    assert any(
        key[5] == "unknown" and row["requests"] > 1
        for key, row in reporter._current_counters.items()
    )

    clock.advance(60)
    reporter.on_request(_event(), [(_counter_key(), _counter_increment())])
    assert reporter._closed_windows[0].window_start == 0.0
    assert reporter._current_window_start == 60.0


def test_failed_flush_retains_counters_then_delivers_them_with_their_age(
    reporter_factory: Callable[..., TelemetryReporter],
) -> None:
    clock = _Clock()
    batches: list[dict[str, Any]] = []
    statuses = iter((503, 202))

    def handler(request: httpx.Request) -> httpx.Response:
        batches.append(json.loads(request.content))
        return httpx.Response(next(statuses), json={"policy": {}})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    reporter = reporter_factory(
        clock=clock,
        api_key_provider=lambda: "sk-tr-test",
        http_client_factory=lambda: client,
        success_sample_rate=0.0,
    )
    _record(reporter)
    assert reporter.flush_now() is False
    assert len(reporter._closed_windows) == 1

    clock.advance(120)
    assert reporter.flush_now() is True
    assert len(batches) == 2
    assert batches[1]["counters"][0]["window_start_age_ms"] == 120_000
    assert not reporter._closed_windows


def test_retention_drops_expired_and_byte_capped_windows_oldest_first(
    monkeypatch: pytest.MonkeyPatch,
    reporter_factory: Callable[..., TelemetryReporter],
) -> None:
    monkeypatch.setattr("trustedrouter._telemetry.TELEMETRY_RETENTION_BYTES", 700)
    clock = _Clock()
    reporter = reporter_factory(clock=clock, success_sample_rate=0.0)
    for _ in range(4):
        reporter.on_request(_event(), [(_counter_key(), _counter_increment())])
        clock.advance(60)
    reporter.on_request(_event(), [])
    starts = [window.window_start for window in reporter._closed_windows]
    assert starts == sorted(starts)
    assert starts and starts[0] > 0
    assert reporter._retained_window_bytes <= 700
    assert reporter._dropped_since_last > 0

    clock.advance(86_401)
    with reporter._lock:
        reporter._prune_windows_locked(clock())
    assert not reporter._closed_windows


def test_wire_is_bounded_content_free_and_uses_the_reporter_client(
    reporter_factory: Callable[..., TelemetryReporter],
) -> None:
    seen: list[httpx.Request] = []
    injected_content = "private prompt text that must not leave"

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(202, json={"policy": {}})

    reporter_client = httpx.Client(transport=httpx.MockTransport(handler))
    reporter = reporter_factory(
        api_key_provider=lambda: "sk-tr-test",
        workspace_id="ws_test",
        http_client_factory=lambda: reporter_client,
        success_sample_rate=1.0,
    )
    event = _event(
        model=injected_content,
        prompt=injected_content,
        attempts=[_attempt(should_retry="true")],
    )
    _record(reporter, event)
    assert reporter.flush_now() is True
    assert len(seen) == 1
    request = seen[0]
    assert str(request.url) == "https://trustedrouter.com/v1/client-events"
    assert request.headers["authorization"] == "Bearer sk-tr-test"
    assert request.headers["x-trustedrouter-workspace"] == "ws_test"
    body = json.loads(request.content)
    assert set(body) == {
        "schema_version",
        "batch_id",
        "instance_id",
        "seq",
        "sent_at_ms",
        "sdk",
        "synthetic",
        "dropped_since_last",
        "events",
        "counters",
    }
    assert re.fullmatch(r"[0-9a-f]{32}", body["batch_id"])
    assert re.fullmatch(r"[0-9a-f]{16}", body["instance_id"])
    assert body["events"][0]["model"] is None
    assert body["events"][0]["attempts"][0]["should_retry"] is True
    encoded = json.dumps(body)
    assert injected_content not in encoded
    assert not {"messages", "prompt", "input", "content", "text"} & set(
        body["events"][0]
    )


def test_policy_only_reduces_volume_and_pause_defers_delivery(
    reporter_factory: Callable[..., TelemetryReporter],
) -> None:
    clock = _Clock()
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        policy = (
            {"success_sample_rate": 0.005, "flush_seconds": 60, "pause_seconds": 120}
            if calls == 1
            else {"success_sample_rate": 0.5, "flush_seconds": 1, "pause_seconds": 0}
        )
        return httpx.Response(202, json={"policy": policy})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    reporter = reporter_factory(
        clock=clock,
        api_key_provider=lambda: "sk-tr-test",
        http_client_factory=lambda: client,
        success_sample_rate=0.01,
    )
    _record(reporter, _event(final_outcome="http_error"))
    assert reporter.flush_now() is True
    assert reporter.success_sample_rate == 0.005
    assert reporter.flush_seconds == 60

    _record(reporter, _event(final_outcome="http_error"))
    assert reporter.flush_now() is False
    assert calls == 1
    clock.advance(120)
    assert reporter.flush_now() is True
    assert reporter.success_sample_rate == 0.005
    assert reporter.flush_seconds == 60


@pytest.mark.parametrize("status", [400, 401, 403, 404, 410])
def test_permanent_response_disables_and_clears_the_reporter(
    status: int,
    reporter_factory: Callable[..., TelemetryReporter],
) -> None:
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(status)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    reporter = reporter_factory(
        api_key_provider=lambda: "sk-tr-test",
        http_client_factory=lambda: client,
    )
    _record(reporter, _event(final_outcome="http_error"))
    assert reporter.flush_now() is False
    assert reporter._disabled is True
    _record(reporter, _event(final_outcome="http_error"))
    assert reporter.flush_now() is False
    assert calls == 1
    assert not reporter._events
    assert not reporter._closed_windows


def test_off_header_disables_and_retry_after_backs_off_without_losing_data(
    reporter_factory: Callable[..., TelemetryReporter],
) -> None:
    clock = _Clock()
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            return httpx.Response(429, headers={"retry-after": "120"})
        return httpx.Response(202, json={"policy": {}})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    reporter = reporter_factory(
        clock=clock,
        api_key_provider=lambda: "sk-tr-test",
        http_client_factory=lambda: client,
    )
    _record(reporter, _event(final_outcome="http_error"))
    assert reporter.flush_now() is False
    clock.advance(119)
    assert reporter.flush_now() is False
    assert calls == 1
    clock.advance(1)
    assert reporter.flush_now() is True
    assert calls == 2

    off_client = httpx.Client(
        transport=httpx.MockTransport(
            lambda _request: httpx.Response(202, headers={"x-tr-telemetry": "off"})
        )
    )
    off = reporter_factory(
        api_key_provider=lambda: "sk-tr-test",
        http_client_factory=lambda: off_client,
    )
    _record(off, _event(final_outcome="http_error"))
    assert off.flush_now() is True
    assert off._disabled is True


def test_transport_error_backs_off_and_debug_echoes_exact_batch(
    capsys: pytest.CaptureFixture[str],
    reporter_factory: Callable[..., TelemetryReporter],
) -> None:
    clock = _Clock()
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise httpx.ConnectError("offline")
        return httpx.Response(202, json={"policy": {}})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    reporter = reporter_factory(
        clock=clock,
        api_key_provider=lambda: "sk-tr-test",
        http_client_factory=lambda: client,
        debug=True,
    )
    _record(reporter, _event(final_outcome="transport_error"))
    assert reporter.flush_now() is False
    assert "trustedrouter telemetry batch: " in capsys.readouterr().err
    clock.advance(59)
    assert reporter.flush_now() is False
    clock.advance(1)
    assert reporter.flush_now() is True


def test_lifecycle_is_lazy_fork_safe_and_close_is_bounded(
    reporter_factory: Callable[..., TelemetryReporter],
) -> None:
    def slow_handler(_request: httpx.Request) -> httpx.Response:
        time.sleep(5)
        return httpx.Response(202, json={"policy": {}})

    client = httpx.Client(transport=httpx.MockTransport(slow_handler))
    reporter = reporter_factory(
        api_key_provider=lambda: "sk-tr-test",
        http_client_factory=lambda: client,
    )
    assert reporter._thread is None
    _record(reporter, _event(final_outcome="http_error"))
    assert reporter._thread is not None
    assert reporter._thread.daemon is True
    reporter._reset_after_fork()
    assert reporter._thread is None
    assert not reporter._events
    assert not reporter._current_counters
    assert not reporter._closed_windows

    _record(reporter, _event(final_outcome="http_error"))
    started = time.monotonic()
    reporter.close(0.5)
    assert time.monotonic() - started < 1.0


def test_facades_construct_reporters_only_for_enabled_inference_calls() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"ok": True})

    disabled = TrustedRouter(
        telemetry=False,
        regional_affinity=False,
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    assert disabled._telemetry_sink is None
    assert disabled.request("GET", "/models") == {"ok": True}
    assert disabled._telemetry_sink is None

    custom = TrustedRouter(
        base_url="https://private.example/v1",
        regional_affinity=False,
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    assert custom.request("GET", "/models") == {"ok": True}
    assert custom._telemetry_sink is None

    enabled = TrustedRouter(
        regional_affinity=False,
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    assert enabled._telemetry_sink is None
    assert enabled.request("GET", "/models") == {"ok": True}
    assert isinstance(enabled._telemetry_sink, TelemetryReporter)
    enabled.close()


@pytest.mark.asyncio
async def test_async_facade_uses_the_same_thread_reporter_and_closes_it() -> None:
    client = httpx.AsyncClient(
        transport=httpx.MockTransport(lambda _request: httpx.Response(200, json={"ok": True}))
    )
    sdk = AsyncTrustedRouter(client=client, regional_affinity=False)
    assert await sdk.request("GET", "/models") == {"ok": True}
    assert isinstance(sdk._telemetry_sink, TelemetryReporter)
    reporter = sdk._telemetry_sink
    await sdk.aclose()
    assert reporter._closed is True


def test_sdk_identity_uses_only_the_contract_vocabulary() -> None:
    identity = sdk_identity()
    assert identity["name"] == "tr-py"
    assert identity["lang"] == "python"
    assert re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+].+)?", identity["version"])
    assert re.fullmatch(r"[a-z]{1,10}/[0-9A-Za-z.+-]{1,24}", identity["runtime"])
    assert identity["os"] in {"linux", "macos", "windows", "freebsd", "other"}
    assert identity["arch"] in {"x64", "x32", "arm", "arm64", "wasm", "other"}
    assert set(TELEMETRY_HOSTS) >= {"apex", "custom"}
    assert set(TELEMETRY_FINAL_OUTCOMES) >= {"ok", "exhausted"}
    assert set(TELEMETRY_TIMEOUT_PHASES) >= {"none", "idle"}
