"""Content-free client telemetry recording with no network side effects."""

from __future__ import annotations

import math
import os
import re
import socket
import ssl
import time
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from typing import Any, Protocol
from urllib.parse import urlsplit

import httpx

from trustedrouter._constants import (
    ALIAS_API_BASE_URLS,
    DEFAULT_API_BASE_URL,
    DEFAULT_CONTROL_BASE_URL,
    REGION_BASE_URLS,
    TELEMETRY_ENDPOINTS,
    TELEMETRY_LATENCY_BUCKETS,
)
from trustedrouter._retry import _retry_after_seconds

_MAX_DURATION_MS = 3_600_000
_HEADER_VALUE_RE = re.compile(r"^[a-z0-9_]{1,24}$")
_MODEL_RE = re.compile(r"^[A-Za-z0-9._:/~@-]{1,128}$")
_REQUEST_ID_RE = re.compile(r"^rlog_[0-9a-f]{32}$")
_LATENCY_UPPER_BOUNDS = (100, 200, 400, 800, 1600, 3200, 6400, 12800, 25600, 51200, 102400)


def _scheme_host(url: str) -> tuple[str, str] | None:
    try:
        parsed = urlsplit(url)
        if not parsed.scheme or not parsed.hostname:
            return None
        return parsed.scheme.lower(), parsed.hostname.lower()
    except ValueError:
        return None


def _control_host(url: str) -> bool:
    scheme_host = _scheme_host(url)
    if scheme_host is None:
        return False
    scheme, host = scheme_host
    trustedrouter_host = host == "trustedrouter.com" or host.endswith(".trustedrouter.com")
    return scheme == "https" and trustedrouter_host


def host_enum(base_url: str) -> str:
    """Map a URL to the closed telemetry host vocabulary."""
    scheme_host = _scheme_host(base_url)
    if scheme_host is None:
        return "custom"
    if scheme_host == _scheme_host(DEFAULT_API_BASE_URL):
        return "apex"
    if scheme_host == _scheme_host(ALIAS_API_BASE_URLS[0]):
        return "ally"
    if scheme_host == _scheme_host(ALIAS_API_BASE_URLS[1]):
        return "uptime"
    regions = ("us_central1", "us_east4", "europe_west4")
    for region_url, region in zip(REGION_BASE_URLS, regions, strict=True):
        if scheme_host == _scheme_host(region_url):
            return region
    if scheme_host == _scheme_host(DEFAULT_CONTROL_BASE_URL) or _control_host(base_url):
        return "control"
    return "custom"


def endpoint_enum(path: str) -> str:
    """Map an inference path to the closed telemetry endpoint vocabulary."""
    parsed = urlsplit(path)
    clean_path = parsed.path.rstrip("/") or "/"
    exact = {
        "/chat/completions": "chat_completions",
        "/messages": "messages",
        "/responses": "responses",
        "/embeddings": "embeddings",
    }
    if clean_path in exact:
        return exact[clean_path]
    for prefix, endpoint in (
        ("/images", "images"),
        ("/videos", "videos"),
        ("/models", "models"),
        ("/fusion", "fusion"),
    ):
        if clean_path == prefix or clean_path.startswith(f"{prefix}/"):
            return endpoint
    return "inference_other"


def _exception_chain(exc: BaseException) -> list[BaseException]:
    chain: list[BaseException] = []
    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and len(chain) < 6 and id(current) not in seen:
        chain.append(current)
        seen.add(id(current))
        current = current.__cause__ or current.__context__
    return chain


def classify_transport_error(exc: BaseException) -> tuple[str, str]:
    """Classify a transport exception and its timeout phase."""
    chain = _exception_chain(exc)
    if any(isinstance(item, httpx.ConnectTimeout) for item in chain):
        return "connect_timeout", "connect"
    if any(isinstance(item, httpx.ReadTimeout) for item in chain):
        return "read_timeout", "first_byte"
    if any(isinstance(item, httpx.WriteTimeout) for item in chain):
        return "write_timeout", "first_byte"
    if any(isinstance(item, httpx.PoolTimeout) for item in chain):
        return "pool_timeout", "none"
    if any(isinstance(item, ssl.SSLError) for item in chain):
        return "tls", "none"
    if any(isinstance(item, socket.gaierror) for item in chain):
        return "dns", "none"
    if any(isinstance(item, ConnectionRefusedError) for item in chain):
        return "connect_refused", "none"
    if any(isinstance(item, ConnectionResetError) for item in chain):
        return "reset", "none"
    if any(isinstance(item, httpx.ConnectError) for item in chain):
        return "connect_error", "none"
    protocol_errors = (httpx.RemoteProtocolError, httpx.LocalProtocolError)
    if any(isinstance(item, protocol_errors) for item in chain):
        return "protocol_error", "none"
    if any(isinstance(item, (httpx.ReadError, httpx.WriteError)) for item in chain):
        return "io_error", "none"
    if any(isinstance(item, httpx.ProxyError) for item in chain):
        return "proxy_error", "none"
    return "unknown", "none"


def latency_bucket(ms: int) -> str:
    value = max(0, int(ms))
    for upper, name in zip(
        _LATENCY_UPPER_BOUNDS, TELEMETRY_LATENCY_BUCKETS[:-1], strict=True
    ):
        if value < upper:
            return name
    return TELEMETRY_LATENCY_BUCKETS[-1]


def status_class(status: int | None) -> str:
    if status is None:
        return "none"
    if 200 <= status <= 299:
        return "2xx"
    if status == 429:
        return "429"
    if 400 <= status <= 499:
        return "4xx"
    if 500 <= status <= 599:
        return "5xx"
    return "none"


def timeout_floor_met(phase: str, configured_ms: int | None) -> bool:
    if configured_ms is None:
        return False
    floors = {"connect": 10_000, "first_byte": 60_000, "idle": 30_000}
    floor = floors.get(phase)
    return floor is not None and configured_ms >= floor


def resolve_telemetry_enabled(
    explicit: bool | None,
    *,
    base_url: str,
    control_base_url: str,
    environ: Mapping[str, str],
) -> bool:
    """Resolve opt-out precedence without reading process state implicitly."""
    if explicit is not None:
        return explicit
    configured = environ.get("TRUSTEDROUTER_TELEMETRY", "").strip().lower()
    if configured in {"0", "false", "off", "no"}:
        return False
    if configured in {"1", "true", "on", "yes"}:
        return True
    if environ.get("DO_NOT_TRACK", "").strip() == "1":
        return False
    return host_enum(base_url) != "custom" and _control_host(control_base_url)


class TelemetrySink(Protocol):
    def on_request(
        self,
        event: dict[str, Any],
        counters: list[tuple[tuple[Any, ...], dict[str, Any]]],
    ) -> None: ...


class NullSink:
    def on_request(
        self,
        event: dict[str, Any],
        counters: list[tuple[tuple[Any, ...], dict[str, Any]]],
    ) -> None:
        pass


class RecordingSink:
    """In-memory sink for tests and telemetry debug tooling."""

    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []
        self.counters: list[tuple[tuple[Any, ...], dict[str, Any]]] = []

    def on_request(
        self,
        event: dict[str, Any],
        counters: list[tuple[tuple[Any, ...], dict[str, Any]]],
    ) -> None:
        self.events.append(event)
        self.counters.extend(counters)


@dataclass
class AttemptRecord:
    index: int
    host: str
    outcome: str
    http_status: int | None
    error_class: str | None
    error_source: str | None
    should_retry: str
    retry_after_ms: int | None
    elapsed_ms: int
    ttfb_ms: int | None
    request_id: str | None
    moved: bool


def _duration_ms(start: float, end: float | None = None) -> int:
    elapsed = (time.perf_counter() if end is None else end) - start
    return min(_MAX_DURATION_MS, max(0, int(elapsed * 1000)))


def _header(headers: Mapping[str, str], name: str) -> str | None:
    wanted = name.lower()
    for key, value in headers.items():
        if key.lower() == wanted:
            return value
    return None


class RequestRecorder:
    """Record one logical inference call and derive its exact counter increments."""

    def __init__(
        self,
        sink: TelemetrySink,
        *,
        endpoint: str,
        method: str,
        streaming: bool,
        provider_pinned: bool,
        model: str | None,
        configured_timeout: float | httpx.Timeout | None,
        since_first: float | None = None,
    ) -> None:
        self.sink = sink
        self.endpoint = endpoint
        self.method = method.upper()
        self._recordable = endpoint in TELEMETRY_ENDPOINTS and self.method in {
            "GET",
            "POST",
            "PUT",
            "PATCH",
            "DELETE",
        }
        self.streaming = streaming
        self.provider_pinned = provider_pinned
        self.model = model if isinstance(model, str) and _MODEL_RE.fullmatch(model) else None
        self.configured_timeout = configured_timeout
        self.attempts: list[AttemptRecord] = []
        self.failover_used = False
        self.ttft_ms: int | None = None
        self._attempt_phases: list[str] = []
        self._first_started = since_first
        self._attempt_started: float | None = None
        self._current_host: str | None = None
        self._current_index: int | None = None
        self._finished = False

    def begin_attempt(self, base_url: str) -> None:
        started = time.perf_counter()
        if self._first_started is None:
            self._first_started = started
        self._attempt_started = started
        self._current_host = host_enum(base_url)
        self._current_index = len(self.attempts)

    def header_value(self) -> str | None:
        if self._current_host == "custom" or self._current_index is None:
            return None
        values = ["v=1", f"a={self._current_index}"]
        if self._current_index:
            previous = self.attempts[-1]
            first_started = self._first_started
            if first_started is None:
                first_started = self._attempt_started or time.perf_counter()
            since_first_ms = _duration_ms(
                first_started,
                self._attempt_started,
            )
            values.extend(
                (
                    f"po={previous.outcome}",
                    f"pc={previous.error_class or 'none'}",
                    f"ph={previous.host}",
                    f"pm={previous.elapsed_ms}",
                    f"sm={since_first_ms}",
                )
            )
        values.append(f"s={int(self.streaming)}")
        if self._current_index:
            values.append(f"fo={int(self.failover_used)}")
        header = ";".join(values)
        # Bounded by construction (enum values, ms <= 7 digits, <= 9 keys), but
        # telemetry may never raise on the request path -- and `assert` is
        # stripped under -O -- so an out-of-grammar value simply sends nothing.
        if len(header) > 160 or not all(
            _HEADER_VALUE_RE.fullmatch(part.split("=", 1)[1]) for part in values
        ):
            return None
        return header

    def _store_attempt(self, attempt: AttemptRecord, phase: str) -> None:
        if attempt.index < len(self.attempts):
            self.attempts[attempt.index] = attempt
            self._attempt_phases[attempt.index] = phase
        else:
            self.attempts.append(attempt)
            self._attempt_phases.append(phase)

    def on_response(
        self,
        status_code: int,
        headers: Mapping[str, str],
        *,
        error_source: str | None = None,
    ) -> None:
        if self._attempt_started is None or self._current_host is None:
            return
        elapsed_ms = _duration_ms(self._attempt_started)
        should_retry = _header(headers, "x-should-retry")
        should_retry = (
            should_retry.strip().lower()
            if should_retry is not None and should_retry.strip().lower() in {"true", "false"}
            else "absent"
        )
        retry_after = _retry_after_seconds(headers)
        request_id = _header(headers, "x-request-id")
        if request_id is None or _REQUEST_ID_RE.fullmatch(request_id) is None:
            request_id = None
        if error_source not in {"router", "provider", "unknown"}:
            error_source = None
        index = self._current_index if self._current_index is not None else len(self.attempts)
        self._store_attempt(
            AttemptRecord(
                index=index,
                host=self._current_host,
                outcome="ok" if status_code < 400 else "http_error",
                http_status=status_code,
                error_class=None,
                error_source=error_source,
                should_retry=should_retry,
                retry_after_ms=(
                    min(_MAX_DURATION_MS, max(0, int(retry_after * 1000)))
                    if retry_after is not None
                    else None
                ),
                elapsed_ms=elapsed_ms,
                ttfb_ms=elapsed_ms,
                request_id=request_id,
                moved=False,
            ),
            "none",
        )

    def on_transport_error(
        self,
        exc: BaseException,
        *,
        response_opened: bool,
        body_started: bool,
    ) -> None:
        if self._attempt_started is None or self._current_host is None:
            return
        error_class, phase = classify_transport_error(exc)
        if isinstance(exc, httpx.TimeoutException):
            outcome = "timeout"
            if body_started:
                phase = "idle"
                if isinstance(exc, httpx.ReadTimeout):
                    error_class = "stream_stalled"
        elif body_started:
            outcome = "stream_broken"
        else:
            outcome = "transport_error"
        index = self._current_index if self._current_index is not None else len(self.attempts)
        previous = self.attempts[index] if index < len(self.attempts) else None
        elapsed_ms = _duration_ms(self._attempt_started)
        self._store_attempt(
            AttemptRecord(
                index=index,
                host=self._current_host,
                outcome=outcome,
                http_status=previous.http_status if response_opened and previous else None,
                error_class=error_class,
                error_source=previous.error_source if previous else None,
                should_retry=previous.should_retry if previous else "absent",
                retry_after_ms=previous.retry_after_ms if previous else None,
                elapsed_ms=elapsed_ms,
                ttfb_ms=previous.ttfb_ms if response_opened and previous else None,
                request_id=previous.request_id if previous else None,
                moved=False,
            ),
            phase,
        )

    def on_moved(self) -> None:
        if not self.attempts:
            return
        self.attempts[-1].moved = True
        self.failover_used = True

    def on_first_event(self) -> None:
        if self.ttft_ms is None and self._first_started is not None:
            self.ttft_ms = _duration_ms(self._first_started)

    def on_aborted(self) -> None:
        if self._attempt_started is None or self._current_host is None:
            return
        index = self._current_index if self._current_index is not None else len(self.attempts)
        previous = self.attempts[index] if index < len(self.attempts) else None
        self._store_attempt(
            AttemptRecord(
                index=index,
                host=self._current_host,
                outcome="aborted",
                http_status=previous.http_status if previous else None,
                error_class=previous.error_class if previous else None,
                error_source=previous.error_source if previous else None,
                should_retry=previous.should_retry if previous else "absent",
                retry_after_ms=previous.retry_after_ms if previous else None,
                elapsed_ms=_duration_ms(self._attempt_started),
                ttfb_ms=previous.ttfb_ms if previous else None,
                request_id=previous.request_id if previous else None,
                moved=previous.moved if previous else False,
            ),
            self._attempt_phases[index] if previous else "none",
        )

    def _configured_timeout_ms(self, phase: str) -> int | None:
        timeout: float | None
        if isinstance(self.configured_timeout, httpx.Timeout):
            if phase == "connect":
                timeout = self.configured_timeout.connect
            elif phase in {"first_byte", "idle"}:
                timeout = self.configured_timeout.read
            else:
                timeout = None
        elif isinstance(self.configured_timeout, (int, float)):
            timeout = float(self.configured_timeout)
        else:
            timeout = None
        if timeout is None or not math.isfinite(timeout) or timeout <= 0:
            return None
        return min(_MAX_DURATION_MS, max(1, int(timeout * 1000)))

    def _finish(self, *, exhausted: bool) -> None:
        if not self._recordable or not self.attempts or self._first_started is None:
            return
        final = self.attempts[-1]
        final_outcome = (
            "exhausted"
            if exhausted and len(self.attempts) > 1 and final.outcome != "ok"
            else final.outcome
        )
        timeout_phase = self._attempt_phases[-1]
        configured_timeout_ms = self._configured_timeout_ms(timeout_phase)
        total_ms = _duration_ms(self._first_started)
        event = {
            "age_ms": 0,
            "plane": "inference",
            "endpoint": self.endpoint,
            "method": self.method,
            "streaming": self.streaming,
            "provider_pinned": self.provider_pinned,
            "model": self.model,
            "attempts": [asdict(attempt) for attempt in self.attempts],
            "final_outcome": final_outcome,
            "final_http_status": final.http_status,
            "total_ms": total_ms,
            "ttft_ms": self.ttft_ms,
            "failover_used": self.failover_used,
            "timeout_phase": timeout_phase,
            "configured_timeout_ms": configured_timeout_ms,
        }
        counter_outcome = final.outcome if final_outcome == "exhausted" else final_outcome
        first_error_class = next(
            (attempt.error_class for attempt in self.attempts if attempt.error_class is not None),
            None,
        )
        request_key = (
            "request",
            self.endpoint,
            self.streaming,
            final.host,
            counter_outcome,
            first_error_class,
            status_class(final.http_status),
            timeout_phase,
            timeout_floor_met(timeout_phase, configured_timeout_ms),
            self.provider_pinned,
        )
        request_increment: dict[str, Any] = {
            "requests": 1,
            "attempts": len(self.attempts),
            "failover_used": int(self.failover_used),
            "first_attempt_success": int(self.attempts[0].outcome == "ok"),
            "total_ms_hist": {latency_bucket(total_ms): 1},
        }
        first_event_ms = self.ttft_ms if self.ttft_ms is not None else final.ttfb_ms
        if first_event_ms is not None:
            request_increment["first_event_ms_hist"] = {latency_bucket(first_event_ms): 1}
        counters = [(request_key, request_increment)]
        for attempt, phase in zip(self.attempts, self._attempt_phases, strict=True):
            attempt_timeout_ms = self._configured_timeout_ms(phase)
            attempt_key = (
                "attempt",
                self.endpoint,
                self.streaming,
                attempt.host,
                attempt.outcome,
                attempt.error_class,
                status_class(attempt.http_status),
                phase,
                timeout_floor_met(phase, attempt_timeout_ms),
                self.provider_pinned,
            )
            counters.append(
                (
                    attempt_key,
                    {
                        "requests": 1,
                        "attempts": 1,
                        "failover_used": int(attempt.moved),
                        "first_attempt_success": 0,
                    },
                )
            )
        self.sink.on_request(event, counters)

    def finish(self, *, exhausted: bool) -> None:
        if self._finished:
            return
        self._finished = True
        try:
            self._finish(exhausted=exhausted)
        except Exception:  # noqa: BLE001
            if os.environ.get("TRUSTEDROUTER_TELEMETRY_STRICT") == "1":
                raise
