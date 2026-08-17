"""Content-free client reliability telemetry recording and delivery."""

from __future__ import annotations

import atexit
import json
import logging
import math
import os
import platform
import re
import secrets
import socket
import ssl
import sys
import threading
import time
import weakref
from collections import deque
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass
from typing import Any, Protocol
from urllib.parse import urlsplit

import httpx

from trustedrouter._constants import (
    ALIAS_API_BASE_URLS,
    DEFAULT_API_BASE_URL,
    DEFAULT_CONTROL_BASE_URL,
    DEFAULT_TELEMETRY_PATH,
    REGION_BASE_URLS,
    TELEMETRY_BACKOFF_MAX_SECONDS,
    TELEMETRY_BACKOFF_MIN_SECONDS,
    TELEMETRY_ENDPOINTS,
    TELEMETRY_ERROR_CLASSES,
    TELEMETRY_FINAL_OUTCOMES,
    TELEMETRY_FLUSH_SECONDS,
    TELEMETRY_HOSTS,
    TELEMETRY_LATENCY_BUCKETS,
    TELEMETRY_MAX_BATCH_COUNTERS,
    TELEMETRY_MAX_BATCH_EVENTS,
    TELEMETRY_MAX_EVENTS,
    TELEMETRY_MAX_WINDOW_KEYS,
    TELEMETRY_OUTCOMES,
    TELEMETRY_RETENTION_BYTES,
    TELEMETRY_RETENTION_SECONDS,
    TELEMETRY_SCHEMA_VERSION,
    TELEMETRY_TIMEOUT_PHASES,
)
from trustedrouter._requests import _DEFAULT_USER_AGENT
from trustedrouter._retry import _retry_after_seconds

_MAX_DURATION_MS = 3_600_000
_HEADER_VALUE_RE = re.compile(r"^[a-z0-9_]{1,24}$")
_MODEL_RE = re.compile(r"^[A-Za-z0-9._:/~@-]{1,128}$")
_REQUEST_ID_RE = re.compile(r"^rlog_[0-9a-f]{32}$")
_SEMVER_RE = re.compile(
    r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)
_RUNTIME_RE = re.compile(r"^[a-z]{1,10}/[0-9A-Za-z.+-]{1,24}$")
_LATENCY_UPPER_BOUNDS = (100, 200, 400, 800, 1600, 3200, 6400, 12800, 25600, 51200, 102400)
_HTTP_STATUS_CLASSES = {"none", "2xx", "4xx", "429", "5xx"}
_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE"}
_SAMPLE_REASONS = {"failure", "retried", "slow", "random"}
_BATCH_TRIGGER_BYTES = 60 * 1024
_MAX_BATCH_BYTES = 65_536
_logger = logging.getLogger(__name__)


def _os_enum(system: str | None = None) -> str:
    """Return the process OS using the contract's closed vocabulary."""
    value = (platform.system() if system is None else system).strip().lower()
    return {
        "darwin": "macos",
        "linux": "linux",
        "windows": "windows",
        "freebsd": "freebsd",
    }.get(value, "other")


def _arch_enum(machine: str | None = None) -> str:
    """Return the process architecture using the contract's closed vocabulary."""
    value = (platform.machine() if machine is None else machine).strip().lower()
    if value in {"x86_64", "amd64"}:
        return "x64"
    if value in {"i386", "i486", "i586", "i686", "x86"}:
        return "x32"
    if value in {"aarch64", "arm64"}:
        return "arm64"
    if value.startswith("arm"):
        return "arm"
    if value.startswith("wasm"):
        return "wasm"
    return "other"


def sdk_identity() -> dict[str, str]:
    """Build the bounded SDK identity included in every telemetry batch."""
    try:
        from importlib.metadata import version

        sdk_version = version("trusted-router-py")
    except Exception:  # noqa: BLE001
        sdk_version = "0.0.0"
    if len(sdk_version) > 32 or _SEMVER_RE.fullmatch(sdk_version) is None:
        sdk_version = "0.0.0"
    implementation = getattr(sys.implementation, "name", "cpython").lower()
    if implementation not in {"cpython", "pypy"}:
        implementation = "cpython"
    py_version = sys.version_info
    runtime = f"{implementation}/{py_version.major}.{py_version.minor}.{py_version.micro}"
    if _RUNTIME_RE.fullmatch(runtime) is None:
        runtime = "cpython/0.0.0"
    return {
        "name": "tr-py",
        "version": sdk_version,
        "lang": "python",
        "runtime": runtime,
        "os": _os_enum(),
        "arch": _arch_enum(),
    }


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
class _CounterWindow:
    window_start: float
    rows: dict[tuple[Any, ...], dict[str, Any]]
    size_bytes: int


def _bounded_int(value: Any, minimum: int, maximum: int) -> int:
    try:
        return min(maximum, max(minimum, int(value)))
    except (TypeError, ValueError, OverflowError):
        return minimum


def _bounded_optional_int(value: Any, minimum: int, maximum: int) -> int | None:
    if value is None:
        return None
    try:
        parsed = int(value)
    except (TypeError, ValueError, OverflowError):
        return None
    if parsed < minimum or parsed > maximum:
        return None
    return parsed


def _float_value(value: object) -> float | None:
    if not isinstance(value, (str, int, float)):
        return None
    try:
        parsed = float(value)
    except (TypeError, ValueError, OverflowError):
        return None
    return parsed if math.isfinite(parsed) else None


def _normalise_sdk_identity(identity: Mapping[str, Any]) -> dict[str, str]:
    fallback = sdk_identity()
    name = identity.get("name")
    if name not in {"tr-py", "tr-js", "tr-go", "tr-rust", "tr-java", "tr-swift"}:
        name = fallback["name"]
    version = identity.get("version")
    if (
        not isinstance(version, str)
        or len(version) > 32
        or _SEMVER_RE.fullmatch(version) is None
    ):
        version = fallback["version"]
    lang = identity.get("lang")
    if lang not in {"python", "js", "go", "rust", "java", "swift"}:
        lang = fallback["lang"]
    runtime = identity.get("runtime")
    if not isinstance(runtime, str) or _RUNTIME_RE.fullmatch(runtime) is None:
        runtime = fallback["runtime"]
    os_name = identity.get("os")
    if os_name not in {"linux", "macos", "windows", "ios", "android", "freebsd", "other"}:
        os_name = fallback["os"]
    arch = identity.get("arch")
    if arch not in {"x64", "x32", "arm", "arm64", "wasm", "other"}:
        arch = fallback["arch"]
    return {
        "name": name,
        "version": version,
        "lang": lang,
        "runtime": runtime,
        "os": os_name,
        "arch": arch,
    }


def _normalise_counter_key(key: tuple[Any, ...]) -> tuple[Any, ...] | None:
    if len(key) != 10:
        return None
    (
        level,
        endpoint,
        streaming,
        host,
        outcome,
        error_class,
        http_status_class,
        timeout_phase,
        floor_met,
        provider_pinned,
    ) = key
    if level not in {"attempt", "request"}:
        return None
    if endpoint not in TELEMETRY_ENDPOINTS:
        endpoint = "inference_other"
    if host not in TELEMETRY_HOSTS:
        host = "custom"
    if outcome not in TELEMETRY_FINAL_OUTCOMES:
        return None
    if error_class is not None and error_class not in TELEMETRY_ERROR_CLASSES:
        error_class = "unknown"
    if http_status_class not in _HTTP_STATUS_CLASSES:
        http_status_class = "none"
    if timeout_phase not in TELEMETRY_TIMEOUT_PHASES:
        timeout_phase = "none"
    return (
        level,
        endpoint,
        bool(streaming),
        host,
        outcome,
        error_class,
        http_status_class,
        timeout_phase,
        bool(floor_met),
        bool(provider_pinned),
    )


def _merge_histogram(target: dict[str, int], source: Any) -> None:
    if not isinstance(source, Mapping):
        return
    for bucket, count in source.items():
        if bucket not in TELEMETRY_LATENCY_BUCKETS:
            continue
        parsed = _bounded_int(count, 0, 10_000_000)
        target[bucket] = target.get(bucket, 0) + parsed


def _merge_counter_increment(target: dict[str, Any], increment: Mapping[str, Any]) -> None:
    for field in ("requests", "attempts", "failover_used", "first_attempt_success"):
        value = _bounded_int(increment.get(field, 0), 0, 10_000_000)
        target[field] = target.get(field, 0) + value
    for field in ("total_ms_hist", "first_event_ms_hist"):
        histogram = target.setdefault(field, {})
        _merge_histogram(histogram, increment.get(field, {}))


def _wire_attempt(attempt: Mapping[str, Any]) -> dict[str, Any]:
    host = attempt.get("host")
    if host not in TELEMETRY_HOSTS:
        host = "custom"
    outcome = attempt.get("outcome")
    if outcome not in TELEMETRY_OUTCOMES:
        outcome = "transport_error"
    error_class = attempt.get("error_class")
    if error_class not in TELEMETRY_ERROR_CLASSES:
        error_class = None
    error_source = attempt.get("error_source")
    if error_source not in {"router", "provider", "unknown"}:
        error_source = None
    request_id = attempt.get("request_id")
    if not isinstance(request_id, str) or _REQUEST_ID_RE.fullmatch(request_id) is None:
        request_id = None
    wire = {
        "index": _bounded_int(attempt.get("index"), 0, 99),
        "host": host,
        "outcome": outcome,
        "http_status": _bounded_optional_int(attempt.get("http_status"), 100, 599),
        "error_class": error_class,
        "error_source": error_source,
        "retry_after_ms": _bounded_optional_int(
            attempt.get("retry_after_ms"), 0, _MAX_DURATION_MS
        ),
        "elapsed_ms": _bounded_int(attempt.get("elapsed_ms"), 0, _MAX_DURATION_MS),
        "ttfb_ms": _bounded_optional_int(attempt.get("ttfb_ms"), 0, _MAX_DURATION_MS),
        "request_id": request_id,
        "moved": bool(attempt.get("moved")),
    }
    should_retry = attempt.get("should_retry")
    if should_retry is True or should_retry == "true":
        wire["should_retry"] = True
    elif should_retry is False or should_retry == "false":
        wire["should_retry"] = False
    return wire


def _wire_event(event: Mapping[str, Any], now: float) -> dict[str, Any] | None:
    attempts_value = event.get("attempts")
    if not isinstance(attempts_value, list):
        return None
    attempts = [_wire_attempt(item) for item in attempts_value[:16] if isinstance(item, Mapping)]
    if not attempts:
        return None
    completed_at = event.get("_completed_at", now)
    try:
        age_ms = int((now - float(completed_at)) * 1000)
    except (TypeError, ValueError, OverflowError):
        age_ms = 0
    endpoint = event.get("endpoint")
    if endpoint not in TELEMETRY_ENDPOINTS:
        endpoint = "inference_other"
    method = event.get("method")
    if method not in _METHODS:
        method = "POST"
    model = event.get("model")
    if not isinstance(model, str) or _MODEL_RE.fullmatch(model) is None:
        model = None
    final_outcome = event.get("final_outcome")
    if final_outcome not in TELEMETRY_FINAL_OUTCOMES:
        final_outcome = attempts[-1]["outcome"]
    timeout_phase = event.get("timeout_phase")
    if timeout_phase not in TELEMETRY_TIMEOUT_PHASES:
        timeout_phase = "none"
    sample_reason = event.get("sample_reason")
    if sample_reason not in _SAMPLE_REASONS:
        return None
    sample_rate = _float_value(event.get("sample_rate"))
    if sample_rate is None:
        return None
    if sample_rate <= 0 or sample_rate > 1:
        return None
    return {
        "age_ms": min(86_400_000, max(0, age_ms)),
        "plane": "inference",
        "endpoint": endpoint,
        "method": method,
        "streaming": bool(event.get("streaming")),
        "provider_pinned": bool(event.get("provider_pinned")),
        "model": model,
        "attempts": attempts,
        "final_outcome": final_outcome,
        "final_http_status": _bounded_optional_int(
            event.get("final_http_status"), 100, 599
        ),
        "total_ms": _bounded_int(event.get("total_ms"), 0, _MAX_DURATION_MS),
        "ttft_ms": _bounded_optional_int(event.get("ttft_ms"), 0, _MAX_DURATION_MS),
        "failover_used": bool(event.get("failover_used")),
        "timeout_phase": timeout_phase,
        "configured_timeout_ms": _bounded_optional_int(
            event.get("configured_timeout_ms"), 1, _MAX_DURATION_MS
        ),
        "sample_rate": sample_rate,
        "sample_reason": sample_reason,
    }


def _counter_row(
    key: tuple[Any, ...], increment: Mapping[str, Any], window_age_ms: int
) -> dict[str, Any]:
    return {
        "window_start_age_ms": min(86_400_000, max(0, window_age_ms)),
        "level": key[0],
        "endpoint": key[1],
        "streaming": key[2],
        "host": key[3],
        "outcome": key[4],
        "error_class": key[5],
        "http_status_class": key[6],
        "timeout_phase": key[7],
        "timeout_floor_met": key[8],
        "provider_pinned": key[9],
        "requests": _bounded_int(increment.get("requests"), 1, 10_000_000),
        "attempts": _bounded_int(increment.get("attempts"), 0, 10_000_000),
        "failover_used": _bounded_int(
            increment.get("failover_used"), 0, 10_000_000
        ),
        "first_attempt_success": _bounded_int(
            increment.get("first_attempt_success"), 0, 10_000_000
        ),
        "total_ms_hist": dict(increment.get("total_ms_hist", {})),
        "first_event_ms_hist": dict(increment.get("first_event_ms_hist", {})),
    }


_REPORTERS: weakref.WeakSet[TelemetryReporter] = weakref.WeakSet()


class TelemetryReporter:
    """Bounded, out-of-engine delivery sink for client reliability telemetry."""

    def __init__(
        self,
        *,
        control_base_url: str,
        api_key_provider: Callable[[], str | None],
        workspace_id: str | None,
        sdk_identity: dict[str, Any],
        success_sample_rate: float = 0.01,
        flush_seconds: float = TELEMETRY_FLUSH_SECONDS,
        http_client_factory: Callable[[], httpx.Client] | None = None,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
        debug: bool = False,
    ) -> None:
        self.control_base_url = control_base_url.rstrip("/")
        self._api_key_provider = api_key_provider
        self.workspace_id = workspace_id
        self._sdk_identity = _normalise_sdk_identity(sdk_identity)
        self.success_sample_rate = self._sample_rate(success_sample_rate)
        self.flush_seconds = self._flush_interval(flush_seconds)
        self._http_client_factory = http_client_factory or (
            lambda: httpx.Client(timeout=5.0)
        )
        self._clock = clock
        self._sleep = sleep
        self.debug = debug or os.environ.get("TRUSTEDROUTER_TELEMETRY_DEBUG") == "1"
        self._lock = threading.RLock()
        self._flush_lock = threading.Lock()
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._http_client: httpx.Client | None = None
        self._events: deque[dict[str, Any]] = deque(maxlen=TELEMETRY_MAX_EVENTS)
        self._events_size_bytes = 0
        self._current_window_start: float | None = None
        self._current_counters: dict[tuple[Any, ...], dict[str, Any]] = {}
        self._closed_windows: deque[_CounterWindow] = deque()
        self._retained_window_bytes = 0
        self._dropped_since_last = 0
        self._instance_id = secrets.token_hex(8)
        self._seq = 0
        self._backoff_seconds = TELEMETRY_BACKOFF_MIN_SECONDS
        self._backoff_until = 0.0
        self._paused_until = 0.0
        self._next_flush_at = 0.0
        self._urgent_flush = False
        self._disabled = False
        self._closed = False
        self._at_fork_registered = False
        self._register_at_fork()
        _REPORTERS.add(self)

    @staticmethod
    def _sample_rate(value: Any) -> float:
        try:
            parsed = float(value)
        except (TypeError, ValueError, OverflowError):
            return 0.01
        if not math.isfinite(parsed):
            return 0.01
        return min(1.0, max(0.0, parsed))

    @staticmethod
    def _flush_interval(value: Any) -> float:
        try:
            parsed = float(value)
        except (TypeError, ValueError, OverflowError):
            return TELEMETRY_FLUSH_SECONDS
        if not math.isfinite(parsed) or parsed <= 0:
            return TELEMETRY_FLUSH_SECONDS
        return min(TELEMETRY_BACKOFF_MAX_SECONDS, parsed)

    def _register_at_fork(self) -> None:
        if self._at_fork_registered or not hasattr(os, "register_at_fork"):
            return
        reporter_ref = weakref.ref(self)

        def reset() -> None:
            reporter = reporter_ref()
            if reporter is not None:
                reporter._reset_after_fork()

        os.register_at_fork(after_in_child=reset)
        self._at_fork_registered = True

    def _reset_after_fork(self) -> None:
        old_stop = self._stop
        old_wake = self._wake
        old_stop.set()
        old_wake.set()
        self._lock = threading.RLock()
        self._flush_lock = threading.Lock()
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._thread = None
        self._http_client = None
        self._events = deque(maxlen=TELEMETRY_MAX_EVENTS)
        self._events_size_bytes = 0
        self._current_window_start = None
        self._current_counters = {}
        self._closed_windows = deque()
        self._retained_window_bytes = 0
        self._dropped_since_last = 0
        self._instance_id = secrets.token_hex(8)
        self._seq = 0
        self._backoff_seconds = TELEMETRY_BACKOFF_MIN_SECONDS
        self._backoff_until = 0.0
        self._paused_until = 0.0
        self._next_flush_at = 0.0
        self._urgent_flush = False
        self._disabled = False
        self._closed = False

    def _start_worker_locked(self, now: float) -> None:
        if self._thread is not None or self._disabled or self._closed:
            return
        self._next_flush_at = now + self.flush_seconds
        self._thread = threading.Thread(
            target=self._worker,
            name="trustedrouter-telemetry",
            daemon=True,
        )
        self._thread.start()

    def _sample_reason(self, event: Mapping[str, Any]) -> tuple[str, float] | None:
        if event.get("final_outcome") != "ok":
            return "failure", 1.0
        attempts = event.get("attempts")
        if (isinstance(attempts, list) and len(attempts) > 1) or bool(
            event.get("failover_used")
        ):
            return "retried", 1.0
        if _bounded_int(event.get("total_ms"), 0, _MAX_DURATION_MS) > 30_000:
            return "slow", 1.0
        rate = self.success_sample_rate
        draw = secrets.randbits(53) / (1 << 53)
        if rate <= 0 or draw >= rate:
            return None
        return "random", rate

    def _drop_buffered_event_locked(self) -> None:
        index = next(
            (
                index
                for index, buffered in enumerate(self._events)
                if buffered.get("final_outcome") == "ok"
            ),
            0,
        )
        self._events.rotate(-index)
        dropped = self._events.popleft()
        self._events.rotate(index)
        self._events_size_bytes -= int(dropped.get("_estimated_bytes", 0))
        self._dropped_since_last += 1

    def _append_event_locked(self, event: dict[str, Any]) -> None:
        if len(self._events) >= TELEMETRY_MAX_EVENTS:
            self._drop_buffered_event_locked()
        try:
            estimated = len(json.dumps(event, separators=(",", ":"), default=str))
        except Exception:  # noqa: BLE001
            estimated = 600
        event["_estimated_bytes"] = estimated
        self._events.append(event)
        self._events_size_bytes += estimated

    def _minute_start(self, now: float) -> float:
        return math.floor(max(0.0, now) / 60.0) * 60.0

    def _roll_window_locked(self, now: float) -> None:
        minute_start = self._minute_start(now)
        if self._current_window_start is None:
            self._current_window_start = minute_start
            return
        if minute_start > self._current_window_start:
            self._close_current_window_locked(now)
            self._current_window_start = minute_start

    def _folded_counter_key(
        self, key: tuple[Any, ...], *, endpoint: bool
    ) -> tuple[Any, ...]:
        values = list(key)
        values[5] = "unknown"
        if endpoint:
            values[1] = "inference_other"
        return tuple(values)

    def _counter_target_locked(self, key: tuple[Any, ...]) -> tuple[Any, ...]:
        if key in self._current_counters or len(self._current_counters) < TELEMETRY_MAX_WINDOW_KEYS:
            return key
        error_folded = self._folded_counter_key(key, endpoint=False)
        if error_folded in self._current_counters:
            return error_folded
        error_compatible = next(
            (
                existing
                for existing in self._current_counters
                if all(existing[index] == key[index] for index in (0, 1, 2, 3, 4, 6, 7, 8, 9))
            ),
            None,
        )
        if error_compatible is not None:
            previous = self._current_counters.pop(error_compatible)
            target = self._folded_counter_key(error_compatible, endpoint=False)
            merged: dict[str, Any] = {}
            _merge_counter_increment(merged, previous)
            self._current_counters[target] = merged
            return target
        endpoint_folded = self._folded_counter_key(key, endpoint=True)
        if endpoint_folded in self._current_counters:
            return endpoint_folded
        compatible = next(
            (
                existing
                for existing in self._current_counters
                if all(existing[index] == key[index] for index in (0, 2, 3, 4, 6, 7, 8, 9))
            ),
            None,
        )
        if compatible is not None:
            previous = self._current_counters.pop(compatible)
            target = self._folded_counter_key(compatible, endpoint=True)
            merged: dict[str, Any] = {}
            _merge_counter_increment(merged, previous)
            self._current_counters[target] = merged
            return target
        return next(iter(self._current_counters))

    def _merge_counters_locked(
        self, counters: list[tuple[tuple[Any, ...], dict[str, Any]]]
    ) -> None:
        for raw_key, increment in counters:
            if not isinstance(raw_key, tuple) or not isinstance(increment, Mapping):
                self._dropped_since_last += 1
                continue
            key = _normalise_counter_key(raw_key)
            if key is None:
                self._dropped_since_last += 1
                continue
            target_key = self._counter_target_locked(key)
            target = self._current_counters.setdefault(target_key, {})
            _merge_counter_increment(target, increment)

    def on_request(
        self,
        event: dict[str, Any],
        counters: list[tuple[tuple[Any, ...], dict[str, Any]]],
    ) -> None:
        try:
            now = float(self._clock())
            reason = self._sample_reason(event)
            sampled: dict[str, Any] | None = None
            invalid_sample = False
            if reason is not None:
                candidate = dict(event)
                candidate["sample_reason"], candidate["sample_rate"] = reason
                candidate["_completed_at"] = now
                sampled = _wire_event(candidate, now)
                if sampled is None:
                    invalid_sample = True
                else:
                    sampled["_completed_at"] = now
            with self._lock:
                if self._disabled or self._closed:
                    return
                self._roll_window_locked(now)
                self._merge_counters_locked(counters)
                if invalid_sample:
                    self._dropped_since_last += 1
                if sampled is not None:
                    self._append_event_locked(sampled)
                self._start_worker_locked(now)
                if (
                    len(self._events) >= 50
                    or self._events_size_bytes + self._retained_window_bytes
                    + len(self._current_counters) * 400
                    >= _BATCH_TRIGGER_BYTES
                ):
                    self._urgent_flush = True
                    self._wake.set()
        except Exception:  # noqa: BLE001
            return

    def _window_size(self, window: _CounterWindow) -> int:
        rows = [_counter_row(key, value, 0) for key, value in window.rows.items()]
        return len(json.dumps(rows, separators=(",", ":")))

    def _close_current_window_locked(self, now: float) -> None:
        if not self._current_counters or self._current_window_start is None:
            return
        window = _CounterWindow(
            window_start=self._current_window_start,
            rows=self._current_counters,
            size_bytes=0,
        )
        window.size_bytes = self._window_size(window)
        self._closed_windows.append(window)
        self._retained_window_bytes += window.size_bytes
        self._current_counters = {}
        self._current_window_start = self._minute_start(now)
        self._prune_windows_locked(now)

    def _drop_window_locked(self, window: _CounterWindow) -> None:
        self._retained_window_bytes -= window.size_bytes
        self._dropped_since_last += len(window.rows)

    def _prune_windows_locked(self, now: float) -> None:
        while (
            self._closed_windows
            and now - self._closed_windows[0].window_start > TELEMETRY_RETENTION_SECONDS
        ):
            self._drop_window_locked(self._closed_windows.popleft())
        while self._closed_windows and self._retained_window_bytes > TELEMETRY_RETENTION_BYTES:
            self._drop_window_locked(self._closed_windows.popleft())

    def _api_key(self) -> str | None:
        try:
            value = self._api_key_provider()
        except Exception:  # noqa: BLE001
            return None
        return value if isinstance(value, str) and value else None

    def _select_batch_locked(
        self, now: float
    ) -> tuple[
        dict[str, Any],
        list[dict[str, Any]],
        list[tuple[_CounterWindow, tuple[Any, ...]]],
        int,
    ] | None:
        self._roll_window_locked(now)
        self._close_current_window_locked(now)
        self._prune_windows_locked(now)
        event_refs: list[dict[str, Any]] = []
        wire_events: list[dict[str, Any]] = []
        invalid_events: list[dict[str, Any]] = []
        for buffered in self._events:
            wire = _wire_event(buffered, now)
            if wire is None:
                invalid_events.append(buffered)
                continue
            event_refs.append(buffered)
            wire_events.append(wire)
            if len(wire_events) >= TELEMETRY_MAX_BATCH_EVENTS:
                break
        if invalid_events:
            invalid_ids = {id(item) for item in invalid_events}
            self._events = deque(
                (item for item in self._events if id(item) not in invalid_ids),
                maxlen=TELEMETRY_MAX_EVENTS,
            )
            self._events_size_bytes = sum(
                int(item.get("_estimated_bytes", 0)) for item in self._events
            )
            self._dropped_since_last += len(invalid_events)
        counter_refs: list[tuple[_CounterWindow, tuple[Any, ...]]] = []
        wire_counters: list[dict[str, Any]] = []
        for window in self._closed_windows:
            age_ms = int((now - window.window_start) * 1000)
            for key, increment in window.rows.items():
                counter_refs.append((window, key))
                wire_counters.append(_counter_row(key, increment, age_ms))
                if len(wire_counters) >= TELEMETRY_MAX_BATCH_COUNTERS:
                    break
            if len(wire_counters) >= TELEMETRY_MAX_BATCH_COUNTERS:
                break
        if not wire_events and not wire_counters:
            return None
        dropped = self._dropped_since_last
        batch: dict[str, Any] = {
            "schema_version": TELEMETRY_SCHEMA_VERSION,
            "batch_id": secrets.token_hex(16),
            "instance_id": self._instance_id,
            "seq": self._seq,
            "sent_at_ms": int(time.time() * 1000),
            "sdk": dict(self._sdk_identity),
            "synthetic": False,
            "dropped_since_last": dropped,
            "events": wire_events,
            "counters": wire_counters,
        }
        self._seq += 1
        while len(json.dumps(batch, separators=(",", ":"))) > _MAX_BATCH_BYTES:
            if batch["events"]:
                batch["events"].pop()
                event_refs.pop()
            elif batch["counters"]:
                batch["counters"].pop()
                counter_refs.pop()
            else:
                return None
        return batch, event_refs, counter_refs, dropped

    def _http(self) -> httpx.Client:
        with self._lock:
            if self._http_client is None:
                self._http_client = self._http_client_factory()
            return self._http_client

    def _retry_after(self, response: httpx.Response) -> float | None:
        value = response.headers.get("retry-after")
        if value is None:
            return None
        try:
            seconds = float(value.strip())
        except (TypeError, ValueError):
            return None
        if not math.isfinite(seconds) or seconds < 0 or seconds > 600:
            return None
        return seconds

    def _set_backoff_locked(self, now: float, retry_after: float | None = None) -> None:
        delay = self._backoff_seconds
        if retry_after is not None:
            delay = max(delay, retry_after)
        self._backoff_until = now + min(TELEMETRY_BACKOFF_MAX_SECONDS, delay)
        self._backoff_seconds = min(
            TELEMETRY_BACKOFF_MAX_SECONDS,
            max(TELEMETRY_BACKOFF_MIN_SECONDS, self._backoff_seconds * 2),
        )
        self._wake.set()

    def _remove_selected_locked(
        self,
        event_refs: list[dict[str, Any]],
        counter_refs: list[tuple[_CounterWindow, tuple[Any, ...]]],
    ) -> None:
        event_ids = {id(item) for item in event_refs}
        self._events = deque(
            (item for item in self._events if id(item) not in event_ids),
            maxlen=TELEMETRY_MAX_EVENTS,
        )
        self._events_size_bytes = sum(
            int(item.get("_estimated_bytes", 0)) for item in self._events
        )
        changed: dict[int, _CounterWindow] = {}
        for window, key in counter_refs:
            if key in window.rows:
                del window.rows[key]
                changed[id(window)] = window
        for window in changed.values():
            self._retained_window_bytes -= window.size_bytes
            window.size_bytes = self._window_size(window) if window.rows else 0
            self._retained_window_bytes += window.size_bytes
        self._closed_windows = deque(
            window for window in self._closed_windows if window.rows
        )

    def _apply_policy_locked(self, response: httpx.Response, now: float) -> None:
        try:
            payload = response.json()
        except Exception:  # noqa: BLE001
            return
        policy = payload.get("policy") if isinstance(payload, Mapping) else None
        if not isinstance(policy, Mapping):
            return
        if "success_sample_rate" in policy:
            sample_rate = _float_value(policy["success_sample_rate"])
            if sample_rate is not None and 0 <= sample_rate < self.success_sample_rate:
                self.success_sample_rate = sample_rate
        if "flush_seconds" in policy:
            flush_seconds = _float_value(policy["flush_seconds"])
            if flush_seconds is not None and flush_seconds > self.flush_seconds:
                self.flush_seconds = min(TELEMETRY_BACKOFF_MAX_SECONDS, flush_seconds)
        pause_seconds = _float_value(policy.get("pause_seconds"))
        if pause_seconds is not None and 0 <= pause_seconds <= 86_400:
            self._paused_until = max(self._paused_until, now + pause_seconds)

    def _disable_locked(self) -> None:
        self._disabled = True
        self._events.clear()
        self._events_size_bytes = 0
        self._current_counters.clear()
        self._closed_windows.clear()
        self._retained_window_bytes = 0
        self._dropped_since_last = 0
        self._stop.set()
        self._wake.set()

    def _handle_response(
        self,
        response: httpx.Response,
        *,
        now: float,
        event_refs: list[dict[str, Any]],
        counter_refs: list[tuple[_CounterWindow, tuple[Any, ...]]],
        dropped: int,
    ) -> None:
        with self._lock:
            if response.headers.get("x-tr-telemetry", "").strip().lower() == "off":
                self._disable_locked()
                return
            if response.status_code == 202:
                self._remove_selected_locked(event_refs, counter_refs)
                self._dropped_since_last = max(0, self._dropped_since_last - dropped)
                self._backoff_seconds = TELEMETRY_BACKOFF_MIN_SECONDS
                self._backoff_until = 0.0
                self._apply_policy_locked(response, now)
                return
            if response.status_code in {400, 401, 403, 404, 410}:
                _logger.debug(
                    "trustedrouter telemetry disabled after HTTP %s", response.status_code
                )
                self._disable_locked()
                return
            if response.status_code == 413:
                self._remove_selected_locked(event_refs, counter_refs)
                self._dropped_since_last += len(event_refs) + len(counter_refs)
                return
            self._set_backoff_locked(now, self._retry_after(response))

    def _flush_once(self, timeout: float | None = None) -> bool:
        with self._flush_lock:
            now = float(self._clock())
            with self._lock:
                if self._disabled or now < max(self._paused_until, self._backoff_until):
                    return False
            api_key = self._api_key()
            if api_key is None:
                return False
            with self._lock:
                selected = self._select_batch_locked(now)
            if selected is None:
                return False
            batch, event_refs, counter_refs, dropped = selected
            if self.debug:
                print(
                    "trustedrouter telemetry batch: "
                    + json.dumps(batch, separators=(",", ":")),
                    file=sys.stderr,
                    flush=True,
                )
            headers = {
                "authorization": f"Bearer {api_key}",
                "user-agent": _DEFAULT_USER_AGENT,
                "content-type": "application/json",
            }
            if self.workspace_id:
                headers["x-trustedrouter-workspace"] = self.workspace_id
            try:
                kwargs: dict[str, Any] = {
                    "headers": headers,
                    "json": batch,
                }
                if timeout is not None:
                    kwargs["timeout"] = max(0.001, timeout)
                response = self._http().post(
                    f"{self.control_base_url}{DEFAULT_TELEMETRY_PATH}",
                    **kwargs,
                )
            except Exception:  # noqa: BLE001
                with self._lock:
                    self._set_backoff_locked(float(self._clock()))
                if os.environ.get("TRUSTEDROUTER_TELEMETRY_STRICT") == "1":
                    raise
                return False
            self._handle_response(
                response,
                now=float(self._clock()),
                event_refs=event_refs,
                counter_refs=counter_refs,
                dropped=dropped,
            )
            return response.status_code == 202

    def flush_now(self) -> bool:
        """Synchronously attempt one flush; intended for deterministic tests."""
        try:
            return self._flush_once()
        except Exception:  # noqa: BLE001
            if os.environ.get("TRUSTEDROUTER_TELEMETRY_STRICT") == "1":
                raise
            return False

    def _worker(self) -> None:
        stop = self._stop
        wake = self._wake
        try:
            while not stop.is_set():
                now = float(self._clock())
                with self._lock:
                    deadline = max(
                        self._next_flush_at,
                        self._paused_until,
                        self._backoff_until,
                    )
                    urgent = self._urgent_flush and now >= max(
                        self._paused_until, self._backoff_until
                    )
                    if urgent:
                        self._urgent_flush = False
                if not urgent and now < deadline:
                    wake.wait(timeout=max(0.0, deadline - now))
                    wake.clear()
                    continue
                self._flush_once()
                with self._lock:
                    self._next_flush_at = float(self._clock()) + self.flush_seconds
        except Exception:  # noqa: BLE001
            if os.environ.get("TRUSTEDROUTER_TELEMETRY_STRICT") == "1":
                raise

    def _close_http_client(self) -> None:
        with self._lock:
            client = self._http_client
            self._http_client = None
        if client is not None:
            try:
                client.close()
            except Exception:  # noqa: BLE001
                _logger.debug("trustedrouter telemetry client close failed", exc_info=True)

    def _final_flush(self, timeout: float) -> None:
        try:
            self._flush_once(timeout=timeout)
        except Exception:  # noqa: BLE001
            if os.environ.get("TRUSTEDROUTER_TELEMETRY_STRICT") == "1":
                raise
        finally:
            self._close_http_client()

    def close(self, timeout: float = 2.0) -> None:
        timeout = max(0.0, float(timeout))
        started = time.monotonic()
        with self._lock:
            if self._closed:
                return
            self._closed = True
            worker = self._thread
            self._stop.set()
            self._wake.set()
        final = threading.Thread(
            target=self._final_flush,
            args=(timeout,),
            name="trustedrouter-telemetry-close",
            daemon=True,
        )
        final.start()
        final.join(timeout=timeout)
        remaining = max(0.0, timeout - (time.monotonic() - started))
        if worker is not None and worker is not threading.current_thread():
            worker.join(timeout=remaining)


def _close_reporters() -> None:
    for reporter in list(_REPORTERS):
        reporter.close(2.0)


atexit.register(_close_reporters)


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
        # The contract (v1, section 3.2) caps `a` at 0..99 and the enclave drops
        # the whole header on an out-of-range value, so suppress it entirely
        # past the bound -- matching the sibling SDKs.
        if self._current_index > 99:
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
