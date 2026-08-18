"""Transport engine (L3): THE single retry/failover loop.

This module is the ONLY place in the entire codebase where a base-URL /
candidate index advances (via ``RetryController``, the sole mutator of
that index) and the ONLY module allowed to ``time.sleep`` /
``asyncio.sleep``. Four mechanical drivers wrap the sans-IO controller:
sync/async x buffered/stream-open — the async twins are the entire
remaining sync/async duplication in the SDK.

The engine never drains a success body (that is what lets streaming share
it) and never retries after the first surfaced body byte.

INVARIANTS enforced here (decision logic lives in ``trustedrouter._retry``;
each line names its enforcing test):

(1) A response that may move domains is always also retryable in place —
    the engine only moves inside a retry.
    tests/test_alias_domain_failover.py::test_a_503_from_the_primary_reaches_an_alias.
(2) 500 never moves domains.
    tests/test_alias_domain_failover.py::test_a_500_does_NOT_move_to_another_domain.
(3) Control-plane and custom-base calls run these same loops with a
    single-entry candidate list, so failover is structurally impossible.
    tests/test_features.py::test_control_request_retries_without_regional_failover.
(4) x-should-retry overrides the predicates in both directions.
    tests/test_should_retry_header.py::test_a_502_labelled_do_not_retry_is_not_retried_at_all,
    ::test_a_400_labelled_retry_is_retried.
(5) The idempotency key is baked into the request builder before the loop
    and replayed verbatim on every attempt and domain.
    tests/test_features.py::test_sync_responses_stream_fails_over_with_same_idempotency_key.
(6) A transport error after the response opened propagates — the stream is
    never reconnected mid-body.
    tests/test_retry_controller.py::test_transport_error_after_stream_opened_always_gives_up.
(7) regional_failover=False still retries, in place.
    tests/test_alias_domain_failover.py::test_regional_failover_false_keeps_every_attempt_on_one_host.
(8) Transport-error advances are gated on regional_failover on every
    request mode, streaming included.
    tests/test_alias_domain_failover.py::test_sync_stream_regional_failover_false_pins_host_on_transport_error,
    ::test_async_stream_regional_failover_false_pins_host_on_transport_error.
(9) Exhausted retryable STATUS returns the final response for the caller
    to classify; IO exhaustion raises; stream-open raising uses the typed
    stream helpers.
    tests/test_features.py::test_request_retries_on_5xx_then_gives_up,
    ::test_request_transport_error_fails_over_then_raises,
    tests/test_client.py::test_chat_completions_chunk_stream_raises_on_error_status.
(10) See ``trustedrouter._retry._regional_failoverable`` — the documented
    surviving mutant is consulted from these loops and only these loops.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import AsyncIterator, Callable, Iterator
from typing import Any, TypeVar

import httpx

from trustedrouter._errors import (
    _araise_for_stream_response,
    _raise_for_stream_response,
    _transport_retry_error,
)
from trustedrouter._requests import _RESERVED_MARKER, _strip_reserved_headers
from trustedrouter._retry import RetryController, _retryable
from trustedrouter._telemetry import RequestRecorder

T = TypeVar("T")


def _apply_reserved_headers(
    request_kwargs: dict[str, Any], recorder: RequestRecorder | None
) -> None:
    """Enforce the x-tr-client reservation for one attempt.

    The strip runs on EVERY path, recorder or not -- opt-out, custom base and
    control-plane calls included -- so a value the SDK was handed never rides
    the request; the header is then set only from an active recorder.

    Also stamps ``extensions[_RESERVED_MARKER]`` with the value this attempt
    must end up with, which is what lets the terminal hook installed on the
    client re-assert the reservation after httpx has merged client default
    headers and run the caller's ``Auth`` and request hooks. Marking per
    attempt (not per request) keeps the value correct across retries, where
    the recorder's header changes every time. See ``_requests.RESERVED_HEADERS``
    for the layers and the remaining boundary.
    """
    headers = request_kwargs["headers"]
    _strip_reserved_headers(headers)
    value = recorder.header_value() if recorder is not None else None
    if value is not None:
        headers["x-tr-client"] = value
    extensions = dict(request_kwargs.get("extensions") or {})
    extensions[_RESERVED_MARKER] = value
    request_kwargs["extensions"] = extensions


def request_with_retry(
    client: httpx.Client,
    controller: RetryController,
    method: str,
    path: str,
    kwargs: dict[str, Any],
    *,
    recorder: RequestRecorder | None = None,
) -> httpx.Response:
    """Sync buffered driver.

    Re-reads the candidate pool through the controller on every attempt
    (preserving the lazy affinity probe and swapped-client detection —
    tests/test_client.py::test_sync_client_pins_fastest_healthy_region_once)
    and returns the FINAL response for the caller to ``_json_or_raise``:
    the last response is surfaced even when retryable, with no sleep, and
    ``max_retries=0`` makes exactly one attempt
    (tests/test_features.py::test_max_retries_zero_disables_retry_loop_entirely).
    """
    kwargs = dict(kwargs)
    attempt_headers = dict(kwargs.get("headers") or {})
    kwargs["headers"] = attempt_headers
    exhausted = False
    try:
        while True:
            base_url = controller.current_base_url()
            url = f"{base_url}/{path.lstrip('/')}"
            if recorder is not None:
                recorder.begin_attempt(base_url)
            _apply_reserved_headers(kwargs, recorder)
            try:
                response = client.request(method, url, **kwargs)
            except httpx.TransportError as exc:
                if recorder is not None:
                    recorder.on_transport_error(
                        exc, response_opened=False, body_started=False
                    )
                decision = controller.on_transport_error(response_opened=False)
                if recorder is not None and decision.moved_host:
                    recorder.on_moved()
                if decision.action != "retry":
                    if recorder is not None:
                        exhausted = controller.attempt > 0
                    raise _transport_retry_error(exc) from exc
                time.sleep(decision.sleep_seconds)
                continue
            if recorder is not None:
                recorder.on_response(response.status_code, response.headers)
            decision = controller.on_response(response.status_code, response.headers)
            if recorder is not None and decision.moved_host:
                recorder.on_moved()
            if decision.action != "retry":
                if recorder is not None:
                    exhausted = controller.attempt > 0 and _retryable(
                        response.status_code, response.headers
                    )
                return response
            time.sleep(decision.sleep_seconds)
    except KeyboardInterrupt:
        if recorder is not None:
            recorder.on_aborted()
        raise
    finally:
        if recorder is not None:
            recorder.finish(exhausted=exhausted)


async def arequest_with_retry(
    client: httpx.AsyncClient,
    controller: RetryController,
    method: str,
    path: str,
    kwargs: dict[str, Any],
    *,
    recorder: RequestRecorder | None = None,
) -> httpx.Response:
    """Async twin of :func:`request_with_retry`."""
    kwargs = dict(kwargs)
    attempt_headers = dict(kwargs.get("headers") or {})
    kwargs["headers"] = attempt_headers
    exhausted = False
    try:
        while True:
            base_url = controller.current_base_url()
            url = f"{base_url}/{path.lstrip('/')}"
            if recorder is not None:
                recorder.begin_attempt(base_url)
            _apply_reserved_headers(kwargs, recorder)
            try:
                response = await client.request(method, url, **kwargs)
            except httpx.TransportError as exc:
                if recorder is not None:
                    recorder.on_transport_error(
                        exc, response_opened=False, body_started=False
                    )
                decision = controller.on_transport_error(response_opened=False)
                if recorder is not None and decision.moved_host:
                    recorder.on_moved()
                if decision.action != "retry":
                    if recorder is not None:
                        exhausted = controller.attempt > 0
                    raise _transport_retry_error(exc) from exc
                await asyncio.sleep(decision.sleep_seconds)
                continue
            if recorder is not None:
                recorder.on_response(response.status_code, response.headers)
            decision = controller.on_response(response.status_code, response.headers)
            if recorder is not None and decision.moved_host:
                recorder.on_moved()
            if decision.action != "retry":
                if recorder is not None:
                    exhausted = controller.attempt > 0 and _retryable(
                        response.status_code, response.headers
                    )
                return response
            await asyncio.sleep(decision.sleep_seconds)
    except (asyncio.CancelledError, KeyboardInterrupt):
        if recorder is not None:
            recorder.on_aborted()
        raise
    finally:
        if recorder is not None:
            recorder.finish(exhausted=exhausted)


def stream_events(
    client: httpx.Client,
    controller: RetryController,
    build_request: Callable[[str], dict[str, Any]],
    iter_body: Callable[[httpx.Response], Iterator[T]],
    *,
    recorder: RequestRecorder | None = None,
) -> Iterator[T]:
    """Sync stream-open driver: a generator, so opening stays lazy.

    Error statuses at stream open are drained (`response.read()`) before
    the controller decides, so a retry never leaks an open connection and
    a give-up can surface the body detail. The body iteration happens
    INSIDE the try so a mid-body ``httpx.TransportError`` reaches the
    except with ``response_opened=True`` and re-raises as
    ``_transport_retry_error`` — never a reconnect (invariant 6).
    """
    exhausted = False
    try:
        while True:
            base_url = controller.current_base_url()
            if recorder is not None:
                recorder.begin_attempt(base_url)
            req = dict(build_request(base_url))
            req["headers"] = dict(req.get("headers") or {})
            _apply_reserved_headers(req, recorder)
            response_opened = False
            body_started = False
            try:
                with client.stream(**req) as response:
                    response_opened = True
                    if recorder is not None:
                        recorder.on_response(response.status_code, response.headers)
                    if response.is_error:
                        response.read()
                        decision = controller.on_response(response.status_code, response.headers)
                        if recorder is not None and decision.moved_host:
                            recorder.on_moved()
                        if decision.action == "retry":
                            time.sleep(decision.sleep_seconds)
                            continue
                        if recorder is not None:
                            exhausted = controller.attempt > 0 and _retryable(
                                response.status_code, response.headers
                            )
                        _raise_for_stream_response(response)
                    for item in iter_body(response):
                        if not body_started:
                            body_started = True
                            if recorder is not None:
                                recorder.on_first_event()
                        yield item
                    return
            except httpx.TransportError as exc:
                if recorder is not None:
                    recorder.on_transport_error(
                        exc,
                        response_opened=response_opened,
                        body_started=body_started,
                    )
                decision = controller.on_transport_error(response_opened=response_opened)
                if recorder is not None and decision.moved_host:
                    recorder.on_moved()
                if decision.action != "retry":
                    if recorder is not None:
                        exhausted = not response_opened and controller.attempt > 0
                    raise _transport_retry_error(exc) from exc
                time.sleep(decision.sleep_seconds)
    except (GeneratorExit, KeyboardInterrupt):
        if recorder is not None:
            recorder.on_aborted()
        raise
    finally:
        if recorder is not None:
            recorder.finish(exhausted=exhausted)


async def astream_events(
    client: httpx.AsyncClient,
    controller: RetryController,
    build_request: Callable[[str], dict[str, Any]],
    iter_body: Callable[[httpx.Response], AsyncIterator[T]],
    *,
    recorder: RequestRecorder | None = None,
) -> AsyncIterator[T]:
    """Async twin of :func:`stream_events`."""
    exhausted = False
    try:
        while True:
            base_url = controller.current_base_url()
            if recorder is not None:
                recorder.begin_attempt(base_url)
            req = dict(build_request(base_url))
            req["headers"] = dict(req.get("headers") or {})
            _apply_reserved_headers(req, recorder)
            response_opened = False
            body_started = False
            try:
                async with client.stream(**req) as response:
                    response_opened = True
                    if recorder is not None:
                        recorder.on_response(response.status_code, response.headers)
                    if response.is_error:
                        await response.aread()
                        decision = controller.on_response(response.status_code, response.headers)
                        if recorder is not None and decision.moved_host:
                            recorder.on_moved()
                        if decision.action == "retry":
                            await asyncio.sleep(decision.sleep_seconds)
                            continue
                        if recorder is not None:
                            exhausted = controller.attempt > 0 and _retryable(
                                response.status_code, response.headers
                            )
                        await _araise_for_stream_response(response)
                    async for item in iter_body(response):
                        if not body_started:
                            body_started = True
                            if recorder is not None:
                                recorder.on_first_event()
                        yield item
                    return
            except httpx.TransportError as exc:
                if recorder is not None:
                    recorder.on_transport_error(
                        exc,
                        response_opened=response_opened,
                        body_started=body_started,
                    )
                decision = controller.on_transport_error(response_opened=response_opened)
                if recorder is not None and decision.moved_host:
                    recorder.on_moved()
                if decision.action != "retry":
                    if recorder is not None:
                        exhausted = not response_opened and controller.attempt > 0
                    raise _transport_retry_error(exc) from exc
                await asyncio.sleep(decision.sleep_seconds)
    except (GeneratorExit, asyncio.CancelledError, KeyboardInterrupt):
        if recorder is not None:
            recorder.on_aborted()
        raise
    finally:
        if recorder is not None:
            recorder.finish(exhausted=exhausted)
