"""Policy kernel (L1): pure retry/failover decision logic. No I/O, no clock.

Everything in this module is a decision function over (status, headers,
attempt, candidate list); the only place those decisions are *acted on* —
the only place a request is sent or a sleep happens — is the transport
engine in ``trustedrouter._transport``. ``RetryController`` below is the
ONLY code anywhere in the SDK that increments a candidate ``base_index``
or an ``attempt`` counter.

INVARIANTS (each line names its enforcing test):

(1) Failover set {502, 503, 504} is a strict subset of the retry set
    {429, >=500, verdict-true} — a response that may move domains is always
    also retryable in place.
    tests/test_alias_domain_failover.py::test_a_503_from_the_primary_reaches_an_alias,
    tests/test_should_retry_header.py::test_an_unlabelled_502_still_moves_domains.
(2) 500 NEVER moves domains — a server processed the non-idempotent
    inference; re-sending elsewhere risks a second generation.
    tests/test_alias_domain_failover.py::test_a_500_does_NOT_move_to_another_domain
    and ::test_async_500_does_not_move_to_another_domain.
(3) Aliases exist only for the default host; the control plane always has
    exactly one candidate (list length is the gate, not a second flag);
    custom bases are never redirected.
    tests/test_alias_domain_failover.py::test_a_custom_base_url_is_never_redirected_to_a_public_alias,
    tests/test_features.py::test_control_request_retries_without_regional_failover.
(4) x-should-retry overrides both predicates in both directions: explicit
    false forbids retry AND failover; explicit true forces retry;
    absent/unparseable keeps the status heuristics.
    tests/test_should_retry_header.py::test_a_502_labelled_do_not_retry_is_not_retried_at_all,
    ::test_a_400_labelled_retry_is_retried,
    ::test_retryable_without_headers_keeps_the_status_heuristics.
(5) Idempotency key minted once per logical call before the loop and
    re-sent verbatim across every attempt and domain move — the caller is
    never double-charged (idempotent auth + exactly-once settlement).
    tests/test_client.py::test_async_client_pins_fastest_region_and_keeps_idempotency_on_failover,
    tests/test_features.py::test_chat_stream_fails_over_before_returning_chunks.
(6) Retries happen only before any body bytes are surfaced; a broken open
    stream propagates, never reconnects.
    tests/test_retry_controller.py::test_transport_error_after_stream_opened_always_gives_up.
(7) The regional_failover flag governs WHERE, never WHETHER — a pinned
    client still retries in place.
    tests/test_alias_domain_failover.py::test_regional_failover_false_keeps_every_attempt_on_one_host
    and ::test_async_regional_failover_false_keeps_every_attempt_on_one_host.
(8) Transport errors (no server saw the request) may always move hosts
    within the flag gating; HTTP moves additionally require a failoverable
    status.
    tests/test_alias_domain_failover.py::test_a_dead_primary_domain_reaches_an_alias,
    ::test_regional_failover_false_pins_the_host_on_a_transport_error,
    ::test_sync_stream_regional_failover_false_pins_host_on_transport_error,
    ::test_async_stream_regional_failover_false_pins_host_on_transport_error.
(9) Terminal asymmetries are contract and survive verbatim: an exhausted
    retryable STATUS returns the final response for the caller to classify,
    while IO exhaustion THROWS; buffered vs stream-open raising differs.
    tests/test_features.py::test_request_retries_on_5xx_then_gives_up (returns),
    ::test_request_transport_error_fails_over_then_raises (throws),
    tests/test_client.py::test_chat_completions_chunk_stream_raises_on_error_status.
(10) The deliberately-unreachable verdict-false guard inside
    ``_regional_failoverable`` is a documented surviving mutant — moved
    verbatim, never "fixed", never tested.
"""

from __future__ import annotations

import math
import random
import secrets
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Literal


def _should_retry_header(headers: Mapping[str, str]) -> bool | None:
    """The gateway's explicit verdict, which overrides everything below.

    A status code cannot say whether a provider already ran. A 502 from "could
    not reach the provider" and a 502 from "the generation succeeded and then
    settlement failed" are indistinguishable to us, and only the second one is
    dangerous to re-send. The gateway knows which it is and says so here.

    Same header OpenAI's clients honor. `None` means the server did not say,
    and the status heuristics below apply.
    """
    raw = headers.get("x-should-retry") or headers.get("X-Should-Retry")
    if raw is None:
        return None
    value = raw.strip().lower()
    if value == "true":
        return True
    if value == "false":
        return False
    return None


def _retryable(status_code: int, headers: Mapping[str, str] | None = None) -> bool:
    """Which responses the SDK retries by default. 429 + 5xx are safe
    to retry idempotently; the gateway is responsible for 5xx-on-write
    being safe (its writes are idempotent or the response is 4xx)."""
    if headers is not None:
        verdict = _should_retry_header(headers)
        if verdict is not None:
            return verdict
    return status_code == 429 or status_code >= 500


def _regional_failoverable(
    status_code: int, headers: Mapping[str, str] | None = None
) -> bool:
    """Which responses may move to a DIFFERENT domain.

    An explicit `x-should-retry: false` forbids it outright: that is the
    gateway telling us a provider already ran, which is precisely the case
    where re-sending anywhere costs a second generation.

    That check is UNREACHABLE today and has no test, deliberately: every caller
    consults `_retryable` first, which already returns False for a labelled
    response, so we never get here. It is kept so that widening the retry set
    later cannot silently reintroduce domain movement on a spent response —
    the failure this whole header exists to prevent. Mutation-testing it
    correctly reports it as surviving.
    """
    if headers is not None and _should_retry_header(headers) is False:
        return False
    return status_code in {502, 503, 504}


MAX_RETRY_AFTER_SECONDS = 60.0
"""Ceiling on a server-supplied Retry-After floor.

Retry-After arrives from whatever answered the socket — the gateway, a proxy
in front of it, or an alias domain — so it is untrusted input, and it was
being applied as an *uncapped* floor on the sleep. `Retry-After: inf` parsed
to infinity: the async client never resumed, and the sync client raised a bare
OverflowError out of time.sleep that is not one of this SDK's error types.
Finite-but-absurd values were worse than they look, because they are accepted
silently: `Retry-After: 100000` parked every caller for 27.8 hours per attempt.

60 s is above any hint a healthy gateway sends and far below the point where a
caller would rather have the error. A server asking for longer still gets its
retries; they just arrive sooner, and `max_retries` bounds the total.
"""


def _bounded_retry_after(seconds: float) -> float | None:
    """Clamp a parsed hint into [0, MAX_RETRY_AFTER_SECONDS], or reject it.

    Returns None for anything not a usable delay — NaN, ±inf, negatives — so
    that the caller falls through to plain jittered backoff. Both SDKs reject
    exactly this set, so the two accept the same header language.
    """
    if not math.isfinite(seconds) or seconds < 0:
        return None
    return min(seconds, MAX_RETRY_AFTER_SECONDS)


def _retry_after_seconds(headers: Mapping[str, str]) -> float | None:
    """Parse Retry-After. Per RFC 7231 it can be either an integer number
    of seconds OR an HTTP-date; we only honor the integer form because
    the gateway only emits that and the date form is rarely useful for
    short retries.

    The result is always None or a finite value in [0, MAX_RETRY_AFTER_SECONDS]
    — see tests/test_retry_after_bounds.py, which states that as a property
    over arbitrary header bytes.
    """
    # retry-after-ms wins when both are present: it is the more precise of the
    # two, and a server that bothers to send it means the sub-second value.
    raw_ms = headers.get("retry-after-ms") or headers.get("Retry-After-Ms")
    if raw_ms:
        try:
            millis = float(raw_ms.strip())
        except (TypeError, ValueError):
            millis = -1.0
        bounded = _bounded_retry_after(millis / 1000.0) if math.isfinite(millis) else None
        if bounded is not None:
            return bounded
    raw = headers.get("retry-after") or headers.get("Retry-After")
    if not raw:
        return None
    try:
        return _bounded_retry_after(float(raw.strip()))
    except ValueError:
        return None


def _retry_sleep(attempt: int, *, retry_after: float | None) -> float:
    """Exponential backoff with full jitter, capped at 30 s. If the
    server gave us a Retry-After hint, honor that as the floor — bounded,
    so a hostile or broken hint cannot park or hang the caller."""
    # 0.5 * 2**6 == 32 already exceeds the 30 s ceiling, so every attempt from
    # 6 up is exactly 30. Special-casing that instead of computing the power
    # keeps a caller-chosen max_retries above ~1024 from raising OverflowError
    # out of 2**attempt (a Python int too large to convert to float).
    base = 0.5 * (2**attempt) if attempt < 6 else 30.0
    delay = random.uniform(0, base)  # noqa: S311  not crypto
    if retry_after is not None:
        delay = max(delay, retry_after)
    # Re-clamp rather than trusting the caller: _retry_sleep is monkeypatched
    # and called directly by downstream code, so the bound belongs on the value
    # that actually reaches time.sleep/asyncio.sleep, not only on the parser.
    return min(delay, max(30.0, MAX_RETRY_AFTER_SECONDS))


def _new_idempotency_key() -> str:
    """Generate a stable-at-call-site key for retryable inference requests."""
    return f"tr-req-{secrets.token_urlsafe(24)}"


def _sleep_seconds(attempt: int, retry_after: float | None) -> float:
    """Compute a backoff duration through the compat module's seam.

    ``trustedrouter.client._retry_sleep`` is the historical name tests and
    downstream code monkeypatch to control backoff. Binding ``_retry_sleep``
    directly here would silently disconnect those patches, so the decision
    kernel resolves the function through the compat module at call time.
    The import is deferred to avoid a cycle (client.py re-exports us).
    """
    from trustedrouter import client as _compat

    sleep_fn = getattr(_compat, "_retry_sleep", _retry_sleep)
    return sleep_fn(attempt, retry_after=retry_after)


@dataclass(frozen=True)
class Decision:
    """The kernel's canonical verdict for one observed attempt outcome.

    ``RETRY`` means the transport engine should sleep ``sleep_seconds`` and
    try again (the controller has already advanced its own attempt counter,
    and the candidate index when a domain move is warranted). ``GIVE_UP``
    means the outcome is terminal: the engine returns the final response for
    the caller to classify, or raises for IO exhaustion (invariant 9).
    """

    action: Literal["retry", "give_up"]
    sleep_seconds: float = 0.0
    moved_host: bool = False


_RETRY: Literal["retry"] = "retry"
_GIVE_UP: Literal["give_up"] = "give_up"


class RetryController:
    """Sans-IO retry/failover state machine for ONE logical request.

    Constructed per logical call with a candidate provider (re-read on every
    consultation so lazy regional-affinity resolution and swapped-client
    detection keep working), the retry budget, and the regional_failover
    flag. This class is the only code in the SDK that increments
    ``base_index`` or ``attempt``; the transport engine is the only code
    that sleeps on its decisions.
    """

    def __init__(
        self,
        base_urls: Callable[[], Sequence[str]],
        *,
        max_retries: int,
        regional_failover: bool,
    ) -> None:
        self._base_urls = base_urls
        self._max_retries = max_retries
        self._regional_failover = regional_failover
        self._attempt = 0
        self._base_index = 0

    @property
    def attempt(self) -> int:
        return self._attempt

    @property
    def base_index(self) -> int:
        return self._base_index

    def current_base_url(self) -> str:
        """The base URL for the upcoming attempt, re-reading the provider."""
        return self._base_urls()[self._base_index]

    def on_response(self, status_code: int, headers: Mapping[str, str]) -> Decision:
        """Decide after an HTTP response arrived (no body surfaced yet).

        Give up when the budget is exhausted or the response is not
        retryable — the caller classifies the final response (invariant 9).
        Otherwise advance the candidate index iff regional_failover is on,
        the status is failoverable, and another candidate exists; sleep is
        jittered backoff floored by any Retry-After hint.
        """
        if self._attempt >= self._max_retries or not _retryable(status_code, headers):
            return Decision(_GIVE_UP)
        moved_host = False
        if (
            self._regional_failover
            and _regional_failoverable(status_code, headers)
            and self._base_index < len(self._base_urls()) - 1
        ):
            self._base_index += 1
            moved_host = True
        sleep = _sleep_seconds(self._attempt, _retry_after_seconds(headers))
        self._attempt += 1
        return Decision(_RETRY, sleep, moved_host)

    def on_transport_error(self, *, response_opened: bool) -> Decision:
        """Decide after the transport failed.

        A transport error after the response opened means body bytes may
        already have been surfaced — never reconnect (invariant 6). Before
        that, no server saw a byte of the request, so moving hosts is always
        safe — but only when the caller allowed it (invariant 7/8): the
        advance is gated on regional_failover, on every request mode.
        """
        if response_opened or self._attempt >= self._max_retries:
            return Decision(_GIVE_UP)
        moved_host = False
        if self._regional_failover and self._base_index < len(self._base_urls()) - 1:
            self._base_index += 1
            moved_host = True
        sleep = _sleep_seconds(self._attempt, None)
        self._attempt += 1
        return Decision(_RETRY, sleep, moved_host)
