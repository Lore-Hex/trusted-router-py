"""Property tests for the Retry-After bound.

Retry-After arrives from whatever answered the socket — the gateway, a proxy,
an alias domain — so it is untrusted input, and it was applied as an *uncapped*
floor on the backoff sleep. The law:

    for every attempt a and every header map H over arbitrary strings,
        _retry_after_seconds(H) is None, or finite and in [0, MAX_RETRY_AFTER_SECONDS]
        _retry_sleep(a, ...)     is finite and in [0, max(30, MAX_RETRY_AFTER_SECONDS)]

Before the bound, all three of these were reachable from one header:

    Retry-After: inf     -> sleep = inf. asyncio.sleep(inf) never resumes, so the
                            async client hangs; time.sleep(inf) raises a bare
                            OverflowError that is not one of this SDK's error types.
    Retry-After: 1e300   -> accepted silently, sleep = 1e300.
    Retry-After: 100000  -> accepted silently, 27.8 hours per attempt.

The example suite missed all of it because its only cap test
(test_features.py::test_retry_sleep_caps_at_30_seconds) passes retry_after=None,
so the floor path — the one without a cap — was never exercised.

The acceptance-set test is the cross-SDK half: trusted-router-js rejects the
same header language, and a divergence there means the two SDKs behave
differently on identical network weather.
"""

from __future__ import annotations

import math

from hypothesis import assume, given, settings
from hypothesis import strategies as st

from trustedrouter._retry import (
    MAX_RETRY_AFTER_SECONDS,
    _bounded_retry_after,
    _retry_after_seconds,
    _retry_sleep,
)

SLEEP_CEILING = max(30.0, MAX_RETRY_AFTER_SECONDS)

# The shapes a real header can take, weighted toward the ones that broke it.
header_values = st.one_of(
    st.text(max_size=24),
    st.sampled_from(
        [
            "inf",
            "-inf",
            "Infinity",
            "-Infinity",
            "nan",
            "NaN",
            "1e300",
            "1e309",
            "100000",
            "-5",
            "0",
            "0.001",
            "  30  ",
            "1_000",
            "0x10",
            "",
            "   ",
            "30s",
            "Wed, 21 Oct 2015 07:28:00 GMT",
        ]
    ),
    st.floats(allow_nan=True, allow_infinity=True).map(repr),
    st.integers(min_value=-(10**12), max_value=10**12).map(str),
)

header_names = st.sampled_from(
    ["retry-after", "Retry-After", "retry-after-ms", "Retry-After-Ms"]
)

headers = st.dictionaries(header_names, header_values, max_size=4)


@given(h=headers)
@settings(max_examples=1000)
def test_parsed_hint_is_none_or_finite_and_bounded(h: dict[str, str]) -> None:
    """The parser never yields a value that could park or hang a caller."""
    parsed = _retry_after_seconds(h)
    if parsed is None:
        return
    assert math.isfinite(parsed), f"non-finite hint {parsed!r} from {h!r}"
    assert 0.0 <= parsed <= MAX_RETRY_AFTER_SECONDS, f"unbounded hint {parsed!r} from {h!r}"


@given(h=headers, attempt=st.integers(min_value=0, max_value=64))
@settings(max_examples=1000)
def test_sleep_is_always_finite_and_bounded(h: dict[str, str], attempt: int) -> None:
    """The value that actually reaches time.sleep/asyncio.sleep is bounded.

    Quantified over the attempt counter too: the jitter base is exponential in
    it, so a large attempt is its own overflow path independent of the header.
    """
    delay = _retry_sleep(attempt, retry_after=_retry_after_seconds(h))
    assert math.isfinite(delay), f"non-finite sleep {delay!r} from {h!r}"
    assert 0.0 <= delay <= SLEEP_CEILING, f"unbounded sleep {delay!r} from {h!r}"


@given(retry_after=st.floats(allow_nan=True, allow_infinity=True))
@settings(max_examples=500)
def test_sleep_bounds_a_hint_handed_to_it_directly(retry_after: float) -> None:
    """_retry_sleep is a documented monkeypatch seam and is called directly by
    downstream code, so it re-clamps rather than trusting the parser."""
    delay = _retry_sleep(0, retry_after=retry_after)
    assert math.isfinite(delay)
    assert 0.0 <= delay <= SLEEP_CEILING


@given(seconds=st.floats(allow_nan=True, allow_infinity=True))
def test_bounded_retry_after_rejects_exactly_the_unusable_values(seconds: float) -> None:
    """Rejection is exactly {NaN, ±inf, negatives} — the set trusted-router-js
    also rejects. Anything else is clamped, never dropped."""
    result = _bounded_retry_after(seconds)
    if not math.isfinite(seconds) or seconds < 0:
        assert result is None
    else:
        assert result == min(seconds, MAX_RETRY_AFTER_SECONDS)


@given(seconds=st.floats(min_value=0.0, max_value=MAX_RETRY_AFTER_SECONDS, allow_nan=False))
def test_hints_within_the_bound_are_honoured_exactly(seconds: float) -> None:
    """The bound must not disturb the values it was not aimed at: a server
    asking for a delay it is entitled to still gets exactly that delay."""
    assert _bounded_retry_after(seconds) == seconds
    assert _retry_sleep(0, retry_after=seconds) >= seconds


@given(millis=st.integers(min_value=0, max_value=10**15))
def test_millisecond_header_wins_and_is_bounded(millis: int) -> None:
    parsed = _retry_after_seconds({"retry-after-ms": str(millis), "retry-after": "1"})
    assert parsed is not None
    assert parsed == min(millis / 1000.0, MAX_RETRY_AFTER_SECONDS)


@given(value=st.sampled_from(["inf", "-inf", "nan", "NaN", "Infinity"]))
def test_unusable_millisecond_header_falls_through_to_seconds(value: str) -> None:
    """A junk retry-after-ms must not shadow a usable retry-after; the original
    fall-through behaviour for negatives is preserved for non-finites too."""
    assert _retry_after_seconds({"retry-after-ms": value, "retry-after": "7"}) == 7.0


@given(h=headers)
def test_parsing_is_deterministic(h: dict[str, str]) -> None:
    assert _retry_after_seconds(h) == _retry_after_seconds(dict(h))


def test_the_three_headers_that_used_to_hang_or_park_a_caller() -> None:
    """Regression pins for the concrete values, alongside the general property."""
    assert _retry_after_seconds({"retry-after": "inf"}) is None
    assert _retry_after_seconds({"retry-after-ms": "inf"}) is None
    assert _retry_after_seconds({"retry-after": "1e300"}) == MAX_RETRY_AFTER_SECONDS
    assert _retry_after_seconds({"retry-after": "100000"}) == MAX_RETRY_AFTER_SECONDS

    for header in ({"retry-after": "inf"}, {"retry-after": "1e300"}, {"retry-after": "100000"}):
        assert _retry_sleep(0, retry_after=_retry_after_seconds(header)) <= SLEEP_CEILING


@given(attempt=st.integers(min_value=0, max_value=10_000))
def test_jitter_base_alone_never_overflows(attempt: int) -> None:
    """0.5 * 2**attempt overflows float at attempt ~1024; the min() against 30
    must be evaluated in a way that survives it."""
    assume(attempt >= 0)
    delay = _retry_sleep(attempt, retry_after=None)
    assert math.isfinite(delay)
    assert 0.0 <= delay <= SLEEP_CEILING
