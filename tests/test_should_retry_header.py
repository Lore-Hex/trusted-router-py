"""The gateway's x-should-retry verdict overrides our status heuristics.

A status code cannot say whether a provider already ran. A 502 from "could not
reach the provider" and a 502 from "the generation succeeded and then
settlement failed" are indistinguishable here, and only the second is
dangerous to re-send: the caller is not double-charged, but TrustedRouter pays
the upstream provider twice and the caller may get a different answer.

The gateway now labels the second kind. These tests prove we obey.
"""

from __future__ import annotations

import httpx
import pytest

from trustedrouter.client import (
    InternalError,
    TrustedRouter,
    _retry_after_seconds,
    _retryable,
    _should_retry_header,
)


def _client(handler) -> TrustedRouter:
    return TrustedRouter(
        api_key="sk-test",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        max_retries=3,
    )


def test_header_parsing_is_explicit_about_absence() -> None:
    assert _should_retry_header({}) is None
    assert _should_retry_header({"x-should-retry": "true"}) is True
    assert _should_retry_header({"x-should-retry": "FALSE"}) is False
    # Anything we do not understand must not be read as a verdict.
    assert _should_retry_header({"x-should-retry": "maybe"}) is None


def test_a_502_labelled_do_not_retry_is_not_retried_at_all() -> None:
    """The settlement-after-generation case the gateway now labels."""
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.host)
        return httpx.Response(
            502,
            json={"error": {"message": "settlement failed"}},
            headers={"x-should-retry": "false"},
        )

    with pytest.raises(InternalError):
        _client(handler).request("GET", "/models")

    assert len(seen) == 1, f"a labelled 502 was retried {len(seen)} times: {seen}"
    assert set(seen) == {"api.trustedrouter.com"}, f"and it moved domains: {seen}"


def test_an_unlabelled_502_still_moves_domains() -> None:
    """Absence of the header must leave existing behaviour untouched, or this
    change would quietly remove failover from every older gateway."""
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.host)
        if request.url.host == "api.trustedrouter.com":
            return httpx.Response(502, json={"error": "unavailable"})
        return httpx.Response(200, json={"ok": True})

    assert _client(handler).request("GET", "/models") == {"ok": True}
    assert "api.allyrouter.com" in seen, f"lost failover: {seen}"


def test_a_400_labelled_retry_is_retried() -> None:
    """The header overrides in both directions, as OpenAI's clients do: a
    status we would never retry becomes retryable when the server says so."""
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(
                400, json={"error": "transient"}, headers={"x-should-retry": "true"}
            )
        return httpx.Response(200, json={"ok": True})

    assert _client(handler).request("GET", "/models") == {"ok": True}
    assert calls["n"] == 2, "server said retry and we did not"


def test_retryable_without_headers_keeps_the_status_heuristics() -> None:
    assert _retryable(500) is True
    assert _retryable(429) is True
    assert _retryable(400) is False


def test_retry_after_ms_is_honored_and_beats_retry_after() -> None:
    assert _retry_after_seconds({"retry-after-ms": "250"}) == 0.25
    assert _retry_after_seconds({"retry-after": "2"}) == 2.0
    # Both present: the millisecond value is the precise one.
    assert _retry_after_seconds({"retry-after-ms": "500", "retry-after": "9"}) == 0.5
    # Junk in the precise header must fall through, not poison the backoff.
    assert _retry_after_seconds({"retry-after-ms": "soon", "retry-after": "3"}) == 3.0
