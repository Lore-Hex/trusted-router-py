"""The domain is a single point of failure above the whole deployment.

Three names resolve to the same attested enclaves, on separate DNS providers.
These tests prove a client actually reaches the second one when the first
stops answering — the machinery existed before this and could never engage,
because the candidate list had a single entry and every advance is guarded by
`base_index < len(base_urls) - 1`.
"""

from __future__ import annotations

import httpx
import pytest

from trustedrouter.client import (
    ALIAS_API_BASE_URLS,
    DEFAULT_API_BASE_URL,
    TrustedRouter,
    _inference_base_urls,
    _ordered_regions,
)


def test_the_default_candidate_list_has_more_than_one_entry() -> None:
    """A one-entry list makes every failover branch unreachable."""
    urls = _inference_base_urls(DEFAULT_API_BASE_URL)
    assert len(urls) > 1, "failover cannot engage with a single candidate"
    assert urls[0] == DEFAULT_API_BASE_URL.rstrip("/"), "primary must be tried first"
    for alias in ALIAS_API_BASE_URLS:
        assert alias.rstrip("/") in urls


def test_a_custom_base_url_is_never_redirected_to_a_public_alias() -> None:
    """A private deployment or test server must get exactly what was asked for.
    Silently sending that traffic to a public alias would be worse than
    failing."""
    assert _inference_base_urls("https://my.internal/v1") == ["https://my.internal/v1"]


def test_a_failed_health_race_still_leaves_the_aliases() -> None:
    """No region answering is precisely when the aliases matter; collapsing to
    one host there would remove failover at the worst moment."""
    assert len(_ordered_regions(DEFAULT_API_BASE_URL, None)) > 1


def _client_with_transport(handler) -> TrustedRouter:
    # No base_url: the default host is what activates the alias list, and it is
    # the configuration every real caller uses.
    return TrustedRouter(
        api_key="sk-test",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        max_retries=3,
    )


def test_a_dead_primary_domain_reaches_an_alias() -> None:
    """The real scenario: the primary domain does not resolve at all.

    A ConnectError is raised before any byte is written, so no server saw the
    request and moving to another domain cannot double-execute anything.
    """
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.host)
        if request.url.host == "api.trustedrouter.com":
            raise httpx.ConnectError("name resolution failed", request=request)
        return httpx.Response(200, json={"ok": True})

    client = _client_with_transport(handler)
    result = client.request("GET", "/models")

    assert result == {"ok": True}
    assert seen[0] == "api.trustedrouter.com", "primary must be attempted first"
    assert "api.allyrouter.com" in seen, f"never reached an alias: {seen}"


def test_a_503_from_the_primary_reaches_an_alias() -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.host)
        if request.url.host == "api.trustedrouter.com":
            return httpx.Response(503, json={"error": "unavailable"})
        return httpx.Response(200, json={"ok": True})

    client = _client_with_transport(handler)
    assert client.request("GET", "/models") == {"ok": True}
    assert "api.allyrouter.com" in seen, f"never reached an alias: {seen}"


def test_a_500_does_NOT_move_to_another_domain() -> None:
    """A 500 means a server received and processed the request. Inference is
    not idempotent, so retrying it on another domain risks charging twice.
    Failover is for connection failures and 502/503/504 only."""
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.host)
        return httpx.Response(500, json={"error": "boom"})

    client = _client_with_transport(handler)
    with pytest.raises(Exception):
        client.request("GET", "/models")

    assert set(seen) == {"api.trustedrouter.com"}, f"a 500 leaked to another domain: {seen}"
