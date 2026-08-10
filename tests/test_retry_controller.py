"""Unit tests for the sans-IO retry controller (the L1 policy kernel).

The controller is pure: it never sends a request and never sleeps, so its
whole decision table is testable without a mock transport. These tests pin
the semantics the four transport drivers rely on: final-attempt behavior in
both modes, max_retries=0 making exactly one attempt, and the per-attempt
re-read of the candidate provider.
"""

from __future__ import annotations

from trustedrouter._retry import RetryController


def _controller(
    urls: list[str],
    *,
    max_retries: int = 2,
    regional_failover: bool = True,
) -> RetryController:
    return RetryController(
        lambda: urls,
        max_retries=max_retries,
        regional_failover=regional_failover,
    )


# ---- final-attempt semantics, both modes ---------------------------------


def test_final_attempt_gives_up_on_retryable_status_without_sleep() -> None:
    """The last response is surfaced to the caller even when retryable —
    and a give-up carries no sleep (the engine returns immediately)."""
    controller = _controller(["https://a/v1"], max_retries=1)
    first = controller.on_response(503, {})
    assert first.action == "retry"
    final = controller.on_response(503, {})
    assert final.action == "give_up"
    assert final.sleep_seconds == 0.0


def test_final_attempt_gives_up_on_transport_error() -> None:
    controller = _controller(["https://a/v1", "https://b/v1"], max_retries=1)
    assert controller.on_transport_error(response_opened=False).action == "retry"
    assert controller.on_transport_error(response_opened=False).action == "give_up"


def test_transport_error_after_stream_opened_always_gives_up() -> None:
    """Invariant 6: once the response opened, body bytes may have been
    surfaced — a broken stream propagates, never reconnects, no matter how
    much retry budget remains."""
    controller = _controller(["https://a/v1", "https://b/v1"], max_retries=5)
    assert controller.on_transport_error(response_opened=True).action == "give_up"


# ---- max_retries=0 --------------------------------------------------------


def test_max_retries_zero_makes_exactly_one_attempt_in_both_modes() -> None:
    controller = _controller(["https://a/v1", "https://b/v1"], max_retries=0)
    assert controller.on_response(503, {}).action == "give_up"
    assert controller.on_transport_error(response_opened=False).action == "give_up"


# ---- per-attempt provider re-read -----------------------------------------


def test_candidate_provider_is_reread_on_every_consultation() -> None:
    """The provider is consulted per attempt, not snapshotted at
    construction — this is what keeps the lazy affinity probe and the
    swapped-client detection working through the pool."""
    reads = {"count": 0}
    urls = ["https://a/v1"]

    def provider() -> list[str]:
        reads["count"] += 1
        return urls

    controller = RetryController(provider, max_retries=3, regional_failover=True)
    assert controller.current_base_url() == "https://a/v1"
    urls[:] = ["https://swapped/v1", "https://b/v1"]
    assert controller.current_base_url() == "https://swapped/v1"
    assert reads["count"] == 2
    # Decisions consult the provider too (for the advance guard).
    controller.on_response(503, {})
    assert reads["count"] == 3


# ---- advance gating --------------------------------------------------------


def test_transport_error_advance_is_gated_on_regional_failover() -> None:
    urls = ["https://a/v1", "https://b/v1"]
    moving = _controller(urls, max_retries=3, regional_failover=True)
    moving.on_transport_error(response_opened=False)
    assert moving.current_base_url() == "https://b/v1"

    pinned = _controller(urls, max_retries=3, regional_failover=False)
    pinned.on_transport_error(response_opened=False)
    assert pinned.current_base_url() == "https://a/v1"


def test_500_retries_in_place_but_gateway_statuses_move() -> None:
    urls = ["https://a/v1", "https://b/v1"]
    controller = _controller(urls, max_retries=3)
    controller.on_response(500, {})
    assert controller.current_base_url() == "https://a/v1"
    controller.on_response(502, {})
    assert controller.current_base_url() == "https://b/v1"


def test_labelled_do_not_retry_gives_up_even_on_502() -> None:
    controller = _controller(["https://a/v1", "https://b/v1"], max_retries=3)
    decision = controller.on_response(502, {"x-should-retry": "false"})
    assert decision.action == "give_up"
    assert controller.current_base_url() == "https://a/v1"


def test_single_candidate_list_never_advances() -> None:
    """Invariant 3: the control plane and custom bases pass a single-entry
    list, so the advance guard makes failover structurally impossible."""
    controller = _controller(["https://only/v1"], max_retries=3)
    controller.on_response(503, {})
    controller.on_transport_error(response_opened=False)
    assert controller.current_base_url() == "https://only/v1"
