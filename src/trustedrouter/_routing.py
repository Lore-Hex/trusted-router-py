"""Plane router / candidate set (L2).

Builds the ordered base-URL candidate list once per logical call.
Inference plane: primary first, alias domains appended ONLY when the
configured base equals the default host. Control plane and absolute
fetches use a single-entry list, so failover is structurally impossible —
the list length is the gate, not a second flag. The regional-affinity
health race lives here as the candidate provider and keeps its lazy
once-only semantics.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import threading
import time
from collections.abc import Callable

import httpx

from trustedrouter._constants import (
    ALIAS_API_BASE_URLS,
    DEFAULT_API_BASE_URL,
    REGION_BASE_URLS,
)


def _inference_base_urls(primary_base_url: str) -> list[str]:
    """Primary first, then the alias domains.

    This list must have MORE THAN ONE entry or failover cannot engage at all.
    Every advance downstream is guarded by `base_index < len(base_urls) - 1`,
    so a single-entry list makes the transport-error and 502/503/504 handling
    unreachable — the machinery was present and could never run.

    Aliases are appended only for the default API host. A caller who passed
    their own base_url (a private deployment, a test server, a regional pin)
    gets exactly what they asked for; silently redirecting that to a public
    alias would be worse than failing.
    """
    primary = primary_base_url.rstrip("/")
    if primary != DEFAULT_API_BASE_URL.rstrip("/"):
        return [primary]
    return list(dict.fromkeys([primary, *(u.rstrip("/") for u in ALIAS_API_BASE_URLS)]))


def _region_candidates(primary_base_url: str) -> list[str]:
    candidates = [*REGION_BASE_URLS, primary_base_url.rstrip("/")]
    return list(dict.fromkeys(candidate.rstrip("/") for candidate in candidates))


def _healthy_region_status(status_code: int) -> bool:
    # 401 is accepted during the rolling transition from the former
    # authenticated liveness path to the public, storage-free /health route.
    return status_code in {200, 401}


def _ordered_regions(primary_base_url: str, winner: str | None) -> list[str]:
    primary = primary_base_url.rstrip("/")
    if winner is None:
        # No region answered the health race. That is exactly when the alias
        # domains matter, so fall back to the same list used without affinity
        # rather than collapsing to a single unreachable host.
        return _inference_base_urls(primary_base_url)
    return list(
        dict.fromkeys(
            [
                winner,
                primary,
                *_region_candidates(primary_base_url),
                *_inference_base_urls(primary_base_url),
            ]
        )
    )


def _select_regions_sync(
    client: httpx.Client,
    primary_base_url: str,
    *,
    timeout_seconds: float,
) -> list[str]:
    candidates = _region_candidates(primary_base_url)

    def measure(base_url: str) -> tuple[float, str] | None:
        started = time.perf_counter()
        try:
            response = client.get(
                f"{base_url.rsplit('/v1', 1)[0]}/health",
                timeout=timeout_seconds,
            )
        except httpx.HTTPError:
            return None
        if not _healthy_region_status(response.status_code):
            return None
        return (time.perf_counter() - started, base_url)

    executor = concurrent.futures.ThreadPoolExecutor(max_workers=len(candidates))
    futures = [executor.submit(measure, base_url) for base_url in candidates]
    winner: str | None = None
    try:
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result is not None:
                _latency, winner = result
                break
    finally:
        for future in futures:
            future.cancel()
        # Running probes retain their own short HTTP timeout. Do not make the
        # first inference wait for a slow region after a healthy winner exists.
        executor.shutdown(wait=False, cancel_futures=True)
    return _ordered_regions(primary_base_url, winner)


async def _select_regions_async(
    client: httpx.AsyncClient,
    primary_base_url: str,
    *,
    timeout_seconds: float,
) -> list[str]:
    async def measure(base_url: str) -> tuple[float, str] | None:
        started = time.perf_counter()
        try:
            response = await client.get(
                f"{base_url.rsplit('/v1', 1)[0]}/health",
                timeout=timeout_seconds,
            )
        except httpx.HTTPError:
            return None
        if not _healthy_region_status(response.status_code):
            return None
        return (time.perf_counter() - started, base_url)

    tasks = [
        asyncio.create_task(measure(base_url)) for base_url in _region_candidates(primary_base_url)
    ]
    winner: str | None = None
    try:
        for completed in asyncio.as_completed(tasks):
            result = await completed
            if result is not None:
                _latency, winner = result
                break
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
    return _ordered_regions(primary_base_url, winner)


class BaseUrlPool:
    """Sync inference-plane candidate provider.

    Owns the lazy regional-affinity resolution: the first read runs the
    health race exactly once (under a lock), later reads return the pinned
    ordering. If the underlying httpx client was swapped out after
    construction (tests do this to inject transports), the pending probe is
    abandoned and the static alias list is used — probing a transport the
    caller never intended is worse than skipping affinity.
    """

    def __init__(
        self,
        get_client: Callable[[], httpx.Client],
        primary_base_url: str,
        *,
        affinity_pending: bool,
        probe_timeout: float,
    ) -> None:
        self._get_client = get_client
        self._primary = primary_base_url
        self._urls = _inference_base_urls(primary_base_url)
        self._pending = affinity_pending
        self._probe_timeout = probe_timeout
        self._lock = threading.Lock()
        self._client_identity = id(get_client())

    def current(self) -> list[str]:
        client = self._get_client()
        if id(client) != self._client_identity:
            self._pending = False
        if not self._pending:
            return self._urls
        with self._lock:
            if self._pending:
                self._urls = _select_regions_sync(
                    client,
                    self._primary,
                    timeout_seconds=self._probe_timeout,
                )
                self._pending = False
        return self._urls


class AsyncBaseUrlPool:
    """Async twin of :class:`BaseUrlPool`.

    ``current()`` awaits the once-only health race; ``snapshot()`` returns
    the last resolved list without touching the network, for the sans-IO
    retry controller to re-read per attempt after the logical call has
    awaited ``current()`` once.
    """

    def __init__(
        self,
        get_client: Callable[[], httpx.AsyncClient],
        primary_base_url: str,
        *,
        affinity_pending: bool,
        probe_timeout: float,
    ) -> None:
        self._get_client = get_client
        self._primary = primary_base_url
        self._urls = _inference_base_urls(primary_base_url)
        self._pending = affinity_pending
        self._probe_timeout = probe_timeout
        self._lock = asyncio.Lock()
        self._client_identity = id(get_client())

    async def current(self) -> list[str]:
        client = self._get_client()
        if id(client) != self._client_identity:
            self._pending = False
        if not self._pending:
            return self._urls
        async with self._lock:
            if self._pending:
                self._urls = await _select_regions_async(
                    client,
                    self._primary,
                    timeout_seconds=self._probe_timeout,
                )
                self._pending = False
        return self._urls

    def snapshot(self) -> list[str]:
        return self._urls
