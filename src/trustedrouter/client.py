# ruff: noqa: F401
"""Compatibility entry point (L9).

The whole SDK historically lived in this one module. It is now a pure
re-export shim over the layered internal modules:

    _constants.py      L7 data   default URLs, timeouts, model aliases
    _orchestration.py  L7        tool builders, ProviderPreferences, lifting
    _retry.py          L1        pure retry/failover policy kernel
    _routing.py        L2        candidate lists + regional-affinity pools
    _transport.py      L3        THE retry/failover loop (4 drivers)
    _requests.py       L4        per-attempt request assembly
    _sse.py / _collect.py  L5    stream codec + stream->completion collection
    _errors.py         L6        typed error taxonomy + raise helpers
    _client_sync.py / _client_async.py  L8  endpoint facades

Every name importable from ``trustedrouter.client`` before the split —
public or underscore-private — keeps importing from here.

Patch seams preserved on purpose:
- ``trustedrouter.client._retry_sleep`` — the decision kernel resolves the
  backoff function through this module at decision time, so patching it
  here still governs every sleep.
- ``trustedrouter.client.random`` / ``trustedrouter.client.httpx`` — module
  objects kept importable here; patching their attributes (e.g.
  ``random.uniform``, ``httpx.Client``) is global and reaches the split
  modules unchanged.
"""

from __future__ import annotations

import random
import time

import httpx

from trustedrouter._client_async import AsyncTrustedRouter
from trustedrouter._client_sync import TrustedRouter, fetch_trust_release
from trustedrouter._collect import (
    _collect_completion,
    _collect_trustedrouter_metadata,
    _trustedrouter_synth_event_detail,
    _with_usage,
)
from trustedrouter._constants import (
    ADVISOR_MODEL,
    ALIAS_API_BASE_URLS,
    ATHENA_MODEL,
    AUTO_MODEL,
    CONFIDENTIAL_MODEL,
    DEFAULT_API_BASE_URL,
    DEFAULT_CONTROL_BASE_URL,
    DEFAULT_FUSION_TIMEOUT_SECONDS,
    DEFAULT_REGION_PROBE_TIMEOUT_SECONDS,
    DEFAULT_REQUEST_TIMEOUT_SECONDS,
    DEFAULT_STATUS_URL,
    DEFAULT_TRUST_RELEASE_URL,
    E2E_MODEL,
    EU_MODEL,
    FAST_MODEL,
    FUSION_FREEDOM_FALLBACK_FINALS,
    FUSION_FREEDOM_FALLBACK_JUDGES,
    FUSION_FREEDOM_PANEL,
    FUSION_MODEL,
    MAP_REDUCE_MODEL,
    PROMETHEUS_MODEL,
    REGION_BASE_URLS,
    SELECTOR_MODEL,
    SOCRATES_MODEL,
    SUBAGENT_MODEL,
    SYNTH_MODEL,
    US_MODEL,
    ZDR_MODEL,
    ZEUS_MODEL,
)
from trustedrouter._errors import (
    AuthenticationError,
    BadRequestError,
    EndpointNotSupportedError,
    InternalError,
    NotFoundError,
    PermissionDeniedError,
    RateLimitError,
    TrustedRouterError,
    _araise_for_stream_response,
    _classify_error,
    _error_message,
    _json_or_raise,
    _optional_error_string,
    _raise_for_stream_response,
    _transport_retry_error,
)
from trustedrouter._orchestration import (
    _ADVISOR_MODELS,
    _FUSION_PRIMITIVE_MODELS,
    ProviderPreferences,
    _move_orchestration_options_into_tools,
    advisor_tool,
    fusion_tool,
    map_reduce_tool,
    selector_tool,
    subagent_tool,
)
from trustedrouter._requests import (
    _DEFAULT_USER_AGENT,
    _broadcast_destination_body,
    _build_stream_request,
    _models_path,
    _responses_body,
    _user_agent,
)
from trustedrouter._retry import (
    _new_idempotency_key,
    _regional_failoverable,
    _retry_after_seconds,
    _retry_sleep,
    _retryable,
    _should_retry_header,
)
from trustedrouter._routing import (
    _healthy_region_status,
    _inference_base_urls,
    _ordered_regions,
    _region_candidates,
    _select_regions_async,
    _select_regions_sync,
)
from trustedrouter._sse import (
    _aiter_sse_chunks,
    _aiter_sse_events,
    _delta_text,
    _event_from_sse_frame,
    _iter_sse_chunks,
    _iter_sse_events,
    _parse_sse_line,
)
