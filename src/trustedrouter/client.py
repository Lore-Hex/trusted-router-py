from __future__ import annotations

import asyncio
import concurrent.futures
import json as jsonlib
import platform
import random
import secrets
import sys
import threading
import time
from collections.abc import AsyncIterator, Iterator, Mapping, Sequence
from typing import Any
from urllib.parse import urlencode

import httpx

from trustedrouter.models import (
    ActivityList,
    AuthSession,
    ChatCompletion,
    ChatCompletionChunk,
    CheckoutSession,
    CreditsBalance,
    EmbeddingResponse,
    LogoutResponse,
    MessagesResponse,
    ModelList,
    ProviderList,
    RegionList,
    ResponseInputTokens,
    ResponseObject,
    TrustRelease,
)

DEFAULT_API_BASE_URL = "https://api.trustedrouter.com/v1"
DEFAULT_CONTROL_BASE_URL = "https://trustedrouter.com/v1"
DEFAULT_TRUST_RELEASE_URL = "https://trust.trustedrouter.com/trust/gcp-release.json"
DEFAULT_STATUS_URL = "https://status.trustedrouter.com/status.json"
DEFAULT_REQUEST_TIMEOUT_SECONDS = 120.0
DEFAULT_FUSION_TIMEOUT_SECONDS = 600.0
DEFAULT_REGION_PROBE_TIMEOUT_SECONDS = 1.5
REGION_BASE_URLS: tuple[str, ...] = (
    "https://api-us-central1.quillrouter.com/v1",
    "https://api-us-east4.quillrouter.com/v1",
    "https://api-europe-west4.quillrouter.com/v1",
)
# Exact aliases of the primary API, on separate domains served by separate DNS
# providers (trustedrouter.com from Google Cloud DNS, these two from Route 53).
#
# The domain is a single point of failure sitting above the whole deployment: a
# zone that stops answering, a registrar lock, or a resolver handing out a stale
# record takes the API down no matter how many clouds are behind it. These names
# resolve to the same attested enclaves, so falling back to one costs nothing
# and is invisible to callers.
ALIAS_API_BASE_URLS: tuple[str, ...] = (
    "https://api.allyrouter.com/v1",
    "https://api.uptimerouter.com/v1",
)
AUTO_MODEL = "trustedrouter/auto"
FAST_MODEL = "trustedrouter/fast"
ZDR_MODEL = "trustedrouter/zdr"
E2E_MODEL = "trustedrouter/e2e"
CONFIDENTIAL_MODEL = "trustedrouter/confidential"
EU_MODEL = "trustedrouter/eu"
US_MODEL = "trustedrouter/us"
FUSION_MODEL = "trustedrouter/fusion"
SYNTH_MODEL = "trustedrouter/synth"
ADVISOR_MODEL = "trustedrouter/advisor"
SELECTOR_MODEL = "trustedrouter/selector"
MAP_REDUCE_MODEL = "trustedrouter/mapreduce"
SUBAGENT_MODEL = "trustedrouter/subagent"
SOCRATES_MODEL = "trustedrouter/socrates-1.1"
PROMETHEUS_MODEL = "trustedrouter/prometheus-2.0"
ZEUS_MODEL = "trustedrouter/zeus-1.0"
ATHENA_MODEL = "trustedrouter/athena"
_ADVISOR_MODELS = {ADVISOR_MODEL}
_FUSION_PRIMITIVE_MODELS = {
    FUSION_MODEL,
    "trustedrouter/fusion-code",
    SYNTH_MODEL,
    "trustedrouter/synth-code",
    SELECTOR_MODEL,
    MAP_REDUCE_MODEL,
}

# Recommended panel + judge fallback chain for maximum willingness to answer.
# Use gateway-supported latest aliases where possible so examples survive
# provider deprecations without requiring an SDK release.
FUSION_FREEDOM_PANEL: tuple[str, ...] = (
    "minimax/minimax-m3",
    "~kimi/latest",
    "~zai/glm-latest",
    "google/gemma-4-31b-it",
    "deepseek/deepseek-v4-flash",
)
FUSION_FREEDOM_FALLBACK_JUDGES: tuple[str, ...] = (
    "minimax/minimax-m3",
    "~zai/glm-latest",
    "~kimi/latest",
    "deepseek/deepseek-v4-flash",
    "google/gemma-4-31b-it",
)
FUSION_FREEDOM_FALLBACK_FINALS: tuple[str, ...] = (
    "minimax/minimax-m3",
    "~zai/glm-latest",
    "~kimi/latest",
    "deepseek/deepseek-v4-flash",
    "google/gemma-4-31b-it",
)


def fusion_tool(
    *,
    enabled: bool | None = None,
    analysis_models: Sequence[str] | None = None,
    model: str | None = None,  # judge / synthesis model
    selection_strategy: str | None = None,
    fallback_judges: Sequence[str] | None = None,
    fallback_final_models: Sequence[str] | None = None,
    max_completion_tokens: int | None = None,
    max_tool_calls: int | None = None,
    preset: str | None = None,
    panel_prompt: str | None = None,
    synthesis_prompt: str | None = None,
) -> dict[str, Any]:
    """Build a ``trustedrouter:fusion`` tool spec. Fan a request across a panel
    of models and have a judge model pick or synthesize one answer. Omit a field
    to let the gateway default it (``selection_strategy`` defaults to
    ``"synthesize_non_refusals"``)."""
    parameters: dict[str, Any] = {}
    if enabled is not None:
        parameters["enabled"] = enabled
    if preset is not None:
        parameters["preset"] = preset
    if analysis_models is not None:
        parameters["analysis_models"] = list(analysis_models)
    if model is not None:
        parameters["model"] = model
    if selection_strategy is not None:
        parameters["selection_strategy"] = selection_strategy
    if fallback_judges is not None:
        parameters["fallback_judges"] = list(fallback_judges)
    if fallback_final_models is not None:
        parameters["fallback_final_models"] = list(fallback_final_models)
    if max_completion_tokens is not None:
        parameters["max_completion_tokens"] = max_completion_tokens
    if max_tool_calls is not None:
        parameters["max_tool_calls"] = max_tool_calls
    if panel_prompt is not None:
        parameters["panel_prompt"] = panel_prompt
    if synthesis_prompt is not None:
        parameters["synthesis_prompt"] = synthesis_prompt
    return {"type": "trustedrouter:fusion", "parameters": parameters}


def advisor_tool(
    *,
    enabled: bool | None = None,
    depth: int | None = None,
    worker_models: Sequence[str] | None = None,
    advisor_models: Sequence[str] | None = None,
    max_get_advice_calls: int | None = None,
    advisor_max_tokens: int | None = None,
    worker_timeout_ms: int | None = None,
    advisor_timeout_ms: int | None = None,
    auto_initial_advice: bool | None = None,
) -> dict[str, Any]:
    """Build a ``trustedrouter:advisor`` tool spec.

    Advisor orchestration runs a worker model and gives it one private
    zero-argument ``_trustedrouter_get_advice`` tool. The gateway executes that
    internal tool only when the worker asks for help. Most callers should pass
    these options directly to ``chat_completions(model=...)``; the SDK lifts
    them into this tool config.
    """
    parameters: dict[str, Any] = {}
    if enabled is not None:
        parameters["enabled"] = enabled
    if depth is not None:
        parameters["depth"] = depth
    if worker_models is not None:
        parameters["worker_models"] = list(worker_models)
    if advisor_models is not None:
        parameters["advisor_models"] = list(advisor_models)
    if max_get_advice_calls is not None:
        parameters["max_get_advice_calls"] = max_get_advice_calls
    if advisor_max_tokens is not None:
        parameters["advisor_max_tokens"] = advisor_max_tokens
    if worker_timeout_ms is not None:
        parameters["worker_timeout_ms"] = worker_timeout_ms
    if advisor_timeout_ms is not None:
        parameters["advisor_timeout_ms"] = advisor_timeout_ms
    if auto_initial_advice is not None:
        parameters["auto_initial_advice"] = auto_initial_advice
    return {"type": "trustedrouter:advisor", "parameters": parameters}


def selector_tool(
    *,
    enabled: bool | None = None,
    analysis_models: Sequence[str] | None = None,
    selector_models: Sequence[str] | None = None,
    selector_prompt: str | None = None,
    max_completion_tokens: int | None = None,
) -> dict[str, Any]:
    """Build a ``trustedrouter:selector`` tool spec."""
    parameters: dict[str, Any] = {}
    if enabled is not None:
        parameters["enabled"] = enabled
    if analysis_models is not None:
        parameters["analysis_models"] = list(analysis_models)
    if selector_models is not None:
        parameters["selector_models"] = list(selector_models)
    if selector_prompt is not None:
        parameters["selector_prompt"] = selector_prompt
    if max_completion_tokens is not None:
        parameters["max_completion_tokens"] = max_completion_tokens
    return {"type": "trustedrouter:selector", "parameters": parameters}


def map_reduce_tool(
    *,
    enabled: bool | None = None,
    mapper_models: Sequence[str] | None = None,
    parallel_models: Sequence[str] | None = None,
    reducer_models: Sequence[str] | None = None,
    max_parts: int | None = None,
    mapper_prompt: str | None = None,
    parallel_prompt: str | None = None,
    reducer_prompt: str | None = None,
    max_completion_tokens: int | None = None,
) -> dict[str, Any]:
    """Build a ``trustedrouter:mapreduce`` tool spec."""
    parameters: dict[str, Any] = {}
    if enabled is not None:
        parameters["enabled"] = enabled
    for collection_key, collection_value in (
        ("mapper_models", mapper_models),
        ("parallel_models", parallel_models),
        ("reducer_models", reducer_models),
    ):
        if collection_value is not None:
            parameters[collection_key] = list(collection_value)
    for scalar_key, scalar_value in (
        ("max_parts", max_parts),
        ("mapper_prompt", mapper_prompt),
        ("parallel_prompt", parallel_prompt),
        ("reducer_prompt", reducer_prompt),
        ("max_completion_tokens", max_completion_tokens),
    ):
        if scalar_value is not None:
            parameters[scalar_key] = scalar_value
    return {"type": "trustedrouter:mapreduce", "parameters": parameters}


def subagent_tool(
    *,
    enabled: bool | None = None,
    controller_model: str | None = None,
    model: str | None = None,
    instructions: str | None = None,
    depth: int | None = None,
    max_subagent_calls: int | None = None,
    max_completion_tokens: int | None = None,
    temperature: float | None = None,
    reasoning: Any | None = None,
    tools: Sequence[Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build a ``trustedrouter:subagent`` tool spec."""
    parameters: dict[str, Any] = {}
    if enabled is not None:
        parameters["enabled"] = enabled
    for key, value in (
        ("controller_model", controller_model),
        ("model", model),
        ("instructions", instructions),
        ("depth", depth),
        ("max_subagent_calls", max_subagent_calls),
        ("max_completion_tokens", max_completion_tokens),
        ("temperature", temperature),
    ):
        if value is not None:
            parameters[key] = value
    if reasoning is not None:
        parameters["reasoning"] = reasoning
    if tools is not None:
        parameters["tools"] = [dict(tool) for tool in tools]
    return {"type": "trustedrouter:subagent", "parameters": parameters}


class ProviderPreferences(dict[str, Any]):
    """Typed provider routing preferences accepted by inference endpoints."""

    _PRIVACY = {"any", "no_store", "zdr", "confidential", "e2e", "e2ee"}
    _SORT = {"price", "latency", "throughput"}

    def __init__(
        self,
        *,
        order: Sequence[str] | None = None,
        only: Sequence[str] | None = None,
        ignore: Sequence[str] | None = None,
        sort: str | None = None,
        allow_fallbacks: bool | None = None,
        require_parameters: bool | None = None,
        data_collection: str | None = None,
        min_privacy: str | None = None,
        jurisdiction: str | None = None,
        usage: str | None = None,
        quantizations: Sequence[str] | None = None,
        max_price: Mapping[str, Any] | None = None,
    ) -> None:
        super().__init__()
        for key, value in (("order", order), ("only", only), ("ignore", ignore)):
            if value is not None:
                self[key] = list(value)
        if sort is not None:
            normalized = sort.strip().lower()
            if normalized not in self._SORT:
                raise ValueError("sort must be price, latency, or throughput")
            self["sort"] = normalized
        for boolean_key, boolean_value in (
            ("allow_fallbacks", allow_fallbacks),
            ("require_parameters", require_parameters),
        ):
            if boolean_value is not None:
                self[boolean_key] = boolean_value
        if data_collection is not None:
            normalized = data_collection.strip().lower()
            if normalized not in {"allow", "deny"}:
                raise ValueError("data_collection must be allow or deny")
            self["data_collection"] = normalized
        if min_privacy is not None:
            normalized = min_privacy.strip().lower()
            if normalized not in self._PRIVACY:
                raise ValueError("unsupported min_privacy")
            self["min_privacy"] = normalized
        if jurisdiction is not None:
            normalized = jurisdiction.strip().lower()
            if normalized != "us":
                raise ValueError("jurisdiction currently supports only us")
            self["jurisdiction"] = normalized
        if usage is not None:
            normalized = usage.strip().lower()
            if normalized not in {"credits", "byok"}:
                raise ValueError("usage must be credits or byok")
            self["usage"] = normalized
        if quantizations is not None:
            self["quantizations"] = list(quantizations)
        if max_price is not None:
            self["max_price"] = dict(max_price)

    @classmethod
    def zdr(cls) -> ProviderPreferences:
        return cls(min_privacy="zdr", data_collection="deny")

    @classmethod
    def confidential(cls) -> ProviderPreferences:
        return cls(min_privacy="confidential", data_collection="deny")

    @classmethod
    def us_only(cls) -> ProviderPreferences:
        return cls(jurisdiction="us")

def _move_orchestration_options_into_tools(
    model: str,
    params: dict[str, Any],
) -> dict[str, Any]:
    """Lift SDK orchestration kwargs into gateway tool specs.

    The gateway intentionally ignores top-level helper fields such as
    ``worker_models`` and ``analysis_models``. They must live inside the
    TrustedRouter tool config so direct ``chat_completions(model=...)`` calls
    behave the same as the convenience helpers.
    """

    tools = list(params.pop("tools", []))
    normalized_model = model.strip().lower()

    advisor_keys = {
        "depth",
        "worker_models",
        "advisor_models",
        "max_get_advice_calls",
        "advisor_max_tokens",
        "worker_timeout_ms",
        "advisor_timeout_ms",
        "auto_initial_advice",
    }
    advisor_values: dict[str, Any] = {}
    for key in list(params):
        if key not in advisor_keys:
            continue
        value = params.pop(key)
        if value is not None:
            advisor_values[key] = value
    if advisor_values:
        tools.append(
            advisor_tool(
                depth=advisor_values.get("depth"),
                worker_models=advisor_values.get("worker_models"),
                advisor_models=advisor_values.get("advisor_models"),
                max_get_advice_calls=advisor_values.get("max_get_advice_calls"),
                advisor_max_tokens=advisor_values.get("advisor_max_tokens"),
                worker_timeout_ms=advisor_values.get("worker_timeout_ms"),
                advisor_timeout_ms=advisor_values.get("advisor_timeout_ms"),
                auto_initial_advice=advisor_values.get("auto_initial_advice"),
            )
        )

    fusion_key_map = {
        "analysis_models": "analysis_models",
        "judge_model": "model",
        "selection_strategy": "selection_strategy",
        "fallback_judges": "fallback_judges",
        "fallback_final_models": "fallback_final_models",
        "max_completion_tokens": "max_completion_tokens",
        "max_tool_calls": "max_tool_calls",
        "preset": "preset",
        "panel_prompt": "panel_prompt",
        "synthesis_prompt": "synthesis_prompt",
        "final_prompt": "final_prompt",
        "selector_models": "selector_models",
        "selector_model": "selector_model",
        "selector_prompt": "selector_prompt",
        "mapper_models": "mapper_models",
        "mapper_model": "mapper_model",
        "mapper_prompt": "mapper_prompt",
        "parallel_models": "parallel_models",
        "parallel_model": "parallel_model",
        "parallel_prompt": "parallel_prompt",
        "reducer_models": "reducer_models",
        "reducer_model": "reducer_model",
        "reducer_prompt": "reducer_prompt",
    }
    fusion_values: dict[str, Any] = {}
    for sdk_key, gateway_key in fusion_key_map.items():
        if sdk_key not in params:
            continue
        value = params.pop(sdk_key)
        if value is not None:
            fusion_values[gateway_key] = value
    if fusion_values:
        tools.append({"type": "trustedrouter:fusion", "parameters": fusion_values})

    if tools:
        params["tools"] = tools
    elif normalized_model in _ADVISOR_MODELS or normalized_model in _FUSION_PRIMITIVE_MODELS:
        params.pop("tools", None)

    return params


def _user_agent() -> str:
    # Lazy: read __version__ from the installed package metadata so the
    # UA stays in sync with whatever PyPI has, without import-cycling on
    # the package's __init__.py.
    try:
        from importlib.metadata import version as _v

        v = _v("trusted-router-py")
    except Exception:  # noqa: BLE001
        v = "unknown"
    py = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    return f"trusted-router-py/{v} python/{py} httpx/{httpx.__version__} {platform.system()}"


_DEFAULT_USER_AGENT = _user_agent()


# ---- error hierarchy ------------------------------------------------------


class TrustedRouterError(RuntimeError):
    """Base for all SDK-raised errors. Subclasses discriminate by HTTP
    status so callers can `except RateLimitError` / `except AuthenticationError`
    without inspecting numeric status codes."""

    def __init__(self, status_code: int, message: str, *, payload: Any | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.payload = payload
        detail = payload.get("error", payload) if isinstance(payload, Mapping) else {}
        if not isinstance(detail, Mapping):
            detail = {}
        self.layer = _optional_error_string(detail, "layer")
        self.source = _optional_error_string(detail, "source")
        self.provider = _optional_error_string(detail, "provider")
        self.request_id = _optional_error_string(detail, "request_id")


def _optional_error_string(payload: Mapping[str, Any], key: str) -> str | None:
    value = payload.get(key)
    return value if isinstance(value, str) and value else None


class BadRequestError(TrustedRouterError):
    """4xx-class request error (mostly 400, 422). Body is malformed or
    rejected by the gateway/model."""


class AuthenticationError(TrustedRouterError):
    """401 — bearer token is missing, malformed, or revoked."""


class PermissionDeniedError(TrustedRouterError):
    """403 — bearer is valid but lacks scope for this resource."""


class NotFoundError(TrustedRouterError):
    """404 — the model or resource doesn't exist."""


class EndpointNotSupportedError(TrustedRouterError):
    """501 — this OpenRouter-compatible endpoint is intentionally stubbed."""


class RateLimitError(TrustedRouterError):
    """429 — slow down. `retry_after` is the value of the Retry-After
    header in seconds, or None if the gateway didn't send one."""

    def __init__(
        self,
        status_code: int,
        message: str,
        *,
        payload: Any | None = None,
        retry_after: float | None = None,
    ) -> None:
        super().__init__(status_code, message, payload=payload)
        self.retry_after = retry_after


class InternalError(TrustedRouterError):
    """5xx — gateway or upstream model failure. These are the requests
    the SDK retries automatically (see `max_retries`)."""


def _classify_error(
    status_code: int, message: str, *, payload: Any | None, retry_after: float | None
) -> TrustedRouterError:
    if status_code == 401:
        return AuthenticationError(status_code, message, payload=payload)
    if status_code == 403:
        return PermissionDeniedError(status_code, message, payload=payload)
    if status_code == 404:
        return NotFoundError(status_code, message, payload=payload)
    if status_code == 429:
        return RateLimitError(status_code, message, payload=payload, retry_after=retry_after)
    if status_code == 501:
        return EndpointNotSupportedError(status_code, message, payload=payload)
    if 400 <= status_code < 500:
        return BadRequestError(status_code, message, payload=payload)
    if status_code >= 500:
        return InternalError(status_code, message, payload=payload)
    return TrustedRouterError(status_code, message, payload=payload)


def _retry_after_seconds(headers: Mapping[str, str]) -> float | None:
    """Parse Retry-After. Per RFC 7231 it can be either an integer number
    of seconds OR an HTTP-date; we only honor the integer form because
    the gateway only emits that and the date form is rarely useful for
    short retries."""
    raw = headers.get("retry-after") or headers.get("Retry-After")
    if not raw:
        return None
    try:
        return max(0.0, float(raw.strip()))
    except ValueError:
        return None


# ---- retry policy --------------------------------------------------------


def _retryable(status_code: int) -> bool:
    """Which responses the SDK retries by default. 429 + 5xx are safe
    to retry idempotently; the gateway is responsible for 5xx-on-write
    being safe (its writes are idempotent or the response is 4xx)."""
    return status_code == 429 or status_code >= 500


def _regional_failoverable(status_code: int) -> bool:
    return status_code in {502, 503, 504}


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


def _retryable_stream_open_status(
    status_code: int,
    *,
    regional_failover: bool,
) -> bool:
    # Streaming responses are still unopened at this point, so retrying has
    # the same idempotency semantics as a normal request. Regional failover is
    # handled separately: 429 and non-gateway 5xx back off on the pinned host.
    del regional_failover
    return _retryable(status_code)


def _transport_retry_error(exc: httpx.TransportError) -> InternalError:
    return InternalError(503, f"TrustedRouter endpoint unavailable: {exc!s}")


def _retry_sleep(attempt: int, *, retry_after: float | None) -> float:
    """Exponential backoff with full jitter, capped at 30 s. If the
    server gave us a Retry-After hint, honor that as the floor."""
    base = min(30.0, 0.5 * (2**attempt))
    delay = random.uniform(0, base)  # noqa: S311  not crypto
    if retry_after is not None:
        delay = max(delay, retry_after)
    return delay


def _new_idempotency_key() -> str:
    """Generate a stable-at-call-site key for retryable inference requests."""
    return f"tr-req-{secrets.token_urlsafe(24)}"


# ---- shared streaming helpers --------------------------------------------


def _build_stream_request(
    method: str,
    url: str,
    *,
    body: Mapping[str, Any] | None,
    api_key: str | None,
    extra_headers: Mapping[str, str] | None,
    idempotency_key: str | None = None,
    workspace_id: str | None = None,
    timeout: float | httpx.Timeout | None = None,
) -> dict[str, Any]:
    headers: dict[str, str] = {
        "accept": "text/event-stream",
        "user-agent": _DEFAULT_USER_AGENT,
    }
    if extra_headers:
        headers.update(extra_headers)
    if idempotency_key:
        headers["idempotency-key"] = idempotency_key
    if workspace_id:
        headers["x-trustedrouter-workspace"] = workspace_id
    if api_key:
        headers["authorization"] = f"Bearer {api_key}"
    payload: Mapping[str, Any] | None = body
    request: dict[str, Any] = {
        "method": method,
        "url": url,
        "json": payload,
        "headers": headers,
    }
    if timeout is not None:
        request["timeout"] = timeout
    return request


def _parse_sse_line(line: str) -> dict[str, Any] | None:
    """Parse one `data: {...}` line. Returns None for non-data lines or [DONE]."""
    if not line.startswith("data: "):
        return None
    payload = line[len("data: ") :].strip()
    if not payload or payload == "[DONE]":
        return None
    try:
        return jsonlib.loads(payload)  # type: ignore[no-any-return]
    except jsonlib.JSONDecodeError:
        return None


def _event_from_sse_frame(lines: list[str]) -> dict[str, Any] | None:
    event_name: str | None = None
    data_parts: list[str] = []
    for line in lines:
        if line.startswith("event:"):
            event_name = line[len("event:") :].strip()
        elif line.startswith("data:"):
            data_parts.append(line[len("data:") :].strip())
    data = "\n".join(data_parts).strip()
    if not data or data == "[DONE]":
        return None
    try:
        payload = jsonlib.loads(data)
    except jsonlib.JSONDecodeError:
        payload = {"data": data}
    if event_name and isinstance(payload, dict) and "event" not in payload:
        payload = {"event": event_name, **payload}
    return payload if isinstance(payload, dict) else {"event": event_name, "data": payload}


def _iter_sse_events(response: httpx.Response) -> Iterator[dict[str, Any]]:
    frame: list[str] = []
    for line in response.iter_lines():
        if line:
            frame.append(line)
            continue
        event = _event_from_sse_frame(frame)
        frame = []
        if event is not None:
            yield event
    event = _event_from_sse_frame(frame)
    if event is not None:
        yield event


async def _aiter_sse_events(response: httpx.Response) -> AsyncIterator[dict[str, Any]]:
    frame: list[str] = []
    async for line in response.aiter_lines():
        if line:
            frame.append(line)
            continue
        event = _event_from_sse_frame(frame)
        frame = []
        if event is not None:
            yield event
    event = _event_from_sse_frame(frame)
    if event is not None:
        yield event


def _delta_text(chunk: Mapping[str, Any]) -> str:
    choices = chunk.get("choices") or []
    if not choices:
        return ""
    delta = choices[0].get("delta") or {}
    content = delta.get("content")
    return content if isinstance(content, str) else ""


def _iter_sse_chunks(response: httpx.Response) -> Iterator[dict[str, Any]]:
    """Walk an open SSE response and yield each parsed `data: {...}` chunk
    as a dict. Skips blank lines and `[DONE]` sentinels. Shared by the
    sync chat_completions* methods so the SSE parsing lives in one place."""
    for line in response.iter_lines():
        chunk = _parse_sse_line(line)
        if chunk is not None:
            yield chunk


async def _aiter_sse_chunks(response: httpx.Response) -> AsyncIterator[dict[str, Any]]:
    """Async twin of _iter_sse_chunks."""
    async for line in response.aiter_lines():
        chunk = _parse_sse_line(line)
        if chunk is not None:
            yield chunk


def _raise_for_stream_response(response: httpx.Response) -> None:
    """Translate a 4xx/5xx response (during stream open) into the
    appropriate typed error subclass — same hierarchy `_json_or_raise`
    uses for non-streaming requests, so callers can `except RateLimitError`
    consistently."""
    detail = response.read().decode("utf-8", errors="replace")[:240]
    raise _classify_error(
        response.status_code,
        detail,
        payload=None,
        retry_after=_retry_after_seconds(response.headers),
    )


async def _araise_for_stream_response(response: httpx.Response) -> None:
    detail = (await response.aread()).decode("utf-8", errors="replace")[:240]
    raise _classify_error(
        response.status_code,
        detail,
        payload=None,
        retry_after=_retry_after_seconds(response.headers),
    )


def _collect_completion(chunks: list[dict[str, Any]]) -> dict[str, Any]:
    """Reconstruct the OpenAI chat.completion JSON shape from a list of
    chat.completion.chunk frames. Used so callers that asked for
    stream=False still get a JSON object even though the gateway
    insists on streaming."""
    if not chunks:
        return {
            "id": "",
            "object": "chat.completion",
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": ""},
                    "finish_reason": "stop",
                }
            ],
        }
    text_parts: list[str] = []
    finish_reason: str | None = None
    role = "assistant"
    usage: dict[str, Any] | None = None
    trustedrouter = _collect_trustedrouter_metadata(chunks)
    # tool-call deltas arrive fragmented and keyed by `index`; the arguments
    # stream in pieces and must be concatenated in arrival order.
    tool_calls: dict[int, dict[str, Any]] = {}
    for c in chunks:
        chunk_usage = c.get("usage")
        if isinstance(chunk_usage, dict):
            usage = chunk_usage
        choices = c.get("choices") or []
        if not choices:
            continue
        choice0 = choices[0]
        delta = choice0.get("delta") or {}
        if isinstance(delta.get("role"), str):
            role = delta["role"]
        if isinstance(delta.get("content"), str):
            text_parts.append(delta["content"])
        for tc in delta.get("tool_calls") or []:
            if not isinstance(tc, dict):
                continue
            idx = tc.get("index", 0)
            slot = tool_calls.setdefault(
                idx, {"index": idx, "type": "function", "function": {"name": "", "arguments": ""}}
            )
            if tc.get("id"):
                slot["id"] = tc["id"]
            if tc.get("type"):
                slot["type"] = tc["type"]
            fn = tc.get("function")
            if isinstance(fn, dict):
                if fn.get("name"):
                    slot["function"]["name"] = fn["name"]
                if isinstance(fn.get("arguments"), str):
                    slot["function"]["arguments"] += fn["arguments"]
        if choice0.get("finish_reason"):
            finish_reason = choice0["finish_reason"]
    last = chunks[-1]
    content = "".join(text_parts)
    # OpenAI sets content to null when a turn is only tool calls.
    message: dict[str, Any] = {
        "role": role,
        "content": content if content else (None if tool_calls else ""),
    }
    if tool_calls:
        message["tool_calls"] = [tool_calls[i] for i in sorted(tool_calls)]
    result: dict[str, Any] = {
        "id": last.get("id", ""),
        "object": "chat.completion",
        "created": last.get("created", 0),
        "model": last.get("model", ""),
        "choices": [
            {
                "index": 0,
                "message": message,
                "finish_reason": finish_reason or "stop",
            }
        ],
    }
    if usage is not None:
        result["usage"] = usage
    if trustedrouter is not None:
        result["trustedrouter"] = trustedrouter
    return result


def _collect_trustedrouter_metadata(chunks: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Preserve TrustedRouter extension metadata from streamed chunks.

    The gateway streams Synth observability as top-level ``trustedrouter`` events
    with empty ``choices``. The collector used to rebuild only OpenAI core fields,
    which meant callers of ``chat_completions`` lost panel/judge/final details.
    """

    synth_events: list[dict[str, Any]] = []
    synth_details: dict[str, Any] = {}

    for chunk in chunks:
        trusted = chunk.get("trustedrouter")
        if not isinstance(trusted, Mapping):
            continue
        synth = trusted.get("synth")
        if not isinstance(synth, Mapping):
            continue

        synth_dict = dict(synth)
        if "event" in synth_dict:
            synth_events.append(synth_dict)
        else:
            synth_details.update(synth_dict)

    if not synth_events and not synth_details:
        return None

    synth_out = dict(synth_details)
    if synth_events:
        synth_out["events"] = synth_events

    panel: list[dict[str, Any]] = []
    judge_attempts: list[dict[str, Any]] = []
    final_attempts: list[dict[str, Any]] = []
    for event in synth_events:
        event_name = event.get("event")
        detail = _trustedrouter_synth_event_detail(event)
        if detail is None:
            continue
        if event_name == "panel.done":
            panel.append(detail)
        elif event_name == "judge.done":
            judge_attempts.append(detail)
        elif event_name == "final.done":
            final_attempts.append(detail)

    if panel and "panel" not in synth_out:
        synth_out["panel"] = panel
    if judge_attempts:
        synth_out.setdefault("judge_attempts", judge_attempts)
        synth_out.setdefault("judge", judge_attempts[-1])
    if final_attempts and "final_attempts" not in synth_out:
        synth_out["final_attempts"] = final_attempts

    return {"synth": synth_out}


def _trustedrouter_synth_event_detail(event: Mapping[str, Any]) -> dict[str, Any] | None:
    detail = event.get("detail")
    if not isinstance(detail, Mapping):
        return None
    out = dict(detail)
    for key in ("stage", "index", "model"):
        if key in event and key not in out:
            out[key] = event[key]
    return out


def _with_usage(params: Mapping[str, Any]) -> dict[str, Any]:
    """Ask the gateway to emit a trailing usage frame so a *collected*
    completion carries token counts. The streamed transport omits usage
    unless ``stream_options.include_usage`` is set; default it on (callers
    can still override by passing their own ``stream_options``)."""
    merged = dict(params)
    stream_options = dict(merged.get("stream_options") or {})
    stream_options.setdefault("include_usage", True)
    merged["stream_options"] = stream_options
    return merged


def _responses_body(
    *,
    model: str,
    input: str | list[Mapping[str, Any]],
    instructions: str | None,
    stream: bool,
    params: Mapping[str, Any],
) -> dict[str, Any]:
    params_dict = dict(params)
    for reserved in (
        "api_key",
        "extra_headers",
        "idempotency_key",
        "timeout",
        "workspace_id",
        "stream",
    ):
        params_dict.pop(reserved, None)
    body: dict[str, Any] = {"model": model, "input": input, "stream": stream, **params_dict}
    if instructions is not None:
        body["instructions"] = instructions
    return body


def _broadcast_destination_body(
    *,
    type: str,
    name: str,
    endpoint: str | None,
    enabled: bool,
    include_content: bool,
    method: str,
    headers: Mapping[str, str] | None,
    api_key: str | None,
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "type": type,
        "name": name,
        "enabled": enabled,
        "include_content": include_content,
        "method": method,
    }
    if endpoint is not None:
        body["endpoint"] = endpoint
    if headers is not None:
        body["headers"] = dict(headers)
    if api_key is not None:
        body["api_key"] = api_key
    return body


def _models_path(
    *,
    open_weights: bool | None = None,
    provider_jurisdiction: str | None = None,
    provider_region: str | None = None,
) -> str:
    params: dict[str, str] = {}
    if open_weights is not None:
        params["open_weights"] = "true" if open_weights else "false"
    if provider_jurisdiction:
        params["provider[jurisdiction]"] = provider_jurisdiction
    if provider_region:
        params["provider[region]"] = provider_region
    if not params:
        return "/models"
    return f"/models?{urlencode(params)}"


# ---- sync client ---------------------------------------------------------


class TrustedRouter:
    def __init__(
        self,
        api_key: str | None = None,
        *,
        base_url: str | None = None,
        control_base_url: str | None = None,
        timeout: float = DEFAULT_REQUEST_TIMEOUT_SECONDS,
        headers: Mapping[str, str] | None = None,
        workspace_id: str | None = None,
        client: httpx.Client | None = None,
        max_retries: int = 2,
        regional_failover: bool = True,
        regional_affinity: bool | None = None,
        region_probe_timeout: float = DEFAULT_REGION_PROBE_TIMEOUT_SECONDS,
    ) -> None:
        """Sync TrustedRouter client.

        By default, inference calls use the apex `api.trustedrouter.com/v1`.
        Catalog, account, billing, OAuth, and broadcast calls use
        `control_base_url` instead. Pass `base_url=...` for a custom inference
        endpoint, such as a self-hosted gateway.

        `max_retries` controls automatic retry of 429 / 5xx responses
        with exponential backoff + jitter. Set to 0 to disable retries
        entirely (e.g. inside an outer retry loop).

        The default client probes published regional liveness endpoints once,
        pins the lowest-latency healthy region, and retains the other regions
        plus the apex for idempotent failover. Pass a custom `base_url` or set
        `regional_affinity=False` to disable this selection."""
        use_regional_affinity = base_url is None and (
            client is None if regional_affinity is None else regional_affinity
        )
        if base_url is None:
            base_url = DEFAULT_API_BASE_URL
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.control_base_url = (control_base_url or DEFAULT_CONTROL_BASE_URL).rstrip("/")
        self.workspace_id = workspace_id
        self.max_retries = max(0, int(max_retries))
        self._regional_failover = bool(regional_failover)
        self._base_urls = _inference_base_urls(self.base_url)
        self._regional_affinity_pending = bool(use_regional_affinity and self._regional_failover)
        self._region_probe_timeout = max(0.1, float(region_probe_timeout))
        self._region_lock = threading.Lock()
        default_headers = {"user-agent": _DEFAULT_USER_AGENT}
        if headers:
            default_headers.update(headers)
        if client is not None:
            # Caller is responsible for the client's lifecycle (timeouts,
            # transport, cert pinning, etc.). close() becomes a no-op.
            self._client = client
            self._owns_client = False
        else:
            self._client = httpx.Client(timeout=timeout, headers=default_headers)
            self._owns_client = True
        self._region_client_identity = id(self._client)

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def __enter__(self) -> TrustedRouter:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def _active_inference_base_urls(self) -> list[str]:
        if id(self._client) != self._region_client_identity:
            self._regional_affinity_pending = False
        if not self._regional_affinity_pending:
            return self._base_urls
        with self._region_lock:
            if self._regional_affinity_pending:
                self._base_urls = _select_regions_sync(
                    self._client,
                    self.base_url,
                    timeout_seconds=self._region_probe_timeout,
                )
                self._regional_affinity_pending = False
        return self._base_urls

    def _base_index_after_status(self, status_code: int, base_index: int) -> int:
        base_urls = self._active_inference_base_urls()
        if (
            self._regional_failover
            and _regional_failoverable(status_code)
            and base_index < len(base_urls) - 1
        ):
            return base_index + 1
        return base_index

    def request(
        self,
        method: str,
        path: str,
        *,
        json: Mapping[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
        api_key: str | None = None,
        workspace_id: str | None = None,
        idempotency_key: str | None = None,
        timeout: float | httpx.Timeout | None = None,
        _base_url: str | None = None,
    ) -> dict[str, Any]:
        if (
            idempotency_key is None
            and _base_url is None
            and method.upper() not in {"GET", "HEAD", "OPTIONS"}
        ):
            idempotency_key = _new_idempotency_key()
        merged_headers: dict[str, str] = {"user-agent": _DEFAULT_USER_AGENT}
        if headers:
            merged_headers.update(headers)
        if idempotency_key:
            merged_headers["idempotency-key"] = idempotency_key
        selected_workspace_id = workspace_id if workspace_id is not None else self.workspace_id
        if selected_workspace_id:
            merged_headers["x-trustedrouter-workspace"] = selected_workspace_id
        selected_api_key = api_key if api_key is not None else self.api_key
        if selected_api_key:
            merged_headers["authorization"] = f"Bearer {selected_api_key}"
        kwargs: dict[str, Any] = {"json": json, "headers": merged_headers}
        if timeout is not None:
            kwargs["timeout"] = timeout
        # Retry 429 + 5xx with exponential backoff + jitter. Honors
        # Retry-After when present.
        base_urls = (
            [_base_url.rstrip("/")] if _base_url is not None else self._active_inference_base_urls()
        )
        attempt = 0
        base_index = 0
        while True:
            url = f"{base_urls[base_index]}/{path.lstrip('/')}"
            try:
                response = self._client.request(method, url, **kwargs)
            except httpx.TransportError as exc:
                if attempt >= self.max_retries:
                    raise _transport_retry_error(exc) from exc
                if base_index < len(base_urls) - 1:
                    base_index += 1
                time.sleep(_retry_sleep(attempt, retry_after=None))
                attempt += 1
                continue
            if attempt >= self.max_retries or not _retryable(response.status_code):
                return _json_or_raise(response)
            if _regional_failoverable(response.status_code) and base_index < len(base_urls) - 1:
                base_index += 1
            time.sleep(_retry_sleep(attempt, retry_after=_retry_after_seconds(response.headers)))
            attempt += 1

    def _control_request(
        self,
        method: str,
        path: str,
        **kwargs: Any,
    ) -> dict[str, Any]:
        return self.request(method, path, _base_url=self.control_base_url, **kwargs)

    def _build_chat_request(
        self,
        *,
        model: str,
        messages: list[Mapping[str, Any]],
        api_key: str | None,
        params: Mapping[str, Any],
        extra_headers: Mapping[str, str] | None = None,
        idempotency_key: str | None = None,
        timeout: float | httpx.Timeout | None = None,
        base_url: str | None = None,
    ) -> dict[str, Any]:
        # Pull our reserved kwargs out of `params` so they aren't sent
        # into the JSON body. (Defensive: callers spreading a dict
        # might inadvertently include these.)
        params_dict = dict(params)
        workspace_id = params_dict.pop("workspace_id", None)
        for reserved in ("extra_headers", "idempotency_key", "timeout", "api_key"):
            params_dict.pop(reserved, None)
        params_dict = _move_orchestration_options_into_tools(model, params_dict)
        body = {"model": model, "messages": messages, "stream": True, **params_dict}
        return _build_stream_request(
            "POST",
            f"{(base_url or self.base_url).rstrip('/')}/chat/completions",
            body=body,
            api_key=api_key if api_key is not None else self.api_key,
            extra_headers=extra_headers,
            idempotency_key=idempotency_key,
            workspace_id=workspace_id if workspace_id is not None else self.workspace_id,
            timeout=timeout,
        )

    def chat_completions_stream(
        self,
        *,
        model: str,
        messages: list[Mapping[str, Any]],
        api_key: str | None = None,
        extra_headers: Mapping[str, str] | None = None,
        idempotency_key: str | None = None,
        timeout: float | httpx.Timeout | None = None,
        **params: Any,
    ) -> Iterator[str]:
        """Yield assistant-message text deltas as they arrive. The gateway
        streams every response (text/event-stream) regardless of the
        `stream` request param, so this is the lowest-overhead consumer.

        Pass `api_key` to override the instance-level key for this single
        call. Pass `extra_headers`, `idempotency_key`, or `timeout` to
        tune the single request without recreating the client."""
        request_idempotency_key = idempotency_key or _new_idempotency_key()
        attempt = 0
        base_index = 0
        while True:
            req = self._build_chat_request(
                model=model,
                messages=messages,
                api_key=api_key,
                params=params,
                extra_headers=extra_headers,
                idempotency_key=request_idempotency_key,
                timeout=timeout,
                base_url=self._active_inference_base_urls()[base_index],
            )
            response_opened = False
            try:
                with self._client.stream(**req) as response:
                    response_opened = True
                    if response.is_error:
                        if attempt < self.max_retries and _retryable_stream_open_status(
                            response.status_code,
                            regional_failover=self._regional_failover,
                        ):
                            response.read()
                            base_index = self._base_index_after_status(
                                response.status_code, base_index
                            )
                            time.sleep(
                                _retry_sleep(
                                    attempt, retry_after=_retry_after_seconds(response.headers)
                                )
                            )
                            attempt += 1
                            continue
                        _raise_for_stream_response(response)
                    for chunk in _iter_sse_chunks(response):
                        txt = _delta_text(chunk)
                        if txt:
                            yield txt
                    return
            except httpx.TransportError as exc:
                if response_opened or attempt >= self.max_retries:
                    raise _transport_retry_error(exc) from exc
                if base_index < len(self._active_inference_base_urls()) - 1:
                    base_index += 1
                time.sleep(_retry_sleep(attempt, retry_after=None))
                attempt += 1

    def chat_completions_chunk_stream(
        self,
        *,
        model: str,
        messages: list[Mapping[str, Any]],
        api_key: str | None = None,
        extra_headers: Mapping[str, str] | None = None,
        idempotency_key: str | None = None,
        timeout: float | httpx.Timeout | None = None,
        **params: Any,
    ) -> Iterator[ChatCompletionChunk]:
        """Yield parsed OpenAI chat.completion.chunk frames as typed
        ChatCompletionChunk models. Use this when you need access to
        fields beyond the text delta (e.g. `finish_reason`, `model`,
        `id`) — for instance when translating to a different SSE shape."""
        request_idempotency_key = idempotency_key or _new_idempotency_key()
        attempt = 0
        base_index = 0
        while True:
            req = self._build_chat_request(
                model=model,
                messages=messages,
                api_key=api_key,
                params=params,
                extra_headers=extra_headers,
                idempotency_key=request_idempotency_key,
                timeout=timeout,
                base_url=self._active_inference_base_urls()[base_index],
            )
            response_opened = False
            try:
                with self._client.stream(**req) as response:
                    response_opened = True
                    if response.is_error:
                        if attempt < self.max_retries and _retryable_stream_open_status(
                            response.status_code,
                            regional_failover=self._regional_failover,
                        ):
                            response.read()
                            base_index = self._base_index_after_status(
                                response.status_code, base_index
                            )
                            time.sleep(
                                _retry_sleep(
                                    attempt, retry_after=_retry_after_seconds(response.headers)
                                )
                            )
                            attempt += 1
                            continue
                        _raise_for_stream_response(response)
                    for chunk in _iter_sse_chunks(response):
                        yield ChatCompletionChunk.model_validate(chunk)
                    return
            except httpx.TransportError as exc:
                if response_opened or attempt >= self.max_retries:
                    raise _transport_retry_error(exc) from exc
                if base_index < len(self._active_inference_base_urls()) - 1:
                    base_index += 1
                time.sleep(_retry_sleep(attempt, retry_after=None))
                attempt += 1

    def chat_completions(
        self,
        *,
        model: str = AUTO_MODEL,
        messages: list[Mapping[str, Any]],
        api_key: str | None = None,
        extra_headers: Mapping[str, str] | None = None,
        idempotency_key: str | None = None,
        timeout: float | httpx.Timeout | None = None,
        **params: Any,
    ) -> ChatCompletion:
        """Collect the streamed response into a single typed
        ChatCompletion. Use chat_completions_stream() if you want to
        stream tokens to the user instead."""
        request_idempotency_key = idempotency_key or _new_idempotency_key()
        params = _with_usage(params)
        attempt = 0
        base_index = 0
        while True:
            req = self._build_chat_request(
                model=model,
                messages=messages,
                api_key=api_key,
                params=params,
                extra_headers=extra_headers,
                idempotency_key=request_idempotency_key,
                timeout=timeout,
                base_url=self._active_inference_base_urls()[base_index],
            )
            response_opened = False
            try:
                with self._client.stream(**req) as response:
                    response_opened = True
                    if response.is_error:
                        if attempt < self.max_retries and _retryable_stream_open_status(
                            response.status_code,
                            regional_failover=self._regional_failover,
                        ):
                            response.read()
                            base_index = self._base_index_after_status(
                                response.status_code, base_index
                            )
                            time.sleep(
                                _retry_sleep(
                                    attempt, retry_after=_retry_after_seconds(response.headers)
                                )
                            )
                            attempt += 1
                            continue
                        _raise_for_stream_response(response)
                    chunks = list(_iter_sse_chunks(response))
                return ChatCompletion.model_validate(_collect_completion(chunks))
            except httpx.TransportError as exc:
                if response_opened or attempt >= self.max_retries:
                    raise _transport_retry_error(exc) from exc
                if base_index < len(self._active_inference_base_urls()) - 1:
                    base_index += 1
                time.sleep(_retry_sleep(attempt, retry_after=None))
                attempt += 1

    def fusion(
        self,
        *,
        messages: list[Mapping[str, Any]],
        analysis_models: Sequence[str] | None = None,
        model: str | None = None,  # judge / synthesis model
        selection_strategy: str | None = None,
        fallback_judges: Sequence[str] | None = None,
        fallback_final_models: Sequence[str] | None = None,
        max_completion_tokens: int | None = None,
        max_tool_calls: int | None = None,
        preset: str | None = None,
        **params: Any,
    ) -> ChatCompletion:
        """Run a request through TrustedRouter Fusion: fan it across a panel and
        return one answer chosen/synthesized by a judge model. Returns a typed
        ChatCompletion, same as chat_completions. Pass ``fallback_judges`` so a
        single squeamish judge can't sink a prompt."""
        params.setdefault("timeout", DEFAULT_FUSION_TIMEOUT_SECONDS)
        tools = list(params.pop("tools", []))
        tools.append(
            fusion_tool(
                analysis_models=analysis_models,
                model=model,
                selection_strategy=selection_strategy,
                fallback_judges=fallback_judges,
                fallback_final_models=fallback_final_models,
                max_completion_tokens=max_completion_tokens,
                max_tool_calls=max_tool_calls,
                preset=preset,
            )
        )
        return self.chat_completions(model=FUSION_MODEL, messages=messages, tools=tools, **params)

    def models(
        self,
        *,
        open_weights: bool | None = None,
        provider_jurisdiction: str | None = None,
        provider_region: str | None = None,
    ) -> ModelList:
        return ModelList.model_validate(
            self._control_request(
                "GET",
                _models_path(
                    open_weights=open_weights,
                    provider_jurisdiction=provider_jurisdiction,
                    provider_region=provider_region,
                ),
            )
        )

    def providers(self) -> ProviderList:
        return ProviderList.model_validate(self._control_request("GET", "/providers"))

    def regions(self) -> RegionList:
        return RegionList.model_validate(self._control_request("GET", "/regions"))

    def credits(self, *, workspace_id: str | None = None) -> CreditsBalance:
        return CreditsBalance.model_validate(
            self._control_request("GET", "/credits", workspace_id=workspace_id)
        )

    def embeddings(
        self,
        *,
        model: str,
        input: str | list[str] | list[int] | list[list[int]],
        encoding_format: str | None = None,
        dimensions: int | None = None,
        user: str | None = None,
        session_id: str | None = None,
        trace: Mapping[str, Any] | None = None,
        tags: Mapping[str, str] | None = None,
        provider: ProviderPreferences | Mapping[str, Any] | None = None,
    ) -> EmbeddingResponse:
        """OpenAI-compatible embeddings wrapper.

        The hosted TrustedRouter API currently returns a stable
        EndpointNotSupportedError for this route instead of fake vectors.
        The wrapper remains so self-hosted deployments and future hosted
        releases have a typed call site.
        """
        body: dict[str, Any] = {"model": model, "input": input}
        if encoding_format is not None:
            body["encoding_format"] = encoding_format
        if dimensions is not None:
            body["dimensions"] = dimensions
        if user is not None:
            body["user"] = user
        if session_id is not None:
            body["session_id"] = session_id
        if trace is not None:
            body["trace"] = dict(trace)
        if tags is not None:
            body["tags"] = dict(tags)
        if provider is not None:
            body["provider"] = dict(provider)
        return EmbeddingResponse.model_validate(self.request("POST", "/embeddings", json=body))

    def messages(
        self,
        *,
        model: str,
        messages: list[Mapping[str, Any]],
        max_tokens: int = 1024,
        **params: Any,
    ) -> MessagesResponse:
        """Anthropic-shape Messages endpoint. For providers that expose
        the native Anthropic API (rather than translating to/from
        OpenAI shape), this preserves system prompts, content blocks,
        and tool_use semantics that the OpenAI shape can't carry."""
        body: dict[str, Any] = {
            "model": model,
            "messages": messages,
            "max_tokens": max_tokens,
            **params,
        }
        return MessagesResponse.model_validate(self.request("POST", "/messages", json=body))

    def responses(
        self,
        *,
        model: str = AUTO_MODEL,
        input: str | list[Mapping[str, Any]],
        instructions: str | None = None,
        api_key: str | None = None,
        extra_headers: Mapping[str, str] | None = None,
        idempotency_key: str | None = None,
        workspace_id: str | None = None,
        timeout: float | httpx.Timeout | None = None,
        **params: Any,
    ) -> ResponseObject:
        """Create a stateless OpenAI Responses API request."""
        request_idempotency_key = idempotency_key or _new_idempotency_key()
        body = _responses_body(
            model=model,
            input=input,
            instructions=instructions,
            stream=False,
            params=params,
        )
        return ResponseObject.model_validate(
            self.request(
                "POST",
                "/responses",
                json=body,
                headers=extra_headers,
                api_key=api_key,
                workspace_id=workspace_id,
                idempotency_key=request_idempotency_key,
                timeout=timeout,
            )
        )

    def responses_stream(
        self,
        *,
        model: str = AUTO_MODEL,
        input: str | list[Mapping[str, Any]],
        instructions: str | None = None,
        api_key: str | None = None,
        extra_headers: Mapping[str, str] | None = None,
        idempotency_key: str | None = None,
        workspace_id: str | None = None,
        timeout: float | httpx.Timeout | None = None,
        **params: Any,
    ) -> Iterator[dict[str, Any]]:
        """Yield parsed Responses SSE events as dictionaries."""
        request_idempotency_key = idempotency_key or _new_idempotency_key()
        body = _responses_body(
            model=model,
            input=input,
            instructions=instructions,
            stream=True,
            params=params,
        )
        attempt = 0
        base_index = 0
        while True:
            req = _build_stream_request(
                "POST",
                f"{self._active_inference_base_urls()[base_index]}/responses",
                body=body,
                api_key=api_key if api_key is not None else self.api_key,
                extra_headers=extra_headers,
                idempotency_key=request_idempotency_key,
                workspace_id=workspace_id if workspace_id is not None else self.workspace_id,
                timeout=timeout,
            )
            response_opened = False
            try:
                with self._client.stream(**req) as response:
                    response_opened = True
                    if response.is_error:
                        if attempt < self.max_retries and _retryable_stream_open_status(
                            response.status_code,
                            regional_failover=self._regional_failover,
                        ):
                            response.read()
                            base_index = self._base_index_after_status(
                                response.status_code, base_index
                            )
                            time.sleep(
                                _retry_sleep(
                                    attempt, retry_after=_retry_after_seconds(response.headers)
                                )
                            )
                            attempt += 1
                            continue
                        _raise_for_stream_response(response)
                    yield from _iter_sse_events(response)
                    return
            except httpx.TransportError as exc:
                if response_opened or attempt >= self.max_retries:
                    raise _transport_retry_error(exc) from exc
                if base_index < len(self._active_inference_base_urls()) - 1:
                    base_index += 1
                time.sleep(_retry_sleep(attempt, retry_after=None))
                attempt += 1

    def responses_raw_stream(
        self,
        *,
        model: str = AUTO_MODEL,
        input: str | list[Mapping[str, Any]],
        instructions: str | None = None,
        api_key: str | None = None,
        extra_headers: Mapping[str, str] | None = None,
        idempotency_key: str | None = None,
        workspace_id: str | None = None,
        timeout: float | httpx.Timeout | None = None,
        **params: Any,
    ) -> Iterator[bytes]:
        request_idempotency_key = idempotency_key or _new_idempotency_key()
        body = _responses_body(
            model=model,
            input=input,
            instructions=instructions,
            stream=True,
            params=params,
        )
        attempt = 0
        base_index = 0
        while True:
            req = _build_stream_request(
                "POST",
                f"{self._active_inference_base_urls()[base_index]}/responses",
                body=body,
                api_key=api_key if api_key is not None else self.api_key,
                extra_headers=extra_headers,
                idempotency_key=request_idempotency_key,
                workspace_id=workspace_id if workspace_id is not None else self.workspace_id,
                timeout=timeout,
            )
            response_opened = False
            try:
                with self._client.stream(**req) as response:
                    response_opened = True
                    if response.is_error:
                        if attempt < self.max_retries and _retryable_stream_open_status(
                            response.status_code,
                            regional_failover=self._regional_failover,
                        ):
                            response.read()
                            base_index = self._base_index_after_status(
                                response.status_code, base_index
                            )
                            time.sleep(
                                _retry_sleep(
                                    attempt, retry_after=_retry_after_seconds(response.headers)
                                )
                            )
                            attempt += 1
                            continue
                        _raise_for_stream_response(response)
                    yield from response.iter_bytes()
                    return
            except httpx.TransportError as exc:
                if response_opened or attempt >= self.max_retries:
                    raise _transport_retry_error(exc) from exc
                if base_index < len(self._active_inference_base_urls()) - 1:
                    base_index += 1
                time.sleep(_retry_sleep(attempt, retry_after=None))
                attempt += 1

    def responses_input_tokens(
        self,
        *,
        model: str = AUTO_MODEL,
        input: str | list[Mapping[str, Any]],
        instructions: str | None = None,
        workspace_id: str | None = None,
        **params: Any,
    ) -> ResponseInputTokens:
        body = _responses_body(
            model=model,
            input=input,
            instructions=instructions,
            stream=False,
            params=params,
        )
        return ResponseInputTokens.model_validate(
            self.request(
                "POST",
                "/responses/input_tokens",
                json=body,
                workspace_id=workspace_id,
            )
        )

    def billing_checkout(
        self,
        *,
        amount: int | str,
        payment_method: str | None = None,
        workspace_id: str | None = None,
        success_url: str | None = None,
        cancel_url: str | None = None,
        idempotency_key: str | None = None,
    ) -> CheckoutSession:
        """Create a Stripe checkout session. Pass `idempotency_key=` to
        guarantee at-most-once charge semantics across network retries
        — strongly recommended for production."""
        body: dict[str, Any] = {"amount": amount}
        if payment_method is not None:
            body["payment_method"] = payment_method
        if workspace_id is not None:
            body["workspace_id"] = workspace_id
        if success_url is not None:
            body["success_url"] = success_url
        if cancel_url is not None:
            body["cancel_url"] = cancel_url
        return CheckoutSession.model_validate(
            self._control_request(
                "POST",
                "/billing/checkout",
                json=body,
                workspace_id=workspace_id,
                idempotency_key=idempotency_key,
            )
        )

    def stablecoin_checkout(self, *, amount: int | str, **params: Any) -> CheckoutSession:
        return self.billing_checkout(amount=amount, payment_method="stablecoin", **params)

    def auth_session(self) -> AuthSession:
        return AuthSession.model_validate(self._control_request("GET", "/auth/session"))

    def logout(self) -> LogoutResponse:
        return LogoutResponse.model_validate(self._control_request("POST", "/auth/logout"))

    def activity(self, **params: Any) -> ActivityList:
        """List recent generations for the authenticated key/workspace.
        Pass any subset of {since, until, limit, model, workspace_id};
        None values are dropped from the query string."""
        query = httpx.QueryParams({k: v for k, v in params.items() if v is not None})
        suffix = f"?{query}" if query else ""
        return ActivityList.model_validate(self._control_request("GET", f"/activity{suffix}"))

    def broadcast_destinations(self, *, workspace_id: str | None = None) -> dict[str, Any]:
        return self._control_request("GET", "/broadcast/destinations", workspace_id=workspace_id)

    def create_broadcast_destination(
        self,
        *,
        type: str,
        name: str = "Broadcast destination",
        endpoint: str | None = None,
        enabled: bool = True,
        include_content: bool = False,
        method: str = "POST",
        headers: Mapping[str, str] | None = None,
        api_key: str | None = None,
        workspace_id: str | None = None,
    ) -> dict[str, Any]:
        body = _broadcast_destination_body(
            type=type,
            name=name,
            endpoint=endpoint,
            enabled=enabled,
            include_content=include_content,
            method=method,
            headers=headers,
            api_key=api_key,
        )
        return self._control_request(
            "POST", "/broadcast/destinations", json=body, workspace_id=workspace_id
        )

    def get_broadcast_destination(
        self,
        destination_id: str,
        *,
        workspace_id: str | None = None,
    ) -> dict[str, Any]:
        return self._control_request(
            "GET",
            f"/broadcast/destinations/{destination_id}",
            workspace_id=workspace_id,
        )

    def update_broadcast_destination(
        self,
        destination_id: str,
        *,
        workspace_id: str | None = None,
        **patch: Any,
    ) -> dict[str, Any]:
        return self._control_request(
            "PATCH",
            f"/broadcast/destinations/{destination_id}",
            json={key: value for key, value in patch.items() if value is not None},
            workspace_id=workspace_id,
        )

    def delete_broadcast_destination(
        self,
        destination_id: str,
        *,
        workspace_id: str | None = None,
    ) -> dict[str, Any]:
        return self._control_request(
            "DELETE",
            f"/broadcast/destinations/{destination_id}",
            workspace_id=workspace_id,
        )

    def test_broadcast_destination(
        self,
        destination_id: str,
        *,
        workspace_id: str | None = None,
    ) -> dict[str, Any]:
        return self._control_request(
            "POST",
            f"/broadcast/destinations/{destination_id}/test",
            workspace_id=workspace_id,
        )

    def status(self, url: str = DEFAULT_STATUS_URL) -> dict[str, Any]:
        response = self._client.get(url)
        return _json_or_raise(response)

    def attestation(self) -> bytes:
        """Fetch the gateway's live attestation document. Returns the raw
        JWT bytes (Confidential Space mints an OIDC JWT). Pass to
        `trustedrouter.attestation.verify_gateway_attestation` to verify."""
        # /attestation lives at the API root, not under /v1
        url = self.base_url.rsplit("/v1", 1)[0] + "/attestation"
        response = self._client.get(url)
        if response.is_error:
            raise TrustedRouterError(response.status_code, response.text[:240])
        return response.content

    def trust_release(self, url: str = DEFAULT_TRUST_RELEASE_URL) -> TrustRelease:
        response = self._client.get(url)
        return TrustRelease.model_validate(_json_or_raise(response))


# ---- async client --------------------------------------------------------


class AsyncTrustedRouter:
    """Async variant. Same surface as TrustedRouter but every method is a
    coroutine, and the streaming helpers return AsyncIterators. Used by
    asyncio servers (e.g. the Pi's quill-device FastAPI app) so they
    don't block the event loop on a streaming generation call."""

    def __init__(
        self,
        api_key: str | None = None,
        *,
        base_url: str | None = None,
        control_base_url: str | None = None,
        timeout: float = DEFAULT_REQUEST_TIMEOUT_SECONDS,
        headers: Mapping[str, str] | None = None,
        verify: bool | str = True,
        workspace_id: str | None = None,
        client: httpx.AsyncClient | None = None,
        max_retries: int = 2,
        regional_failover: bool = True,
        regional_affinity: bool | None = None,
        region_probe_timeout: float = DEFAULT_REGION_PROBE_TIMEOUT_SECONDS,
    ) -> None:
        """Async TrustedRouter client.

        The default client probes regional liveness endpoints once and stays
        pinned to the fastest healthy region. Custom `base_url` clients are
        never probed or rewritten.
        """
        use_regional_affinity = base_url is None and (
            client is None if regional_affinity is None else regional_affinity
        )
        if base_url is None:
            base_url = DEFAULT_API_BASE_URL
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.control_base_url = (control_base_url or DEFAULT_CONTROL_BASE_URL).rstrip("/")
        self.workspace_id = workspace_id
        self.max_retries = max(0, int(max_retries))
        self._regional_failover = bool(regional_failover)
        self._base_urls = _inference_base_urls(self.base_url)
        self._regional_affinity_pending = bool(use_regional_affinity and self._regional_failover)
        self._region_probe_timeout = max(0.1, float(region_probe_timeout))
        self._region_lock = asyncio.Lock()
        default_headers = {"user-agent": _DEFAULT_USER_AGENT}
        if headers:
            default_headers.update(headers)
        if client is not None:
            # Caller is responsible for the client's lifecycle (timeouts,
            # transport, verify, event hooks for cert pinning, etc.).
            # aclose() becomes a no-op.
            self._client = client
            self._owns_client = False
        else:
            self._client = httpx.AsyncClient(
                timeout=timeout, headers=default_headers, verify=verify
            )
            self._owns_client = True
        self._region_client_identity = id(self._client)

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    async def __aenter__(self) -> AsyncTrustedRouter:
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.aclose()

    async def _active_inference_base_urls(self) -> list[str]:
        if id(self._client) != self._region_client_identity:
            self._regional_affinity_pending = False
        if not self._regional_affinity_pending:
            return self._base_urls
        async with self._region_lock:
            if self._regional_affinity_pending:
                self._base_urls = await _select_regions_async(
                    self._client,
                    self.base_url,
                    timeout_seconds=self._region_probe_timeout,
                )
                self._regional_affinity_pending = False
        return self._base_urls

    async def _base_index_after_status(self, status_code: int, base_index: int) -> int:
        base_urls = await self._active_inference_base_urls()
        if (
            self._regional_failover
            and _regional_failoverable(status_code)
            and base_index < len(base_urls) - 1
        ):
            return base_index + 1
        return base_index

    async def request(
        self,
        method: str,
        path: str,
        *,
        json: Mapping[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
        api_key: str | None = None,
        workspace_id: str | None = None,
        idempotency_key: str | None = None,
        timeout: float | httpx.Timeout | None = None,
        _base_url: str | None = None,
    ) -> dict[str, Any]:
        if (
            idempotency_key is None
            and _base_url is None
            and method.upper() not in {"GET", "HEAD", "OPTIONS"}
        ):
            idempotency_key = _new_idempotency_key()
        merged_headers: dict[str, str] = {"user-agent": _DEFAULT_USER_AGENT}
        if headers:
            merged_headers.update(headers)
        if idempotency_key:
            merged_headers["idempotency-key"] = idempotency_key
        selected_workspace_id = workspace_id if workspace_id is not None else self.workspace_id
        if selected_workspace_id:
            merged_headers["x-trustedrouter-workspace"] = selected_workspace_id
        selected_api_key = api_key if api_key is not None else self.api_key
        if selected_api_key:
            merged_headers["authorization"] = f"Bearer {selected_api_key}"
        kwargs: dict[str, Any] = {"json": json, "headers": merged_headers}
        if timeout is not None:
            kwargs["timeout"] = timeout
        base_urls = (
            [_base_url.rstrip("/")]
            if _base_url is not None
            else await self._active_inference_base_urls()
        )
        attempt = 0
        base_index = 0
        while True:
            url = f"{base_urls[base_index]}/{path.lstrip('/')}"
            try:
                response = await self._client.request(method, url, **kwargs)
            except httpx.TransportError as exc:
                if attempt >= self.max_retries:
                    raise _transport_retry_error(exc) from exc
                if base_index < len(base_urls) - 1:
                    base_index += 1
                await asyncio.sleep(_retry_sleep(attempt, retry_after=None))
                attempt += 1
                continue
            if attempt >= self.max_retries or not _retryable(response.status_code):
                return _json_or_raise(response)
            if _regional_failoverable(response.status_code) and base_index < len(base_urls) - 1:
                base_index += 1
            await asyncio.sleep(
                _retry_sleep(attempt, retry_after=_retry_after_seconds(response.headers))
            )
            attempt += 1

    async def _control_request(
        self,
        method: str,
        path: str,
        **kwargs: Any,
    ) -> dict[str, Any]:
        return await self.request(method, path, _base_url=self.control_base_url, **kwargs)

    def _build_chat_request(
        self,
        *,
        model: str,
        messages: list[Mapping[str, Any]],
        api_key: str | None,
        params: Mapping[str, Any],
        extra_headers: Mapping[str, str] | None = None,
        idempotency_key: str | None = None,
        timeout: float | httpx.Timeout | None = None,
        base_url: str | None = None,
    ) -> dict[str, Any]:
        # Pull our reserved kwargs out of `params` so they aren't sent
        # into the JSON body. (Defensive: callers spreading a dict
        # might inadvertently include these.)
        params_dict = dict(params)
        workspace_id = params_dict.pop("workspace_id", None)
        for reserved in ("extra_headers", "idempotency_key", "timeout", "api_key"):
            params_dict.pop(reserved, None)
        params_dict = _move_orchestration_options_into_tools(model, params_dict)
        body = {"model": model, "messages": messages, "stream": True, **params_dict}
        return _build_stream_request(
            "POST",
            f"{(base_url or self.base_url).rstrip('/')}/chat/completions",
            body=body,
            api_key=api_key if api_key is not None else self.api_key,
            extra_headers=extra_headers,
            idempotency_key=idempotency_key,
            workspace_id=workspace_id if workspace_id is not None else self.workspace_id,
            timeout=timeout,
        )

    async def chat_completions_stream(
        self,
        *,
        model: str,
        messages: list[Mapping[str, Any]],
        api_key: str | None = None,
        extra_headers: Mapping[str, str] | None = None,
        idempotency_key: str | None = None,
        timeout: float | httpx.Timeout | None = None,
        **params: Any,
    ) -> AsyncIterator[str]:
        """Yield assistant-message text deltas as they arrive. Pass
        `api_key` to override the instance key for this single call."""
        request_idempotency_key = idempotency_key or _new_idempotency_key()
        attempt = 0
        base_index = 0
        while True:
            req = self._build_chat_request(
                model=model,
                messages=messages,
                api_key=api_key,
                params=params,
                extra_headers=extra_headers,
                idempotency_key=request_idempotency_key,
                timeout=timeout,
                base_url=(await self._active_inference_base_urls())[base_index],
            )
            response_opened = False
            try:
                async with self._client.stream(**req) as response:
                    response_opened = True
                    if response.is_error:
                        if attempt < self.max_retries and _retryable_stream_open_status(
                            response.status_code,
                            regional_failover=self._regional_failover,
                        ):
                            await response.aread()
                            base_index = await self._base_index_after_status(
                                response.status_code, base_index
                            )
                            await asyncio.sleep(
                                _retry_sleep(
                                    attempt, retry_after=_retry_after_seconds(response.headers)
                                )
                            )
                            attempt += 1
                            continue
                        await _araise_for_stream_response(response)
                    async for chunk in _aiter_sse_chunks(response):
                        txt = _delta_text(chunk)
                        if txt:
                            yield txt
                    return
            except httpx.TransportError as exc:
                if response_opened or attempt >= self.max_retries:
                    raise _transport_retry_error(exc) from exc
                if base_index < len(await self._active_inference_base_urls()) - 1:
                    base_index += 1
                await asyncio.sleep(_retry_sleep(attempt, retry_after=None))
                attempt += 1

    async def chat_completions_chunk_stream(
        self,
        *,
        model: str,
        messages: list[Mapping[str, Any]],
        api_key: str | None = None,
        extra_headers: Mapping[str, str] | None = None,
        idempotency_key: str | None = None,
        timeout: float | httpx.Timeout | None = None,
        **params: Any,
    ) -> AsyncIterator[ChatCompletionChunk]:
        """Yield parsed OpenAI chat.completion.chunk frames as typed
        ChatCompletionChunk models."""
        request_idempotency_key = idempotency_key or _new_idempotency_key()
        attempt = 0
        base_index = 0
        while True:
            req = self._build_chat_request(
                model=model,
                messages=messages,
                api_key=api_key,
                params=params,
                extra_headers=extra_headers,
                idempotency_key=request_idempotency_key,
                timeout=timeout,
                base_url=(await self._active_inference_base_urls())[base_index],
            )
            response_opened = False
            try:
                async with self._client.stream(**req) as response:
                    response_opened = True
                    if response.is_error:
                        if attempt < self.max_retries and _retryable_stream_open_status(
                            response.status_code,
                            regional_failover=self._regional_failover,
                        ):
                            await response.aread()
                            base_index = await self._base_index_after_status(
                                response.status_code, base_index
                            )
                            await asyncio.sleep(
                                _retry_sleep(
                                    attempt, retry_after=_retry_after_seconds(response.headers)
                                )
                            )
                            attempt += 1
                            continue
                        await _araise_for_stream_response(response)
                    async for chunk in _aiter_sse_chunks(response):
                        yield ChatCompletionChunk.model_validate(chunk)
                    return
            except httpx.TransportError as exc:
                if response_opened or attempt >= self.max_retries:
                    raise _transport_retry_error(exc) from exc
                if base_index < len(await self._active_inference_base_urls()) - 1:
                    base_index += 1
                await asyncio.sleep(_retry_sleep(attempt, retry_after=None))
                attempt += 1

    async def chat_completions_raw_stream(
        self,
        *,
        model: str,
        messages: list[Mapping[str, Any]],
        api_key: str | None = None,
        extra_headers: Mapping[str, str] | None = None,
        idempotency_key: str | None = None,
        timeout: float | httpx.Timeout | None = None,
        **params: Any,
    ) -> AsyncIterator[bytes]:
        """Pass-through SSE bytes. For relays that need to forward the
        raw `data: {...}\\n\\n` framing without decoding (e.g. an HTTP
        proxy in front of the gateway)."""
        request_idempotency_key = idempotency_key or _new_idempotency_key()
        attempt = 0
        base_index = 0
        while True:
            req = self._build_chat_request(
                model=model,
                messages=messages,
                api_key=api_key,
                params=params,
                extra_headers=extra_headers,
                idempotency_key=request_idempotency_key,
                timeout=timeout,
                base_url=(await self._active_inference_base_urls())[base_index],
            )
            response_opened = False
            try:
                async with self._client.stream(**req) as response:
                    response_opened = True
                    if response.is_error:
                        if attempt < self.max_retries and _retryable_stream_open_status(
                            response.status_code,
                            regional_failover=self._regional_failover,
                        ):
                            await response.aread()
                            base_index = await self._base_index_after_status(
                                response.status_code, base_index
                            )
                            await asyncio.sleep(
                                _retry_sleep(
                                    attempt, retry_after=_retry_after_seconds(response.headers)
                                )
                            )
                            attempt += 1
                            continue
                        await _araise_for_stream_response(response)
                    async for chunk in response.aiter_bytes():
                        yield chunk
                    return
            except httpx.TransportError as exc:
                if response_opened or attempt >= self.max_retries:
                    raise _transport_retry_error(exc) from exc
                if base_index < len(await self._active_inference_base_urls()) - 1:
                    base_index += 1
                await asyncio.sleep(_retry_sleep(attempt, retry_after=None))
                attempt += 1

    async def chat_completions(
        self,
        *,
        model: str = AUTO_MODEL,
        messages: list[Mapping[str, Any]],
        api_key: str | None = None,
        extra_headers: Mapping[str, str] | None = None,
        idempotency_key: str | None = None,
        timeout: float | httpx.Timeout | None = None,
        **params: Any,
    ) -> ChatCompletion:
        request_idempotency_key = idempotency_key or _new_idempotency_key()
        params = _with_usage(params)
        attempt = 0
        base_index = 0
        while True:
            req = self._build_chat_request(
                model=model,
                messages=messages,
                api_key=api_key,
                params=params,
                extra_headers=extra_headers,
                idempotency_key=request_idempotency_key,
                timeout=timeout,
                base_url=(await self._active_inference_base_urls())[base_index],
            )
            chunks: list[dict[str, Any]] = []
            response_opened = False
            try:
                async with self._client.stream(**req) as response:
                    response_opened = True
                    if response.is_error:
                        if attempt < self.max_retries and _retryable_stream_open_status(
                            response.status_code,
                            regional_failover=self._regional_failover,
                        ):
                            await response.aread()
                            base_index = await self._base_index_after_status(
                                response.status_code, base_index
                            )
                            await asyncio.sleep(
                                _retry_sleep(
                                    attempt, retry_after=_retry_after_seconds(response.headers)
                                )
                            )
                            attempt += 1
                            continue
                        await _araise_for_stream_response(response)
                    async for chunk in _aiter_sse_chunks(response):
                        chunks.append(chunk)
                return ChatCompletion.model_validate(_collect_completion(chunks))
            except httpx.TransportError as exc:
                if response_opened or attempt >= self.max_retries:
                    raise _transport_retry_error(exc) from exc
                if base_index < len(await self._active_inference_base_urls()) - 1:
                    base_index += 1
                await asyncio.sleep(_retry_sleep(attempt, retry_after=None))
                attempt += 1

    async def fusion(
        self,
        *,
        messages: list[Mapping[str, Any]],
        analysis_models: Sequence[str] | None = None,
        model: str | None = None,  # judge / synthesis model
        selection_strategy: str | None = None,
        fallback_judges: Sequence[str] | None = None,
        fallback_final_models: Sequence[str] | None = None,
        max_completion_tokens: int | None = None,
        max_tool_calls: int | None = None,
        preset: str | None = None,
        **params: Any,
    ) -> ChatCompletion:
        """Async TrustedRouter Fusion — mirror of TrustedRouter.fusion."""
        params.setdefault("timeout", DEFAULT_FUSION_TIMEOUT_SECONDS)
        tools = list(params.pop("tools", []))
        tools.append(
            fusion_tool(
                analysis_models=analysis_models,
                model=model,
                selection_strategy=selection_strategy,
                fallback_judges=fallback_judges,
                fallback_final_models=fallback_final_models,
                max_completion_tokens=max_completion_tokens,
                max_tool_calls=max_tool_calls,
                preset=preset,
            )
        )
        return await self.chat_completions(
            model=FUSION_MODEL, messages=messages, tools=tools, **params
        )

    async def models(
        self,
        *,
        open_weights: bool | None = None,
        provider_jurisdiction: str | None = None,
        provider_region: str | None = None,
    ) -> ModelList:
        return ModelList.model_validate(
            await self._control_request(
                "GET",
                _models_path(
                    open_weights=open_weights,
                    provider_jurisdiction=provider_jurisdiction,
                    provider_region=provider_region,
                ),
            )
        )

    async def providers(self) -> ProviderList:
        return ProviderList.model_validate(await self._control_request("GET", "/providers"))

    async def regions(self) -> RegionList:
        return RegionList.model_validate(await self._control_request("GET", "/regions"))

    async def credits(self, *, workspace_id: str | None = None) -> CreditsBalance:
        return CreditsBalance.model_validate(
            await self._control_request("GET", "/credits", workspace_id=workspace_id)
        )

    async def embeddings(
        self,
        *,
        model: str,
        input: str | list[str] | list[int] | list[list[int]],
        encoding_format: str | None = None,
        dimensions: int | None = None,
        user: str | None = None,
        session_id: str | None = None,
        trace: Mapping[str, Any] | None = None,
        tags: Mapping[str, str] | None = None,
        provider: ProviderPreferences | Mapping[str, Any] | None = None,
    ) -> EmbeddingResponse:
        body: dict[str, Any] = {"model": model, "input": input}
        if encoding_format is not None:
            body["encoding_format"] = encoding_format
        if dimensions is not None:
            body["dimensions"] = dimensions
        if user is not None:
            body["user"] = user
        if session_id is not None:
            body["session_id"] = session_id
        if trace is not None:
            body["trace"] = dict(trace)
        if tags is not None:
            body["tags"] = dict(tags)
        if provider is not None:
            body["provider"] = dict(provider)
        return EmbeddingResponse.model_validate(
            await self.request("POST", "/embeddings", json=body)
        )

    async def messages(
        self,
        *,
        model: str,
        messages: list[Mapping[str, Any]],
        max_tokens: int = 1024,
        **params: Any,
    ) -> MessagesResponse:
        body: dict[str, Any] = {
            "model": model,
            "messages": messages,
            "max_tokens": max_tokens,
            **params,
        }
        return MessagesResponse.model_validate(await self.request("POST", "/messages", json=body))

    async def responses(
        self,
        *,
        model: str = AUTO_MODEL,
        input: str | list[Mapping[str, Any]],
        instructions: str | None = None,
        api_key: str | None = None,
        extra_headers: Mapping[str, str] | None = None,
        idempotency_key: str | None = None,
        workspace_id: str | None = None,
        timeout: float | httpx.Timeout | None = None,
        **params: Any,
    ) -> ResponseObject:
        request_idempotency_key = idempotency_key or _new_idempotency_key()
        body = _responses_body(
            model=model,
            input=input,
            instructions=instructions,
            stream=False,
            params=params,
        )
        return ResponseObject.model_validate(
            await self.request(
                "POST",
                "/responses",
                json=body,
                headers=extra_headers,
                api_key=api_key,
                workspace_id=workspace_id,
                idempotency_key=request_idempotency_key,
                timeout=timeout,
            )
        )

    async def responses_stream(
        self,
        *,
        model: str = AUTO_MODEL,
        input: str | list[Mapping[str, Any]],
        instructions: str | None = None,
        api_key: str | None = None,
        extra_headers: Mapping[str, str] | None = None,
        idempotency_key: str | None = None,
        workspace_id: str | None = None,
        timeout: float | httpx.Timeout | None = None,
        **params: Any,
    ) -> AsyncIterator[dict[str, Any]]:
        request_idempotency_key = idempotency_key or _new_idempotency_key()
        body = _responses_body(
            model=model,
            input=input,
            instructions=instructions,
            stream=True,
            params=params,
        )
        attempt = 0
        base_index = 0
        while True:
            req = _build_stream_request(
                "POST",
                f"{(await self._active_inference_base_urls())[base_index]}/responses",
                body=body,
                api_key=api_key if api_key is not None else self.api_key,
                extra_headers=extra_headers,
                idempotency_key=request_idempotency_key,
                workspace_id=workspace_id if workspace_id is not None else self.workspace_id,
                timeout=timeout,
            )
            response_opened = False
            try:
                async with self._client.stream(**req) as response:
                    response_opened = True
                    if response.is_error:
                        if attempt < self.max_retries and _retryable_stream_open_status(
                            response.status_code,
                            regional_failover=self._regional_failover,
                        ):
                            await response.aread()
                            base_index = await self._base_index_after_status(
                                response.status_code, base_index
                            )
                            await asyncio.sleep(
                                _retry_sleep(
                                    attempt, retry_after=_retry_after_seconds(response.headers)
                                )
                            )
                            attempt += 1
                            continue
                        await _araise_for_stream_response(response)
                    async for event in _aiter_sse_events(response):
                        yield event
                    return
            except httpx.TransportError as exc:
                if response_opened or attempt >= self.max_retries:
                    raise _transport_retry_error(exc) from exc
                if base_index < len(await self._active_inference_base_urls()) - 1:
                    base_index += 1
                await asyncio.sleep(_retry_sleep(attempt, retry_after=None))
                attempt += 1

    async def responses_raw_stream(
        self,
        *,
        model: str = AUTO_MODEL,
        input: str | list[Mapping[str, Any]],
        instructions: str | None = None,
        api_key: str | None = None,
        extra_headers: Mapping[str, str] | None = None,
        idempotency_key: str | None = None,
        workspace_id: str | None = None,
        timeout: float | httpx.Timeout | None = None,
        **params: Any,
    ) -> AsyncIterator[bytes]:
        request_idempotency_key = idempotency_key or _new_idempotency_key()
        body = _responses_body(
            model=model,
            input=input,
            instructions=instructions,
            stream=True,
            params=params,
        )
        attempt = 0
        base_index = 0
        while True:
            req = _build_stream_request(
                "POST",
                f"{(await self._active_inference_base_urls())[base_index]}/responses",
                body=body,
                api_key=api_key if api_key is not None else self.api_key,
                extra_headers=extra_headers,
                idempotency_key=request_idempotency_key,
                workspace_id=workspace_id if workspace_id is not None else self.workspace_id,
                timeout=timeout,
            )
            response_opened = False
            try:
                async with self._client.stream(**req) as response:
                    response_opened = True
                    if response.is_error:
                        if attempt < self.max_retries and _retryable_stream_open_status(
                            response.status_code,
                            regional_failover=self._regional_failover,
                        ):
                            await response.aread()
                            base_index = await self._base_index_after_status(
                                response.status_code, base_index
                            )
                            await asyncio.sleep(
                                _retry_sleep(
                                    attempt, retry_after=_retry_after_seconds(response.headers)
                                )
                            )
                            attempt += 1
                            continue
                        await _araise_for_stream_response(response)
                    async for chunk in response.aiter_bytes():
                        yield chunk
                    return
            except httpx.TransportError as exc:
                if response_opened or attempt >= self.max_retries:
                    raise _transport_retry_error(exc) from exc
                if base_index < len(await self._active_inference_base_urls()) - 1:
                    base_index += 1
                await asyncio.sleep(_retry_sleep(attempt, retry_after=None))
                attempt += 1

    async def responses_input_tokens(
        self,
        *,
        model: str = AUTO_MODEL,
        input: str | list[Mapping[str, Any]],
        instructions: str | None = None,
        workspace_id: str | None = None,
        **params: Any,
    ) -> ResponseInputTokens:
        body = _responses_body(
            model=model,
            input=input,
            instructions=instructions,
            stream=False,
            params=params,
        )
        return ResponseInputTokens.model_validate(
            await self.request(
                "POST",
                "/responses/input_tokens",
                json=body,
                workspace_id=workspace_id,
            )
        )

    async def billing_checkout(
        self,
        *,
        amount: int | str,
        payment_method: str | None = None,
        workspace_id: str | None = None,
        success_url: str | None = None,
        cancel_url: str | None = None,
        idempotency_key: str | None = None,
    ) -> CheckoutSession:
        body: dict[str, Any] = {"amount": amount}
        if payment_method is not None:
            body["payment_method"] = payment_method
        if workspace_id is not None:
            body["workspace_id"] = workspace_id
        if success_url is not None:
            body["success_url"] = success_url
        if cancel_url is not None:
            body["cancel_url"] = cancel_url
        return CheckoutSession.model_validate(
            await self._control_request(
                "POST",
                "/billing/checkout",
                json=body,
                workspace_id=workspace_id,
                idempotency_key=idempotency_key,
            )
        )

    async def stablecoin_checkout(self, *, amount: int | str, **params: Any) -> CheckoutSession:
        return await self.billing_checkout(amount=amount, payment_method="stablecoin", **params)

    async def auth_session(self) -> AuthSession:
        return AuthSession.model_validate(await self._control_request("GET", "/auth/session"))

    async def logout(self) -> LogoutResponse:
        return LogoutResponse.model_validate(await self._control_request("POST", "/auth/logout"))

    async def activity(self, **params: Any) -> ActivityList:
        query = httpx.QueryParams({k: v for k, v in params.items() if v is not None})
        suffix = f"?{query}" if query else ""
        return ActivityList.model_validate(await self._control_request("GET", f"/activity{suffix}"))

    async def broadcast_destinations(self, *, workspace_id: str | None = None) -> dict[str, Any]:
        return await self._control_request(
            "GET", "/broadcast/destinations", workspace_id=workspace_id
        )

    async def create_broadcast_destination(
        self,
        *,
        type: str,
        name: str = "Broadcast destination",
        endpoint: str | None = None,
        enabled: bool = True,
        include_content: bool = False,
        method: str = "POST",
        headers: Mapping[str, str] | None = None,
        api_key: str | None = None,
        workspace_id: str | None = None,
    ) -> dict[str, Any]:
        body = _broadcast_destination_body(
            type=type,
            name=name,
            endpoint=endpoint,
            enabled=enabled,
            include_content=include_content,
            method=method,
            headers=headers,
            api_key=api_key,
        )
        return await self._control_request(
            "POST",
            "/broadcast/destinations",
            json=body,
            workspace_id=workspace_id,
        )

    async def get_broadcast_destination(
        self,
        destination_id: str,
        *,
        workspace_id: str | None = None,
    ) -> dict[str, Any]:
        return await self._control_request(
            "GET",
            f"/broadcast/destinations/{destination_id}",
            workspace_id=workspace_id,
        )

    async def update_broadcast_destination(
        self,
        destination_id: str,
        *,
        workspace_id: str | None = None,
        **patch: Any,
    ) -> dict[str, Any]:
        return await self._control_request(
            "PATCH",
            f"/broadcast/destinations/{destination_id}",
            json={key: value for key, value in patch.items() if value is not None},
            workspace_id=workspace_id,
        )

    async def delete_broadcast_destination(
        self,
        destination_id: str,
        *,
        workspace_id: str | None = None,
    ) -> dict[str, Any]:
        return await self._control_request(
            "DELETE",
            f"/broadcast/destinations/{destination_id}",
            workspace_id=workspace_id,
        )

    async def test_broadcast_destination(
        self,
        destination_id: str,
        *,
        workspace_id: str | None = None,
    ) -> dict[str, Any]:
        return await self._control_request(
            "POST",
            f"/broadcast/destinations/{destination_id}/test",
            workspace_id=workspace_id,
        )

    async def status(self, url: str = DEFAULT_STATUS_URL) -> dict[str, Any]:
        response = await self._client.get(url)
        return _json_or_raise(response)

    async def attestation(self) -> bytes:
        url = self.base_url.rsplit("/v1", 1)[0] + "/attestation"
        response = await self._client.get(url)
        if response.is_error:
            raise TrustedRouterError(response.status_code, response.text[:240])
        return response.content


def fetch_trust_release(
    url: str = DEFAULT_TRUST_RELEASE_URL,
    *,
    timeout: float = 30.0,
) -> TrustRelease:
    """Fetch and parse the public trust release. Returns a typed
    `TrustRelease` model (use `.model_dump()` if you need a dict)."""
    with httpx.Client(timeout=timeout) as client:
        return TrustRelease.model_validate(_json_or_raise(client.get(url)))


def _json_or_raise(response: httpx.Response) -> dict[str, Any]:
    retry_after = _retry_after_seconds(response.headers)
    try:
        payload = response.json()
    except ValueError as exc:
        if response.is_error:
            raise _classify_error(
                response.status_code,
                response.text[:240],
                payload=None,
                retry_after=retry_after,
            ) from exc
        raise
    if response.is_error:
        message = _error_message(payload)
        raise _classify_error(
            response.status_code, message, payload=payload, retry_after=retry_after
        )
    if not isinstance(payload, dict):
        raise TrustedRouterError(response.status_code, "Expected JSON object", payload=payload)
    return payload


def _error_message(payload: Any) -> str:
    if isinstance(payload, dict):
        error = payload.get("error")
        if isinstance(error, dict):
            return str(error.get("message") or error.get("type") or "TrustedRouter error")
        if payload.get("message"):
            return str(payload["message"])
    return "TrustedRouter error"
