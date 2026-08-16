from __future__ import annotations

import pytest

from trustedrouter import (
    CONFIDENTIAL_MODEL,
    E2E_MODEL,
    MAP_REDUCE_MODEL,
    SELECTOR_MODEL,
    SUBAGENT_MODEL,
    SYNTH_MODEL,
    US_MODEL,
    ZDR_MODEL,
    InternalError,
    ProviderPreferences,
    advisor_tool,
    fusion_tool,
    map_reduce_tool,
    selector_tool,
    subagent_tool,
)
from trustedrouter._constants import (
    DEFAULT_TELEMETRY_PATH,
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


def test_client_telemetry_contract_constants() -> None:
    assert TELEMETRY_SCHEMA_VERSION == 1
    assert DEFAULT_TELEMETRY_PATH == "/client-events"
    assert TELEMETRY_FLUSH_SECONDS == 30.0
    assert TELEMETRY_MAX_EVENTS == 1000
    assert TELEMETRY_MAX_BATCH_EVENTS == 100
    assert TELEMETRY_MAX_BATCH_COUNTERS == 200
    assert TELEMETRY_MAX_WINDOW_KEYS == 256
    assert TELEMETRY_RETENTION_SECONDS == 86_400
    assert TELEMETRY_RETENTION_BYTES == 524_288
    assert TELEMETRY_BACKOFF_MIN_SECONDS == 60.0
    assert TELEMETRY_BACKOFF_MAX_SECONDS == 600.0
    assert TELEMETRY_HOSTS == (
        "apex",
        "ally",
        "uptime",
        "us_central1",
        "us_east4",
        "europe_west4",
        "control",
        "custom",
    )
    assert TELEMETRY_ENDPOINTS == (
        "chat_completions",
        "messages",
        "responses",
        "embeddings",
        "images",
        "videos",
        "models",
        "fusion",
        "control_other",
        "inference_other",
    )
    assert TELEMETRY_OUTCOMES == (
        "ok",
        "http_error",
        "transport_error",
        "timeout",
        "stream_broken",
        "aborted",
    )
    assert TELEMETRY_FINAL_OUTCOMES == (*TELEMETRY_OUTCOMES, "exhausted")
    assert TELEMETRY_ERROR_CLASSES == (
        "dns",
        "tls",
        "connect_refused",
        "connect_timeout",
        "connect_error",
        "read_timeout",
        "write_timeout",
        "pool_timeout",
        "protocol_error",
        "reset",
        "io_error",
        "proxy_error",
        "stream_stalled",
        "unknown",
    )
    assert TELEMETRY_TIMEOUT_PHASES == (
        "none",
        "connect",
        "first_byte",
        "idle",
        "total",
    )
    assert TELEMETRY_LATENCY_BUCKETS == (
        "lt100",
        "lt200",
        "lt400",
        "lt800",
        "lt1600",
        "lt3200",
        "lt6400",
        "lt12800",
        "lt25600",
        "lt51200",
        "lt102400",
        "ge102400",
    )


def test_stable_routing_and_orchestration_aliases() -> None:
    assert ZDR_MODEL == "trustedrouter/zdr"
    assert E2E_MODEL == "trustedrouter/e2e"
    assert CONFIDENTIAL_MODEL == "trustedrouter/confidential"
    assert US_MODEL == "trustedrouter/us"
    assert SYNTH_MODEL == "trustedrouter/synth"
    assert SELECTOR_MODEL == "trustedrouter/selector"
    assert MAP_REDUCE_MODEL == "trustedrouter/mapreduce"
    assert SUBAGENT_MODEL == "trustedrouter/subagent"


def test_all_atomic_orchestration_builders_use_gateway_schema() -> None:
    assert fusion_tool(enabled=False) == {
        "type": "trustedrouter:fusion",
        "parameters": {"enabled": False},
    }
    assert advisor_tool(
        enabled=True,
        worker_timeout_ms=45_000,
        auto_initial_advice=True,
    ) == {
        "type": "trustedrouter:advisor",
        "parameters": {
            "enabled": True,
            "worker_timeout_ms": 45_000,
            "auto_initial_advice": True,
        },
    }
    assert selector_tool(
        enabled=True,
        analysis_models=["panel/a", "panel/b"],
        selector_models=["selector/a"],
        selector_prompt="pick verbatim",
        max_completion_tokens=128,
    ) == {
        "type": "trustedrouter:selector",
        "parameters": {
            "enabled": True,
            "analysis_models": ["panel/a", "panel/b"],
            "selector_models": ["selector/a"],
            "selector_prompt": "pick verbatim",
            "max_completion_tokens": 128,
        },
    }
    assert map_reduce_tool(
        enabled=True,
        mapper_models=["mapper/a"],
        parallel_models=["worker/a"],
        reducer_models=["reducer/a"],
        max_parts=8,
        mapper_prompt="split",
        parallel_prompt="solve",
        reducer_prompt="merge",
        max_completion_tokens=256,
    ) == {
        "type": "trustedrouter:mapreduce",
        "parameters": {
            "enabled": True,
            "mapper_models": ["mapper/a"],
            "parallel_models": ["worker/a"],
            "reducer_models": ["reducer/a"],
            "max_parts": 8,
            "mapper_prompt": "split",
            "parallel_prompt": "solve",
            "reducer_prompt": "merge",
            "max_completion_tokens": 256,
        },
    }
    assert subagent_tool(
        enabled=True,
        controller_model="controller/a",
        model="worker/a",
        instructions="delegate",
        depth=2,
        max_subagent_calls=3,
        max_completion_tokens=512,
        temperature=0.2,
        reasoning={"effort": "high"},
        tools=[{"type": "function", "function": {"name": "lookup"}}],
    ) == {
        "type": "trustedrouter:subagent",
        "parameters": {
            "enabled": True,
            "controller_model": "controller/a",
            "model": "worker/a",
            "instructions": "delegate",
            "depth": 2,
            "max_subagent_calls": 3,
            "max_completion_tokens": 512,
            "temperature": 0.2,
            "reasoning": {"effort": "high"},
            "tools": [{"type": "function", "function": {"name": "lookup"}}],
        },
    }


def test_provider_preferences_are_exact_composable_and_fail_closed() -> None:
    assert ProviderPreferences.zdr() == {
        "min_privacy": "zdr",
        "data_collection": "deny",
    }
    assert ProviderPreferences.confidential() == {
        "min_privacy": "confidential",
        "data_collection": "deny",
    }
    assert ProviderPreferences.us_only() == {"jurisdiction": "us"}
    assert ProviderPreferences(
        order=["tinfoil", "phala"],
        only=["tinfoil"],
        allow_fallbacks=False,
        require_parameters=True,
        sort="throughput",
        usage="credits",
        quantizations=["fp8"],
        max_price={"prompt": 1.25, "completion": 4.5},
    ) == {
        "order": ["tinfoil", "phala"],
        "only": ["tinfoil"],
        "sort": "throughput",
        "allow_fallbacks": False,
        "require_parameters": True,
        "usage": "credits",
        "quantizations": ["fp8"],
        "max_price": {"prompt": 1.25, "completion": 4.5},
    }
    with pytest.raises(ValueError):
        ProviderPreferences(min_privacy="probably")
    with pytest.raises(ValueError):
        ProviderPreferences(jurisdiction="eu")
    with pytest.raises(ValueError):
        ProviderPreferences(usage="free")


def test_error_attribution_is_available_without_losing_raw_payload() -> None:
    payload = {
        "error": {
            "message": "upstream unavailable",
            "layer": "provider",
            "source": "upstream",
            "provider": "example",
            "request_id": "req_123",
            "future_field": {"kept": True},
        }
    }
    error = InternalError(502, "upstream unavailable", payload=payload)
    assert error.layer == "provider"
    assert error.source == "upstream"
    assert error.provider == "example"
    assert error.request_id == "req_123"
    assert error.payload == payload
