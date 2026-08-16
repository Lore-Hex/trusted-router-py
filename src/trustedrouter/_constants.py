"""Shared constants (L7 data): default URLs, timeouts, and model aliases.

These values are pinned by the cross-SDK parity tests
(tests/test_parity_contract.py, tests/test_client.py) and must not change
here without a coordinated release across every TrustedRouter SDK.
"""

from __future__ import annotations

DEFAULT_API_BASE_URL = "https://api.trustedrouter.com/v1"
DEFAULT_CONTROL_BASE_URL = "https://trustedrouter.com/v1"
DEFAULT_TRUST_RELEASE_URL = "https://trust.trustedrouter.com/trust/gcp-release.json"
DEFAULT_STATUS_URL = "https://status.trustedrouter.com/status.json"
DEFAULT_REQUEST_TIMEOUT_SECONDS = 120.0
DEFAULT_FUSION_TIMEOUT_SECONDS = 600.0
DEFAULT_REGION_PROBE_TIMEOUT_SECONDS = 1.5
TELEMETRY_SCHEMA_VERSION = 1
DEFAULT_TELEMETRY_PATH = "/client-events"
TELEMETRY_FLUSH_SECONDS = 30.0
TELEMETRY_MAX_EVENTS = 1000
TELEMETRY_MAX_BATCH_EVENTS = 100
TELEMETRY_MAX_BATCH_COUNTERS = 200
TELEMETRY_MAX_WINDOW_KEYS = 256
TELEMETRY_RETENTION_SECONDS = 86_400
TELEMETRY_RETENTION_BYTES = 524_288
TELEMETRY_BACKOFF_MIN_SECONDS = 60.0
TELEMETRY_BACKOFF_MAX_SECONDS = 600.0
TELEMETRY_HOSTS: tuple[str, ...] = (
    "apex",
    "ally",
    "uptime",
    "us_central1",
    "us_east4",
    "europe_west4",
    "control",
    "custom",
)
TELEMETRY_ENDPOINTS: tuple[str, ...] = (
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
TELEMETRY_OUTCOMES: tuple[str, ...] = (
    "ok",
    "http_error",
    "transport_error",
    "timeout",
    "stream_broken",
    "aborted",
)
TELEMETRY_FINAL_OUTCOMES: tuple[str, ...] = (*TELEMETRY_OUTCOMES, "exhausted")
TELEMETRY_ERROR_CLASSES: tuple[str, ...] = (
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
TELEMETRY_TIMEOUT_PHASES: tuple[str, ...] = (
    "none",
    "connect",
    "first_byte",
    "idle",
    "total",
)
TELEMETRY_LATENCY_BUCKETS: tuple[str, ...] = (
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
