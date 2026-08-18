# Changelog

## Unreleased

- Typed inference and control-plane mutation helpers now mint one stable
  `Idempotency-Key` per logical call and reuse it for every attempt. The generic
  `request()` escape hatch remains deliberately unkeyed; callers must provide
  `idempotency_key=` to authorize ordinary status retries or replay after an
  ambiguous write.
- Standalone sync and async OAuth exchanges now install the same marker-scoped
  terminal header scrubber used by SDK clients, preventing an injected
  `httpx` request hook from restoring ambient credentials while leaving the
  shared client's unmarked traffic unchanged.

## 0.6.0

- Added client-observed reliability telemetry, enabled by default only when both
  the inference and control planes use TrustedRouter hosts. Exact per-minute
  counters and sampled request diagnostics report endpoint class, method,
  streaming and provider-pinned flags, model identifier, attempt host/outcome,
  bounded error class and status, retry hints, elapsed/TTFB/TTFT/total timing,
  request ID, failover, timeout phase, configured timeout, SDK/runtime/OS/arch,
  latency histograms, sample reason/rate, and bounded delivery ages. Telemetry
  payloads never contain prompts, completions, message text, workspace/key/user/
  session IDs, IP addresses, or hostnames of custom endpoints.
- Added the bounded `x-tr-client` per-attempt header so the gateway can correlate
  retries and failover without receiving request content. Disable both the
  header and reporter with `telemetry=False`, `TRUSTEDROUTER_TELEMETRY=0`, or
  `DO_NOT_TRACK=1`; custom inference or control hosts default to disabled.
- Added `TRUSTEDROUTER_TELEMETRY_DEBUG=1` to echo the exact outbound batch JSON
  to stderr. The out-of-engine reporter retains counters for up to 24 hours and
  512 KiB, sends one bounded batch at a time, and backs off for 429, 503, and
  transport failures without delaying inference. See
  [Telemetry](https://trustedrouter.com/docs/telemetry) for the full disclosure.
- Restructured the internals into the harmonized layered architecture
  (policy kernel / plane router / transport engine / attempt assembly /
  stream codec / error taxonomy / orchestration builders / facades), with
  `trustedrouter.client` kept as a full compatibility re-export shim. The
  public API and import paths are unchanged.
- Behavior change: streaming methods now gate the transport-error domain
  advance on `regional_failover`, matching `request()` and the documented
  intent ("`regional_failover=False` is an instruction, not a hint").
  Previously the 11 streaming loops could move a `regional_failover=False`
  client onto an alias domain after a connection failure.

## 0.4.0

- Changed the default inference API base to `https://api.trustedrouter.com/v1`.
- Added `DEFAULT_CONTROL_BASE_URL` and `control_base_url=` for control-plane calls.
- Routed catalog, account, billing, OAuth, and broadcast calls to the control
  plane at `https://trustedrouter.com/v1` by default.
- Kept `base_url=` scoped to inference-plane calls; overriding `base_url` no
  longer affects catalog, account, billing, OAuth, or broadcast calls.
- Changed regional failover to re-request the global load-balancer apex and
  removed per-region hostnames.
