# Changelog

## 0.9.0

- `verify_gateway_attestation_document(document, policy=..., nonce_hex=...)`:
  document-only gateway attestation for callers that cannot see their TLS
  connection, which includes every `httpx` caller. It runs every token check
  `verify_gateway_attestation()` runs (Google signature, issuer, audience,
  expiry, production Confidential Space claims, image pins) and requires a
  fresh 16–64-byte caller nonce in `eat_nonce`, but claims no TLS binding. Its
  `GatewayAttestationDocument` result has `binding == "none"`, no
  `cert_sha256`, and `cert_sha256_candidates` for callers who later hold the
  certificate. Live gateway tokens carry the certificate hash only as an
  `eat_nonce` entry, so until now nothing could pass without the certificate.
- `binding: "none" | "tls-cert" | "tls-exporter"` on every
  `GatewayAttestation` (type `AttestationBinding`, also in `as_dict()`),
  reporting which connection evidence was actually compared.
  `verify_gateway_session()` and `fetch_attestation_again()` report
  `"tls-exporter"`; `tls_cert_der` gives `"tls-cert"`; a certificate hash that
  is only claimed by the token, or only matched against a policy pin, gives
  `"none"`. The field defaults to `"none"`, so existing constructors keep
  working.
- `client.attestation(nonce_hex=...)` (sync and async) sends the challenge as
  `/attestation?nonce=`. Without it the request is unchanged.
- `trustedrouter attest --verify` sends a fresh nonce and verifies the document
  with `verify_gateway_attestation_document()`; it failed against the live
  gateway before ("JWT does not commit to a TLS cert SHA-256"), for the reason
  above. Its JSON `data` now carries `binding`, `nonce`, and
  `cert_sha256_candidates` instead of `cert_sha256`.
- `verify_gateway_attestation()` behaves as before. When it cannot find a
  certificate commitment without `tls_cert_der`, the error now names the
  document-only verifier.
- Internal: a live-gateway claims fixture (container env stripped) and three
  document-mode mutations in the mutation gate.

## 0.8.0

- Offline signed inference receipt verification: `trustedrouter.receipts.verify_receipt()`
  accepts a compact or flattened JWS and fails closed with typed errors —
  structure (duplicate JSON keys rejected), header, Ed25519 signature,
  `rv`/`iat` (60 s future skew, optional max age), nonce, tee-verified
  claims, and both captured-stream hash domains. `ReceiptCapture` preserves
  exact wire bytes from a streaming response. GCP attestation chains verify
  through the package's existing verifier with the receipt-key commitment
  checked by set membership; `aws-nitro-cose` and `azure-maa-jwt` raise
  `UnsupportedAttestationError` rather than skipping. The enclave-generated
  parity fixtures are byte-identical across all six SDKs.
- Receipt-key attestation binding mode: compact receipts verify fully when
  the caller supplies the attestation document pinned by `att_sha256`
  (`verify_receipt(attestation=...)`); the live-gateway path and its
  TLS-channel requirements are unchanged.
- **Receipt verification fails closed by default**: request and response
  bindings are required unless explicitly disabled, `expected_issuer` is
  required and compared as a canonical origin, and the receipt's `iss` is
  never followed.
- Boundary audit: every value that enters from the wire, storage, argv, or
  env is checked before use, so malformed responses raise the SDK's typed
  protocol error instead of `AttributeError`/`KeyError`. The `/auth/keys`
  exchange requires only `key` (a string) and passes every unknown field
  through; the old coercion that turned a missing key into an empty string
  is gone. `/auth/userinfo` requires `data` to be an object and accepts the
  legacy `{"sub": null, "workspace_id": ...}` shape. Header lookups and
  merges are case-insensitive everywhere.
- Packaging: the sdist ships only the library (no tests, fixtures, scripts,
  or CI files); complete metadata (license files, keywords, per-version
  classifiers, documentation and issue URLs). Every README example executes
  in the test suite and the CLI is covered against the installed wheel.
- Internal: mypy strict on the package, expanded ruff rules, a shared
  cross-SDK auth wire fixture, and a fails-without-fix mutation gate in CI.

## 0.7.0

- Promoted the bundled `trustedrouter` command from a gateway sniff-test helper
  to the official agent-grade CLI. It now supports prompt stdin, `--version`,
  deterministic `--json` success/error envelopes, JSON Lines streaming, and
  documented stable exit codes while preserving the existing plain commands.
  Stdin is bounded at 8 MiB, numeric options fail before networking, 401/403
  share the authentication/permission exit contract, and base/control/workspace
  configuration can come from documented environment variables. Attestation
  JSON distinguishes raw, identity-verified, and TLS-session-verified results;
  only session verification accepts `--connect-ip` or claims same-socket
  binding. SDK exception types are consistent with the JavaScript CLI.
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
