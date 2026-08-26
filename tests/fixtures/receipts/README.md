# Receipt parity fixtures

Files in this directory are frozen, byte-identical artifacts produced by the
enclave implementation. Do not generate or rewrite them in the Python test
suite.

Each supplied fixture may be a subdirectory containing:

- `receipt.jws`: compact JWS text or flattened JWS JSON;
- optional `request.body` with the exact request bytes;
- exactly one optional response artifact, `response.body` or `response.sse`;
- optional `metadata.json` with keyword arguments accepted by
  `verify_receipt` (`expected_nonce`, `max_age_seconds`, `now`, and
  `require_attestation`).

The loader also accepts receipt files directly in this directory. It detects
compact or flattened JWS content and looks first for stem-prefixed companions
such as `chat-stream.request.body`, `chat-stream.response.sse`, and
`chat-stream.metadata.json`, then for the unprefixed names above.

The fixture test verifies every supplied case. When no case subdirectories are
present, it skips cleanly. Embedded GCP evidence is covered by the attestation
verifier tests and is stubbed only in this frozen wire-parity test so expired
fixture JWTs and network access cannot affect byte-format parity.
