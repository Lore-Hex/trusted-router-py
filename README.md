# TrustedRouter Python SDK

[![PyPI version](https://img.shields.io/pypi/v/trusted-router-py?logo=pypi)](https://pypi.org/project/trusted-router-py/)
[![Python versions](https://img.shields.io/pypi/pyversions/trusted-router-py?logo=python)](https://pypi.org/project/trusted-router-py/)
[![CI](https://github.com/Lore-Hex/trusted-router-py/actions/workflows/ci.yml/badge.svg)](https://github.com/Lore-Hex/trusted-router-py/actions/workflows/ci.yml)
[![Typed with Pydantic](https://img.shields.io/badge/types-pydantic-e92063)](https://pypi.org/project/trusted-router-py/)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![Verifiable trust](https://img.shields.io/badge/trust-attested-16a34a)](https://trust.trustedrouter.com)

OpenAI-compatible Python client for [TrustedRouter](https://trustedrouter.com) —
the hosted, attested LLM router that lets you point one OpenAI-shaped client
at every provider (Anthropic, OpenAI, Google Vertex, Gemini, DeepSeek,
Mistral, Cerebras) and *prove* the prompt path doesn't log.

- Gateway: `https://api.quillrouter.com/v1`
- Trust release: `https://trust.trustedrouter.com`
- Source: `https://github.com/Lore-Hex/trusted-router-py`
- License: Apache-2.0

```bash
pip install trusted-router-py                  # base client
pip install trusted-router-py[attestation]     # + GCP attestation verification
```

## Quick start

```python
from trustedrouter import TrustedRouter, AUTO_MODEL

with TrustedRouter(api_key="sk-tr-v1-...") as client:
    resp = client.chat_completions(
        model=AUTO_MODEL,                     # "trustedrouter/auto" — multi-provider failover
        messages=[{"role": "user", "content": "hello"}],
    )
    print(resp.choices[0].message.content)    # typed: ChatCompletion model
```

`chat_completions(...)` defaults to `AUTO_MODEL` when `model=` is omitted, so
the simplest possible call is `client.chat_completions(messages=[...])`.

## Fusion

Fan a request across a panel of models and let a judge model pick or synthesize
one answer. `fusion(...)` (and `AsyncTrustedRouter.fusion(...)`) returns the same
typed `ChatCompletion` as `chat_completions`. `FUSION_FREEDOM_PANEL` /
`FUSION_FREEDOM_FALLBACK_JUDGES` are the recommended most-permissive config.

```python
from trustedrouter import (
    TrustedRouter,
    FUSION_FREEDOM_PANEL,
    FUSION_FREEDOM_FALLBACK_JUDGES,
)

with TrustedRouter(api_key="sk-tr-v1-...") as client:
    resp = client.fusion(
        messages=[{"role": "user", "content": "explain how mRNA vaccines work"}],
        analysis_models=FUSION_FREEDOM_PANEL,       # the panel
        model="z-ai/glm-5.1",                       # judge / synthesis model
        selection_strategy="first_non_refusal",     # or synthesize / synthesize_non_refusals / first_success
        fallback_judges=FUSION_FREEDOM_FALLBACK_JUDGES,  # tried in order if a judge refuses/fails
    )
    print(resp.choices[0].message.content)
```

Or build the spec with `fusion_tool(...)` and pass it to any chat call.
`preset="quality"` or `"budget"` selects a built-in panel.

**Every method returns a typed pydantic model** — IDE autocomplete + runtime
validation. Need a dict? Call `.model_dump()`:

```python
resp.model_dump()["choices"][0]["message"]["content"]
```

## Streaming

```python
for token in client.chat_completions_stream(
    model=AUTO_MODEL,
    messages=[{"role": "user", "content": "Write a haiku"}],
):
    print(token, end="", flush=True)
```

`chat_completions_chunk_stream(...)` yields the raw OpenAI
`chat.completion.chunk` dicts (with `finish_reason`, `model`, `id`) when you
need more than just the text delta.

## Async

Every method on `TrustedRouter` is mirrored on `AsyncTrustedRouter` as a
coroutine; streaming methods return `AsyncIterator`s. Use it from FastAPI,
asyncio, or any event-loop-driven app:

```python
import asyncio
from trustedrouter import AsyncTrustedRouter

async def main():
    async with AsyncTrustedRouter(api_key="sk-tr-v1-...") as client:
        async for token in client.chat_completions_stream(
            model="trustedrouter/auto",
            messages=[{"role": "user", "content": "hi"}],
        ):
            print(token, end="", flush=True)

asyncio.run(main())
```

## Region pinning

The gateway is deployed in `us-central1` (the apex) and `europe-west4`. Pin
to a specific region with one kwarg — no need to construct the URL yourself:

```python
client = TrustedRouter(api_key="sk-tr-v1-...", region="europe-west4")
```

The full list lives in `trustedrouter.REGION_HOSTS`. Pass `region=` for known
regions, or `base_url=` for a custom endpoint (e.g. a self-hosted gateway).
Passing both is a configuration error.

## Typed errors

Every HTTP failure raises a typed subclass of `TrustedRouterError` so callers
can discriminate without inspecting status codes:

```python
from trustedrouter import (
    TrustedRouter, AuthenticationError, RateLimitError,
    BadRequestError, EndpointNotSupportedError, NotFoundError, InternalError,
)

try:
    client.chat_completions(messages=[...])
except RateLimitError as e:
    time.sleep(e.retry_after or 5)        # honors Retry-After header
except AuthenticationError:
    refresh_key()
except BadRequestError as e:
    log.warning("bad request: %s", e)
except EndpointNotSupportedError:
    disable_optional_feature()
except InternalError:
    pass                                   # auto-retried; still failing
```

All subclasses inherit from `TrustedRouterError`, so existing
`except TrustedRouterError` blocks keep working.

## Automatic retries

By default the client retries `429` and `5xx` responses up to **2 times**
with exponential backoff + jitter (capped at 30s, honors `Retry-After`).
Disable with `max_retries=0`:

```python
client = TrustedRouter(api_key="...", max_retries=0)   # raise immediately on transient
```

## Per-call extras

Every chat method (and `request()` for ad-hoc paths) accepts:

| kwarg | use |
|---|---|
| `api_key=` | override the instance bearer for this call only (threadsafe — used by validate_bearer) |
| `extra_headers=` | dict of headers to merge in (trace IDs, custom routing) |
| `workspace_id=` | sets `X-TrustedRouter-Workspace` for workspace-scoped management calls |
| `idempotency_key=` | adds `Idempotency-Key:` so the gateway dedupes retries — **strongly recommended for billing** |
| `timeout=` | override the client-level timeout for this call |

```python
client.billing_checkout(
    amount=25,
    payment_method="stablecoin",
    idempotency_key=f"checkout-{user_id}-{order_id}",   # never double-charge
)
```

## Sign in with TrustedRouter

Let users "bring their own TrustedRouter account" instead of pasting a key:
the OpenRouter-style OAuth **PKCE** flow mints a user-scoped key so LLM calls
are billed to *that user's* credits. `create_oauth_authorization(...)` builds
the authorize URL and returns the `code_verifier` + `state` to keep across the
redirect; `exchange_oauth_key(...)` swaps the returned `code` for the delegated
key + verified identity. Async variants (`exchange_oauth_key_async`,
`fetch_userinfo_async`) mirror these.

```python
from trustedrouter import create_oauth_authorization, exchange_oauth_key, fetch_userinfo

# 1. sign-in: keep auth.code_verifier + auth.state in the user's session
auth = create_oauth_authorization(
    callback_url="https://myapp.com/auth/callback",
    key_label="My App", limit="5", usage_limit_type="monthly",
)
redirect_to(auth.url)

# 2. in /auth/callback (verify state == saved state first)
token = exchange_oauth_key(code=request.args["code"], code_verifier=saved_verifier)
store_for_user(token.key, token.identity)        # sk-tr-v1-… + {sub, email, …}

# 3. anytime
who = fetch_userinfo(api_key=token.key)          # {sub, email, …}
```

Full flow, endpoints, and security notes:
[Sign in with TrustedRouter](https://github.com/Lore-Hex/quill-router/blob/main/docs/sign-in-with-trustedrouter.md).

## Attestation verification (the differentiator)

Every TrustedRouter response is generated inside a Google Confidential Space
workload. The gateway's `/attestation` endpoint mints a Google-signed JWT
that commits to the workload image digest, image reference, your nonce, and
the TLS leaf cert SHA-256. Verifying it proves the prompt path you're about
to use is the exact build the trust page advertises:

```python
import secrets, ssl, socket
from trustedrouter import TrustedRouter
from trustedrouter.attestation import (
    verify_gateway_attestation, policy_from_trust_release,
)

# Pull the published image digest/reference from the trust page
policy = policy_from_trust_release()                 # or pin one explicitly

with TrustedRouter(api_key="sk-tr-v1-...") as client:
    nonce = secrets.token_hex(16)
    jwt = client.attestation()                       # raw JWT bytes

    # Bind the JWT to the live TLS connection's cert
    with ssl.create_default_context().wrap_socket(
        socket.create_connection(("api.quillrouter.com", 443)),
        server_hostname="api.quillrouter.com",
    ) as s:
        cert_der = s.getpeercert(binary_form=True)

    attestation = verify_gateway_attestation(
        jwt, policy=policy, nonce_hex=nonce, tls_cert_der=cert_der
    )
    print("verified gateway:", attestation.image_digest)
```

`verify_gateway_attestation()` raises `AttestationVerificationError` on any
of: bad signature, expired JWT, wrong issuer, audience mismatch,
image_digest mismatch, image_reference mismatch, missing nonce echo, or
TLS cert mismatch. Never returns falsey for a failed verification.

This codepath needs `cryptography`; install with
`pip install trusted-router-py[attestation]`.

## Bring your own httpx client

Pass `client=` if you need a custom transport (cert pinning, retries you
manage, observability hooks). The SDK won't close it on `aclose()`:

```python
import httpx
from trustedrouter import AsyncTrustedRouter

my_client = httpx.AsyncClient(
    timeout=30.0,
    event_hooks={"response": [my_cert_pin_hook]},
)
sdk = AsyncTrustedRouter(api_key="...", client=my_client)
# ...use sdk...
await sdk.aclose()        # no-op for caller-owned clients
await my_client.aclose()  # caller still owns lifecycle
```

This is exactly how the [Quill device](https://github.com/Lore-Hex/quill)
wraps the SDK so it can pin Quill Cloud's self-signed leaf cert via an
httpx event hook, while delegating chat streaming to the SDK.

## CLI

`pip install` exposes a `trustedrouter` console script for sniff tests:

```bash
export TRUSTEDROUTER_API_KEY=sk-tr-v1-...

trustedrouter chat "hello"                 # one-shot completion
trustedrouter chat --stream "long answer"  # token-by-token
trustedrouter regions                      # list deployed regions
trustedrouter providers                    # list provider catalog
trustedrouter models                       # list model catalog
trustedrouter trust                        # show trust release
trustedrouter attest                       # raw JWT bytes (pipe to `jq`-able tools)
trustedrouter --region europe-west4 chat "hi"
```

## Other endpoints

```python
client.models()             # OpenAI-shape catalog
client.providers()          # provider list
client.regions()            # deployed regions
client.credits(workspace_id="ws_...")  # current prepaid balance for a workspace
client.activity(since="2026-01-01", limit=50)
client.messages(            # Anthropic-shape, preserves system + content blocks
    model="anthropic/claude-3-5-sonnet",
    messages=[{"role": "user", "content": "hi"}],
    max_tokens=512,
)
client.billing_checkout(amount=25, payment_method="stablecoin", idempotency_key=...)
```

`client.embeddings(...)` is present for API compatibility, but the hosted
TrustedRouter route currently raises `EndpointNotSupportedError` instead of
returning fake vectors. Use `client.models()` / `/embeddings/models` to inspect
the future embedding catalog.

For routes the SDK doesn't wrap, drop down to `client.request(...)`:

```python
client.request("GET", "/some/new/route", headers={"x-trace": "abc"})
```

## Roadmap

- **v0.3 (shipped):** typed pydantic response models — every method returns
  a typed model. Migration: replace `resp["k"]` with `resp.k`, or call
  `resp.model_dump()` to get the dict back. Models use `extra="allow"`
  so the gateway can add fields without an SDK release.
- **v0.x:** AWS Nitro Enclaves attestation path (currently only GCP).

## Contributing

```bash
uv sync --group dev
uv run ruff check .
uv run pytest                              # ~110 tests, ≥85% coverage gate
```

CI runs lint + tests on every push to main and PR. Coverage gate is
enforced — PRs that drop coverage below 85% fail. Add tests with new
public surface.
