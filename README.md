# TrustedRouter Python SDK

Small Python client for TrustedRouter.

- API base: `https://api.quillrouter.com/v1`
- Trust page: `https://trust.trustedrouter.com`
- Control plane source: `https://github.com/Lore-Hex/quill-router`
- License: Apache-2.0

## Install

```bash
pip install trusted-router-py
```

## Usage

```python
from trustedrouter import AUTO_MODEL, TrustedRouter

client = TrustedRouter(api_key="sk-tr-v1-...")

response = client.chat_completions(
    model=AUTO_MODEL,
    messages=[{"role": "user", "content": "hello"}],
)

print(response["choices"][0]["message"]["content"])
```

`trustedrouter/auto` is the default high-level chat model in the SDK. It maps to
TrustedRouter's provider rollover route.

```python
regions = client.regions()
checkout = client.stablecoin_checkout(amount=25)
challenge = client.wallet_challenge("0x...")
```

The SDK intentionally uses OpenAI-compatible request and response shapes. Use
`client.request(...)` for routes that are not wrapped yet.

## Trust Metadata

```python
from trustedrouter import fetch_trust_release

release = fetch_trust_release()
print(release["image_digest"])
```

Full attestation verification helpers will live here as the hosted attestation
contract stabilizes.
