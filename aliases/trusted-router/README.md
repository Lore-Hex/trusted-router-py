# trusted-router

`trusted-router` is an alias that installs the official TrustedRouter Python SDK,
[`trusted-router-py`](https://pypi.org/project/trusted-router-py/).

```bash
pip install trusted-router
```

This distribution contains only metadata. The SDK provides the `trustedrouter`
and `trusted_router` import names and the `trustedrouter` command.
The `attestation` and `receipts` extras are forwarded to the SDK, for example
`pip install "trusted-router[attestation]"` or `pip install "trusted-router[receipts]"`.

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

- [TrustedRouter](https://trustedrouter.com)
- [Documentation](https://github.com/Lore-Hex/trusted-router-py#readme)
- [Official SDK on PyPI](https://pypi.org/project/trusted-router-py/)
- [Official SDK on GitHub](https://github.com/Lore-Hex/trusted-router-py)
