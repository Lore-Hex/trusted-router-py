from __future__ import annotations

import httpx
import pytest

from trustedrouter import DEFAULT_API_BASE_URL, TrustedRouter
from trustedrouter.client import TrustedRouterError


def test_client_normalizes_base_url() -> None:
    client = TrustedRouter(base_url=DEFAULT_API_BASE_URL + "/")
    assert client.base_url == DEFAULT_API_BASE_URL
    client.close()


def test_request_sends_bearer_token() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["authorization"] == "Bearer sk-tr-test"
        assert str(request.url) == f"{DEFAULT_API_BASE_URL}/models"
        return httpx.Response(200, json={"data": []})

    client = TrustedRouter(api_key="sk-tr-test")
    client._client = httpx.Client(transport=httpx.MockTransport(handler))

    assert client.models() == {"data": []}
    client.close()


def test_error_payload_raises_trusted_router_error() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": {"message": "bad key"}})

    client = TrustedRouter(api_key="sk-tr-test")
    client._client = httpx.Client(transport=httpx.MockTransport(handler))

    with pytest.raises(TrustedRouterError) as exc_info:
        client.models()

    assert exc_info.value.status_code == 401
    assert str(exc_info.value) == "bad key"
    client.close()
