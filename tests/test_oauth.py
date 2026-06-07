"""Coverage for the browser OAuth / PKCE delegated-key flow
(trustedrouter.oauth).

The PKCE helpers are pure and tested directly. The network helpers
(exchange + userinfo) are exercised with httpx.MockTransport so the
exact request shape the live backend expects — POST /auth/keys with NO
auth header, GET /auth/userinfo with Bearer — is asserted, plus the
typed-error mapping on HTTP >= 400."""
from __future__ import annotations

import asyncio
import base64
import hashlib
import json as jsonlib

import httpx
import pytest
import respx

from trustedrouter import (
    DEFAULT_API_BASE_URL,
    AuthenticationError,
    BadRequestError,
    OAuthAuthorization,
    OAuthToken,
    PKCEPair,
    TrustedRouterError,
    create_oauth_authorization,
    create_pkce_pair,
    exchange_oauth_key,
    exchange_oauth_key_async,
    fetch_userinfo,
    fetch_userinfo_async,
    oauth_authorize_url,
    random_oauth_state,
)


def _run(coro):  # type: ignore[no-untyped-def]
    return asyncio.run(coro)


def _expected_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


# ---- PKCE + state ---------------------------------------------------------


def test_random_oauth_state_is_url_safe_and_unique() -> None:
    a = random_oauth_state()
    b = random_oauth_state()
    assert a != b
    # base64url, no padding
    assert "=" not in a and "+" not in a and "/" not in a
    # 16 bytes -> 22 base64url chars
    assert len(a) == 22
    assert len(random_oauth_state(32)) == 43


def test_create_pkce_pair_s256_round_trip() -> None:
    pair = create_pkce_pair()
    assert isinstance(pair, PKCEPair)
    assert pair.code_challenge_method == "S256"
    assert "=" not in pair.code_verifier and "=" not in pair.code_challenge
    # The core PKCE invariant: challenge == base64url(sha256(verifier)).rstrip('=')
    assert pair.code_challenge == _expected_challenge(pair.code_verifier)


def test_create_pkce_pair_accepts_explicit_verifier() -> None:
    pair = create_pkce_pair("my-fixed-verifier")
    assert pair.code_verifier == "my-fixed-verifier"
    assert pair.code_challenge == _expected_challenge("my-fixed-verifier")


# ---- authorize URL --------------------------------------------------------


def test_oauth_authorize_url_includes_only_set_params_and_embeds_state() -> None:
    url = oauth_authorize_url(
        callback_url="https://app.example/cb",
        code_challenge="chal123",
        code_challenge_method="S256",
        key_label="My Laptop",
        limit=25,
        usage_limit_type="monthly",
        expires_at="2026-12-31T00:00:00Z",
        spawn_agent="1",
        state="state-xyz",
    )
    parsed = httpx.URL(url)
    assert str(parsed).startswith(f"{DEFAULT_API_BASE_URL}/auth?")
    params = parsed.params
    assert params["code_challenge"] == "chal123"
    assert params["code_challenge_method"] == "S256"
    assert params["key_label"] == "My Laptop"
    assert params["limit"] == "25"
    assert params["usage_limit_type"] == "monthly"
    assert params["expires_at"] == "2026-12-31T00:00:00Z"
    assert params["spawn_agent"] == "1"
    # No redirect_uri / client_id / response_type / scope.
    assert "redirect_uri" not in params
    assert "client_id" not in params
    assert "response_type" not in params
    assert "scope" not in params
    # spawn_cloud was not set -> absent.
    assert "spawn_cloud" not in params
    # state is embedded INTO callback_url, not a top-level authorize param.
    assert "state" not in params
    callback = httpx.URL(params["callback_url"])
    assert callback.params["state"] == "state-xyz"
    assert str(callback).startswith("https://app.example/cb")


def test_oauth_authorize_url_without_state_leaves_callback_untouched() -> None:
    url = oauth_authorize_url(callback_url="https://app.example/cb")
    params = httpx.URL(url).params
    assert params["callback_url"] == "https://app.example/cb"


def test_oauth_authorize_url_requires_callback_url() -> None:
    with pytest.raises(ValueError, match="callback_url is required"):
        oauth_authorize_url(callback_url="")


def test_oauth_authorize_url_method_without_challenge_is_error() -> None:
    with pytest.raises(ValueError, match="code_challenge is required"):
        oauth_authorize_url(
            callback_url="https://app.example/cb",
            code_challenge_method="S256",
        )


def test_oauth_authorize_url_honors_custom_base_url() -> None:
    url = oauth_authorize_url(
        base_url="https://gw.internal/v1/",
        callback_url="https://app.example/cb",
    )
    assert str(httpx.URL(url)).startswith("https://gw.internal/v1/auth?")


def test_oauth_authorize_url_includes_spawn_cloud() -> None:
    url = oauth_authorize_url(callback_url="https://app.example/cb", spawn_cloud=True)
    assert httpx.URL(url).params["spawn_cloud"] == "True"


def test_create_oauth_authorization_builds_everything() -> None:
    auth = create_oauth_authorization(
        callback_url="https://app.example/cb",
        key_label="agent",
        limit=10,
    )
    assert isinstance(auth, OAuthAuthorization)
    assert auth.code_challenge_method == "S256"
    assert auth.code_challenge == _expected_challenge(auth.code_verifier)
    parsed = httpx.URL(auth.url)
    assert parsed.params["code_challenge"] == auth.code_challenge
    assert parsed.params["key_label"] == "agent"
    assert parsed.params["limit"] == "10"
    # generated state round-trips through the callback_url
    callback = httpx.URL(parsed.params["callback_url"])
    assert callback.params["state"] == auth.state


def test_create_oauth_authorization_respects_provided_verifier_and_state() -> None:
    auth = create_oauth_authorization(
        callback_url="https://app.example/cb",
        code_verifier="pinned-verifier",
        state="pinned-state",
    )
    assert auth.code_verifier == "pinned-verifier"
    assert auth.state == "pinned-state"
    callback = httpx.URL(httpx.URL(auth.url).params["callback_url"])
    assert callback.params["state"] == "pinned-state"


# ---- key exchange ---------------------------------------------------------


def _capture(seen: list, response: httpx.Response):  # type: ignore[no-untyped-def]
    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return response

    return httpx.MockTransport(handler)


def test_exchange_oauth_key_posts_to_keys_with_no_auth() -> None:
    seen: list[httpx.Request] = []
    payload = {
        "key": "sk-tr-v1-abc",
        "user_id": "user_123",
        "identity": {"sub": "user_123", "email": "a@b.co", "email_verified": True},
        "data": {"extra": 1},
    }
    transport = _capture(seen, httpx.Response(200, json=payload))
    token = exchange_oauth_key(
        code="the-code",
        code_verifier="the-verifier",
        client=httpx.Client(transport=transport),
    )
    assert isinstance(token, OAuthToken)
    assert token.key == "sk-tr-v1-abc"
    assert token.user_id == "user_123"
    assert token.identity == payload["identity"]
    assert token.data == payload

    req = seen[0]
    assert req.method == "POST"
    assert str(req.url) == f"{DEFAULT_API_BASE_URL}/auth/keys"
    # Public client — must NOT carry an Authorization header.
    assert "authorization" not in {k.lower() for k in req.headers}
    body = jsonlib.loads(req.content.decode())
    assert body == {"code": "the-code", "code_verifier": "the-verifier"}


def test_exchange_oauth_key_handles_null_identity_and_method() -> None:
    seen: list[httpx.Request] = []
    transport = _capture(
        seen,
        httpx.Response(200, json={"key": "sk-tr-v1-x", "user_id": "u", "identity": None}),
    )
    token = exchange_oauth_key(
        code="c",
        code_verifier="v",
        code_challenge_method="S256",
        client=httpx.Client(transport=transport),
    )
    assert token.identity is None
    body = jsonlib.loads(seen[0].content.decode())
    assert body == {"code": "c", "code_verifier": "v", "code_challenge_method": "S256"}


def test_exchange_oauth_key_requires_code() -> None:
    with pytest.raises(ValueError, match="code is required"):
        exchange_oauth_key(code="", code_verifier="v")


def test_exchange_oauth_key_maps_http_error() -> None:
    transport = httpx.MockTransport(
        lambda request: httpx.Response(400, json={"error": {"message": "bad code"}})
    )
    with pytest.raises(BadRequestError, match="bad code"):
        exchange_oauth_key(code="c", client=httpx.Client(transport=transport))


def test_exchange_oauth_key_async_posts_to_keys() -> None:
    seen: list[httpx.Request] = []
    transport = _capture(
        seen, httpx.Response(200, json={"key": "sk-tr-v1-async", "user_id": "u2"})
    )

    async def run() -> OAuthToken:
        return await exchange_oauth_key_async(
            code="c2",
            code_verifier="v2",
            client=httpx.AsyncClient(transport=transport),
        )

    token = _run(run())
    assert token.key == "sk-tr-v1-async"
    assert token.user_id == "u2"
    assert token.identity is None
    assert str(seen[0].url) == f"{DEFAULT_API_BASE_URL}/auth/keys"
    assert "authorization" not in {k.lower() for k in seen[0].headers}


# ---- userinfo -------------------------------------------------------------


def test_fetch_userinfo_gets_with_bearer_and_unwraps_data() -> None:
    seen: list[httpx.Request] = []
    data = {"sub": "user_1", "email": "u@x.co", "workspace_id": "ws_1"}
    transport = _capture(seen, httpx.Response(200, json={"data": data}))
    result = fetch_userinfo(
        api_key="sk-tr-v1-key",
        client=httpx.Client(transport=transport),
    )
    assert result == data
    req = seen[0]
    assert req.method == "GET"
    assert str(req.url) == f"{DEFAULT_API_BASE_URL}/auth/userinfo"
    assert req.headers["authorization"] == "Bearer sk-tr-v1-key"


def test_fetch_userinfo_falls_back_to_whole_body_without_data_key() -> None:
    flat = {"sub": "user_2", "email": "v@x.co"}
    transport = httpx.MockTransport(lambda request: httpx.Response(200, json=flat))
    result = fetch_userinfo(api_key="k", client=httpx.Client(transport=transport))
    assert result == flat


def test_fetch_userinfo_maps_auth_error() -> None:
    transport = httpx.MockTransport(
        lambda request: httpx.Response(401, json={"error": {"message": "revoked"}})
    )
    with pytest.raises(AuthenticationError, match="revoked"):
        fetch_userinfo(api_key="dead", client=httpx.Client(transport=transport))


def test_fetch_userinfo_maps_non_json_error() -> None:
    transport = httpx.MockTransport(lambda request: httpx.Response(500, text="boom"))
    with pytest.raises(Exception) as excinfo:
        fetch_userinfo(api_key="k", client=httpx.Client(transport=transport))
    assert excinfo.value.status_code == 500  # type: ignore[attr-defined]


def test_fetch_userinfo_async_gets_with_bearer() -> None:
    seen: list[httpx.Request] = []
    transport = _capture(seen, httpx.Response(200, json={"data": {"sub": "uu"}}))

    async def run() -> dict:
        return await fetch_userinfo_async(
            api_key="sk-tr-v1-async",
            client=httpx.AsyncClient(transport=transport),
        )

    result = _run(run())
    assert result == {"sub": "uu"}
    assert seen[0].headers["authorization"] == "Bearer sk-tr-v1-async"
    assert str(seen[0].url) == f"{DEFAULT_API_BASE_URL}/auth/userinfo"


# ---- error-shape + plumbing edges -----------------------------------------


def test_exchange_oauth_key_rejects_non_object_json() -> None:
    transport = httpx.MockTransport(lambda request: httpx.Response(200, json=["not", "obj"]))
    with pytest.raises(TrustedRouterError, match="Expected JSON object"):
        exchange_oauth_key(code="c", client=httpx.Client(transport=transport))


def test_exchange_oauth_key_maps_bare_message_error() -> None:
    transport = httpx.MockTransport(
        lambda request: httpx.Response(400, json={"message": "flat message"})
    )
    with pytest.raises(BadRequestError, match="flat message"):
        exchange_oauth_key(code="c", client=httpx.Client(transport=transport))


# ---- owned-client paths (no client= passed; respx intercepts httpx) -------


@respx.mock
def test_exchange_oauth_key_owned_client() -> None:
    route = respx.post(f"{DEFAULT_API_BASE_URL}/auth/keys").mock(
        return_value=httpx.Response(200, json={"key": "sk-tr-v1-owned", "user_id": "u9"})
    )
    token = exchange_oauth_key(code="c", code_verifier="v")
    assert token.key == "sk-tr-v1-owned"
    assert token.user_id == "u9"
    assert route.called
    assert "authorization" not in {k.lower() for k in route.calls.last.request.headers}


@respx.mock
def test_fetch_userinfo_owned_client() -> None:
    route = respx.get(f"{DEFAULT_API_BASE_URL}/auth/userinfo").mock(
        return_value=httpx.Response(200, json={"data": {"sub": "owned"}})
    )
    result = fetch_userinfo(api_key="sk-tr-v1-owned")
    assert result == {"sub": "owned"}
    assert route.calls.last.request.headers["authorization"] == "Bearer sk-tr-v1-owned"


@respx.mock
def test_exchange_oauth_key_async_owned_client() -> None:
    respx.post(f"{DEFAULT_API_BASE_URL}/auth/keys").mock(
        return_value=httpx.Response(200, json={"key": "sk-tr-v1-aowned", "user_id": "ua"})
    )

    async def run() -> OAuthToken:
        return await exchange_oauth_key_async(code="c", code_verifier="v")

    token = _run(run())
    assert token.key == "sk-tr-v1-aowned"


@respx.mock
def test_fetch_userinfo_async_owned_client() -> None:
    respx.get(f"{DEFAULT_API_BASE_URL}/auth/userinfo").mock(
        return_value=httpx.Response(200, json={"data": {"sub": "aowned"}})
    )

    async def run() -> dict:
        return await fetch_userinfo_async(api_key="k")

    assert _run(run()) == {"sub": "aowned"}
