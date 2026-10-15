"""Document-only gateway attestation and the `binding` every result reports.

The fixture is the claim set the live gateway returned on 2026-10-15 (see
fixtures/attestation/metadata.json). Its shape is the reason this mode
exists: there is no tls_cert_sha256 claim, and the leaf certificate hash is
one anonymous eat_nonce entry among several, so verify_gateway_attestation()
cannot pass without the certificate DER, which an httpx caller never has. The
tests re-sign those claims with a generated key and a fresh expiry, put the
test's own nonce where the caller nonce sat, and check that every claim check
still runs while no TLS binding is claimed."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import secrets
import ssl
import time
from pathlib import Path
from typing import Any

import httpx
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

import trustedrouter.attestation as attestation
from trustedrouter import AsyncTrustedRouter, TrustedRouter
from trustedrouter.attestation import (
    EXPORTER_LENGTH,
    GCP_ISSUER,
    GCP_JWKS_URI,
    AttestationPolicy,
    AttestationVerificationError,
    GatewayAttestationDocument,
    policy_from_trust_release,
    verify_gateway_attestation,
    verify_gateway_attestation_document,
)

_FIXTURES = Path(__file__).parent / "fixtures" / "attestation"
_LIVE_CLAIMS: dict[str, Any] = json.loads((_FIXTURES / "live-gateway-claims.json").read_text())
_LEAF_DER = ssl.PEM_cert_to_DER_cert((_FIXTURES / "live-gateway-leaf.pem").read_text())
_LEAF_SHA = hashlib.sha256(_LEAF_DER).hexdigest()
_CALLER_NONCE_SLOT = 3

_SIGNER = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_STRANGER = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _jwk(key: rsa.RSAPrivateKey, kid: str = "test-kid") -> dict[str, str]:
    numbers = key.public_key().public_numbers()
    return {
        "kid": kid,
        "kty": "RSA",
        "alg": "RS256",
        "use": "sig",
        "n": _b64url(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")),
        "e": _b64url(numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")),
    }


_JWKS = {"keys": [_jwk(_SIGNER)]}


def _make_jwt(claims: dict[str, Any], *, key: rsa.RSAPrivateKey = _SIGNER) -> bytes:
    header = _b64url(json.dumps({"alg": "RS256", "kid": "test-kid", "typ": "JWT"}).encode())
    payload = _b64url(json.dumps(claims).encode())
    signature = key.sign(f"{header}.{payload}".encode(), padding.PKCS1v15(), hashes.SHA256())
    return f"{header}.{payload}.{_b64url(signature)}".encode()


def _fresh_nonce() -> str:
    return secrets.token_hex(32)


def _live_claims(nonce: str, **overrides: Any) -> dict[str, Any]:
    """The live claim set, freshly dated, answering `nonce`."""
    claims = copy.deepcopy(_LIVE_CLAIMS)
    now = int(time.time())
    claims.update(iat=now, nbf=now, exp=now + 3600)
    claims["eat_nonce"][_CALLER_NONCE_SLOT] = nonce
    claims.update(overrides)
    return claims


# What policy_from_trust_release() builds from a release that publishes this build.
_POLICY = policy_from_trust_release(
    {
        "image_digest": _LIVE_CLAIMS["submods"]["container"]["image_digest"],
        "image_reference": _LIVE_CLAIMS["submods"]["container"]["image_reference"],
    }
)


@pytest.fixture
def no_jwks_fetch(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(url: str = GCP_JWKS_URI, *, timeout: float = 10.0) -> dict[str, Any]:
        raise AssertionError(f"unexpected JWKS fetch {url}")

    monkeypatch.setattr(attestation, "_fetch_jwks", refuse)


# ---- the live shape -------------------------------------------------------


def test_live_shaped_token_verifies_with_binding_none(no_jwks_fetch: None) -> None:
    nonce = _fresh_nonce()
    result = verify_gateway_attestation_document(
        _make_jwt(_live_claims(nonce)), policy=_POLICY, nonce_hex=nonce, jwks=_JWKS
    )
    assert isinstance(result, GatewayAttestationDocument)
    assert result.binding == "none"
    assert result.nonce == nonce
    assert result.image_digest == _LIVE_CLAIMS["submods"]["container"]["image_digest"]
    assert result.image_reference == _LIVE_CLAIMS["submods"]["container"]["image_reference"]
    assert result.issuer == GCP_ISSUER
    assert result.audience == "quill-cloud"
    assert isinstance(result.expires_at, int)
    assert result.raw_claims["hwmodel"] == "GCP_INTEL_TDX"
    # No certificate is named as the connection's, so none is returned as one.
    assert not hasattr(result, "cert_sha256")
    assert _LEAF_SHA in result.cert_sha256_candidates
    assert nonce not in result.cert_sha256_candidates
    assert result.cert_sha256_candidates == tuple(_LIVE_CLAIMS["eat_nonce"][:_CALLER_NONCE_SLOT])
    assert result.as_dict() == {
        "binding": "none",
        "cert_sha256_candidates": list(result.cert_sha256_candidates),
        "image_digest": result.image_digest,
        "image_reference": result.image_reference,
        "nonce": nonce,
        "expires_at": result.expires_at,
        "issuer": GCP_ISSUER,
        "audience": "quill-cloud",
    }


def test_default_verifier_still_requires_tls_evidence_for_the_live_shape() -> None:
    nonce = _fresh_nonce()
    jwt = _make_jwt(_live_claims(nonce))
    with pytest.raises(
        AttestationVerificationError,
        match=r"does not commit to a TLS cert SHA-256.*verify_gateway_attestation_document",
    ):
        verify_gateway_attestation(jwt, policy=_POLICY, nonce_hex=nonce, jwks=_JWKS)
    bound = verify_gateway_attestation(
        jwt, policy=_POLICY, nonce_hex=nonce, tls_cert_der=_LEAF_DER, jwks=_JWKS
    )
    assert bound.binding == "tls-cert"
    assert bound.cert_sha256 == _LEAF_SHA
    assert bound.as_dict()["binding"] == "tls-cert"


def test_fetches_googles_jwks_when_none_is_supplied(monkeypatch: pytest.MonkeyPatch) -> None:
    urls: list[str] = []

    def fetch(url: str = GCP_JWKS_URI, *, timeout: float = 10.0) -> dict[str, Any]:
        urls.append(url)
        return _JWKS

    monkeypatch.setattr(attestation, "_fetch_jwks", fetch)
    nonce = _fresh_nonce()
    result = verify_gateway_attestation_document(
        _make_jwt(_live_claims(nonce)), policy=_POLICY, nonce_hex=nonce
    )
    assert urls == [GCP_JWKS_URI]
    assert result.binding == "none"


def test_uppercase_nonce_matches_the_gateways_lowercase_echo() -> None:
    nonce = _fresh_nonce()
    result = verify_gateway_attestation_document(
        _make_jwt(_live_claims(nonce)), policy=_POLICY, nonce_hex=nonce.upper(), jwks=_JWKS
    )
    assert result.nonce == nonce.upper()
    assert nonce not in result.cert_sha256_candidates


# ---- failures ---------------------------------------------------------------


def test_a_different_nonce_is_rejected() -> None:
    jwt = _make_jwt(_live_claims(_fresh_nonce()))
    with pytest.raises(AttestationVerificationError, match="not present in JWT nonces"):
        verify_gateway_attestation_document(
            jwt, policy=_POLICY, nonce_hex=_fresh_nonce(), jwks=_JWKS
        )


def test_the_nonce_must_be_in_eat_nonce_not_only_the_legacy_claim() -> None:
    nonce = _fresh_nonce()
    claims = _live_claims(nonce)
    claims["eat_nonce"] = claims["eat_nonce"][:_CALLER_NONCE_SLOT]
    claims["nonces"] = [nonce]
    with pytest.raises(AttestationVerificationError, match="not present in JWT nonces"):
        verify_gateway_attestation_document(
            _make_jwt(claims), policy=_POLICY, nonce_hex=nonce, jwks=_JWKS
        )
    del claims["eat_nonce"]
    with pytest.raises(AttestationVerificationError, match="not present in JWT nonces"):
        verify_gateway_attestation_document(
            _make_jwt(claims), policy=_POLICY, nonce_hex=nonce, jwks=_JWKS
        )


def test_a_workload_digest_outside_the_policy_is_rejected() -> None:
    nonce = _fresh_nonce()
    claims = _live_claims(nonce)
    claims["submods"]["container"]["image_digest"] = "sha256:" + "0" * 64
    with pytest.raises(AttestationVerificationError, match="image_digest mismatch"):
        verify_gateway_attestation_document(
            _make_jwt(claims), policy=_POLICY, nonce_hex=nonce, jwks=_JWKS
        )


def test_a_workload_reference_outside_the_policy_is_rejected() -> None:
    nonce = _fresh_nonce()
    claims = _live_claims(nonce)
    claims["submods"]["container"]["image_reference"] = (
        "us-central1-docker.pkg.dev/someone/else/img:tag"
    )
    with pytest.raises(AttestationVerificationError, match="image_reference mismatch"):
        verify_gateway_attestation_document(
            _make_jwt(claims), policy=_POLICY, nonce_hex=nonce, jwks=_JWKS
        )


def test_a_signature_from_an_unpublished_key_is_rejected() -> None:
    nonce = _fresh_nonce()
    with pytest.raises(AttestationVerificationError, match="signature verification failed"):
        verify_gateway_attestation_document(
            _make_jwt(_live_claims(nonce), key=_STRANGER),
            policy=_POLICY,
            nonce_hex=nonce,
            jwks=_JWKS,
        )


def test_claims_edited_after_signing_are_rejected() -> None:
    nonce = _fresh_nonce()
    header, _, signature = _make_jwt(_live_claims(_fresh_nonce())).decode().split(".")
    forged = f"{header}.{_b64url(json.dumps(_live_claims(nonce)).encode())}.{signature}"
    with pytest.raises(AttestationVerificationError, match="signature verification failed"):
        verify_gateway_attestation_document(
            forged.encode(), policy=_POLICY, nonce_hex=nonce, jwks=_JWKS
        )


def test_an_expired_token_is_rejected() -> None:
    nonce = _fresh_nonce()
    claims = _live_claims(nonce, exp=int(time.time()) - 1)
    with pytest.raises(AttestationVerificationError, match="expired"):
        verify_gateway_attestation_document(
            _make_jwt(claims), policy=_POLICY, nonce_hex=nonce, jwks=_JWKS
        )


@pytest.mark.parametrize(
    ("overrides", "pattern"),
    [
        ({"iss": "https://evil.example"}, "unexpected issuer"),
        ({"aud": "someone-else"}, "audience"),
        ({"dbgstat": "enabled"}, "disabled-since-boot"),
        ({"swname": "GCE"}, "not running Confidential Space"),
        ({"secboot": False}, "Secure Boot"),
        ({"hwmodel": "GCP_SHIELDED_VM"}, "hardware model"),
    ],
    ids=["issuer", "audience", "debug", "confidential-space", "secure-boot", "hardware"],
)
def test_every_token_check_still_runs(overrides: dict[str, Any], pattern: str) -> None:
    nonce = _fresh_nonce()
    with pytest.raises(AttestationVerificationError, match=pattern):
        verify_gateway_attestation_document(
            _make_jwt(_live_claims(nonce, **overrides)), policy=_POLICY, nonce_hex=nonce, jwks=_JWKS
        )


def test_a_policy_pinning_no_image_is_refused() -> None:
    nonce = _fresh_nonce()
    with pytest.raises(AttestationVerificationError, match="pins no image identity"):
        verify_gateway_attestation_document(
            _make_jwt(_live_claims(nonce)),
            policy=AttestationPolicy(),
            nonce_hex=nonce,
            jwks=_JWKS,
        )


@pytest.mark.parametrize(
    "nonce_hex",
    [
        None,
        "",
        7,
        "ab" * 15,  # 15 bytes: below the 16-byte floor
        "abc" * 11,  # odd length
        "zz" * 32,  # not hex
        " " + "ab" * 32,  # not trimmed for the caller
        "ab" * 32 + "\n",  # a trailing newline is not part of a hex nonce
        "ab" * 65,  # 65 bytes: above the ceiling
    ],
)
def test_a_missing_or_weak_nonce_is_refused_before_any_fetch(
    no_jwks_fetch: None, nonce_hex: Any
) -> None:
    jwt = _make_jwt(_live_claims(_fresh_nonce()))
    with pytest.raises(AttestationVerificationError, match="fresh nonce of 16 to 64 random bytes"):
        verify_gateway_attestation_document(jwt, policy=_POLICY, nonce_hex=nonce_hex)


# ---- certificate candidates ---------------------------------------------------


def test_candidates_are_hash_shaped_deduplicated_and_exclude_the_nonce() -> None:
    nonce = _fresh_nonce()
    labelled = "AB" * 32
    claims = _live_claims(
        nonce,
        tls_cert_sha256=labelled,
        eat_nonce=[_LEAF_SHA, nonce, labelled.lower(), _LEAF_SHA.upper(), "short", "f" * 65],
    )
    result = verify_gateway_attestation_document(
        _make_jwt(claims), policy=_POLICY, nonce_hex=nonce, jwks=_JWKS
    )
    assert result.cert_sha256_candidates == (labelled.lower(), _LEAF_SHA)
    assert result.binding == "none"


def test_a_single_string_eat_nonce_is_accepted() -> None:
    nonce = _fresh_nonce()
    result = verify_gateway_attestation_document(
        _make_jwt(_live_claims(nonce, eat_nonce=nonce)), policy=_POLICY, nonce_hex=nonce, jwks=_JWKS
    )
    assert result.cert_sha256_candidates == ()


# ---- binding levels of the default verifier ----------------------------------


def test_a_claimed_certificate_with_no_connection_evidence_reports_none() -> None:
    jwt = _make_jwt(_live_claims(_fresh_nonce(), tls_cert_sha256=_LEAF_SHA))
    claimed = verify_gateway_attestation(jwt, policy=_POLICY, jwks=_JWKS)
    assert claimed.binding == "none"
    assert claimed.cert_sha256 == _LEAF_SHA
    # A policy pin compares against a published hash, not this connection.
    pinned_policy = policy_from_trust_release(
        {"image_digest": _LIVE_CLAIMS["submods"]["container"]["image_digest"]},
        cert_sha256=_LEAF_SHA,
    )
    pinned = verify_gateway_attestation(jwt, policy=pinned_policy, jwks=_JWKS)
    assert pinned.binding == "none"


def test_a_matching_certificate_reports_tls_cert_and_a_different_one_is_rejected() -> None:
    nonce = _fresh_nonce()
    jwt = _make_jwt(_live_claims(nonce, tls_cert_sha256=_LEAF_SHA))
    bound = verify_gateway_attestation(
        jwt, policy=_POLICY, nonce_hex=nonce, tls_cert_der=_LEAF_DER, jwks=_JWKS
    )
    assert bound.binding == "tls-cert"
    with pytest.raises(AttestationVerificationError, match="TLS cert mismatch"):
        verify_gateway_attestation(
            jwt, policy=_POLICY, nonce_hex=nonce, tls_cert_der=b"\x01\x02\x03", jwks=_JWKS
        )


def test_a_committed_tls_exporter_reports_tls_exporter() -> None:
    nonce = _fresh_nonce()
    exporter = secrets.token_bytes(EXPORTER_LENGTH)
    claims = _live_claims(nonce)
    claims["eat_nonce"][2] = exporter.hex()
    result = verify_gateway_attestation(
        _make_jwt(claims),
        policy=_POLICY,
        nonce_hex=nonce,
        tls_cert_der=_LEAF_DER,
        tls_exporter=exporter,
        jwks=_JWKS,
    )
    assert result.binding == "tls-exporter"
    assert result.cert_sha256 == _LEAF_SHA


# ---- fetching a challenged document --------------------------------------------


def test_client_attestation_sends_the_nonce_to_the_api_root() -> None:
    urls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        urls.append(str(request.url))
        return httpx.Response(200, content=b"header.payload.signature")

    nonce = _fresh_nonce()
    with TrustedRouter(
        api_key="k", client=httpx.Client(transport=httpx.MockTransport(handler))
    ) as client:
        assert client.attestation(nonce_hex=nonce) == b"header.payload.signature"
        client.attestation()
    assert urls == [
        f"https://api.trustedrouter.com/attestation?nonce={nonce}",
        "https://api.trustedrouter.com/attestation",
    ]


async def test_async_client_attestation_sends_the_nonce_to_the_api_root() -> None:
    urls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        urls.append(str(request.url))
        return httpx.Response(200, content=b"header.payload.signature")

    nonce = _fresh_nonce()
    async with AsyncTrustedRouter(
        api_key="k", client=httpx.AsyncClient(transport=httpx.MockTransport(handler))
    ) as client:
        assert await client.attestation(nonce_hex=nonce) == b"header.payload.signature"
        await client.attestation()
    assert urls == [
        f"https://api.trustedrouter.com/attestation?nonce={nonce}",
        "https://api.trustedrouter.com/attestation",
    ]
