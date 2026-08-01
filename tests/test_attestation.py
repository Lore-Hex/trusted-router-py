"""Coverage for the attestation verifier.

The strategy: generate an RSA keypair in-test, build a JWT signed with
it, expose its public half via a JWKS dict that mimics Google's JWKS
endpoint shape. Then drive verify_gateway_attestation() against
crafted-but-real JWTs to exercise both the happy path and every claim
mismatch we want to fail loudly on.

This means the tests do real RS256 signature verification — no
mocking of the crypto path, which is exactly the surface area we
care about being correct."""
from __future__ import annotations

import base64
import hashlib
import json
import time

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from trustedrouter.attestation import (
    GCP_ISSUER,
    AttestationPolicy,
    AttestationVerificationError,
    GatewayAttestation,
    policy_from_trust_release,
    verify_gateway_attestation,
)

# ---- helpers -------------------------------------------------------------


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _gen_keypair():  # type: ignore[no-untyped-def]
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _public_jwk(key, kid="test-kid"):  # type: ignore[no-untyped-def]
    public = key.public_key()
    numbers = public.public_numbers()
    n = numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")
    e = numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big") or b"\x01\x00\x01"
    return {
        "kid": kid,
        "kty": "RSA",
        "alg": "RS256",
        "use": "sig",
        "n": _b64url(n),
        "e": _b64url(e),
    }


def _make_jwt(key, claims, *, kid="test-kid", alg="RS256"):  # type: ignore[no-untyped-def]
    header = {"alg": alg, "typ": "JWT", "kid": kid}
    h = _b64url(json.dumps(header).encode())
    p = _b64url(json.dumps(claims).encode())
    signing_input = f"{h}.{p}".encode()
    sig = key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return f"{h}.{p}.{_b64url(sig)}".encode()


_FAKE_CERT = b"FAKE-CERT-DER-BYTES-FOR-TESTING"
_FAKE_CERT_SHA = hashlib.sha256(_FAKE_CERT).hexdigest()


def _good_claims(*, nonce_hex: str | None = None) -> dict[str, object]:
    nonces = [nonce_hex, _FAKE_CERT_SHA] if nonce_hex else [_FAKE_CERT_SHA]
    return {
        "iss": GCP_ISSUER,
        "aud": ["quill-cloud"],
        "exp": int(time.time()) + 600,
        "dbgstat": "disabled-since-boot",
        "swname": "CONFIDENTIAL_SPACE",
        "secboot": True,
        "hwmodel": "GCP_AMD_SEV",
        "submods": {
            "container": {
                "image_digest": "sha256:abc123",
                "image_reference": "us-central1-docker.pkg.dev/proj/repo/img:tag",
            }
        },
        "tls_cert_sha256": _FAKE_CERT_SHA,
        "eat_nonce": nonces,
    }


# ---- happy path ---------------------------------------------------------


def test_verify_happy_path_returns_attestation() -> None:
    key = _gen_keypair()
    jwks = {"keys": [_public_jwk(key)]}
    nonce = "deadbeef" * 4
    jwt = _make_jwt(key, _good_claims(nonce_hex=nonce))
    policy = AttestationPolicy(
        gcp_audience="quill-cloud",
        expected_image_digest="sha256:abc123",
        expected_image_reference="us-central1-docker.pkg.dev/proj/repo/img:tag",
    )

    result = verify_gateway_attestation(
        jwt, policy=policy, nonce_hex=nonce, tls_cert_der=_FAKE_CERT, jwks=jwks
    )

    assert isinstance(result, GatewayAttestation)
    assert result.cert_sha256 == _FAKE_CERT_SHA
    assert result.image_digest == "sha256:abc123"
    assert result.image_reference == "us-central1-docker.pkg.dev/proj/repo/img:tag"
    assert result.nonce == nonce
    assert result.audience == "quill-cloud"
    assert result.issuer == GCP_ISSUER
    # as_dict() round-trips the public surface
    d = result.as_dict()
    assert d["cert_sha256"] == _FAKE_CERT_SHA
    assert d["image_digest"] == "sha256:abc123"


def test_verify_tls_exporter_binding_accepts_distinct_fresh_nonce() -> None:
    key = _gen_keypair()
    jwks = {"keys": [_public_jwk(key)]}
    exporter = bytes.fromhex("aa" * 32)
    nonce = "bb" * 32
    claims = _good_claims(nonce_hex=nonce)
    assert isinstance(claims["eat_nonce"], list)
    claims["eat_nonce"].append(exporter.hex())
    jwt = _make_jwt(key, claims)

    result = verify_gateway_attestation(
        jwt,
        policy=AttestationPolicy(),
        nonce_hex=nonce,
        tls_cert_der=_FAKE_CERT,
        tls_exporter=exporter,
        jwks=jwks,
    )

    assert result.nonce == nonce


def test_verify_tls_exporter_binding_rejects_missing_exporter_nonce() -> None:
    key = _gen_keypair()
    exporter = bytes.fromhex("aa" * 32)
    nonce = "bb" * 32
    jwt = _make_jwt(key, _good_claims(nonce_hex=nonce))

    with pytest.raises(AttestationVerificationError, match="TLS exporter binding"):
        verify_gateway_attestation(
            jwt,
            policy=AttestationPolicy(),
            nonce_hex=nonce,
            tls_cert_der=_FAKE_CERT,
            tls_exporter=exporter,
            jwks={"keys": [_public_jwk(key)]},
        )


def test_verify_tls_exporter_binding_rejects_missing_fresh_nonce() -> None:
    key = _gen_keypair()
    exporter = bytes.fromhex("aa" * 32)
    claims = _good_claims()
    assert isinstance(claims["eat_nonce"], list)
    claims["eat_nonce"].append(exporter.hex())
    jwt = _make_jwt(key, claims)

    with pytest.raises(AttestationVerificationError, match="fresh nonce required"):
        verify_gateway_attestation(
            jwt,
            policy=AttestationPolicy(),
            tls_cert_der=_FAKE_CERT,
            tls_exporter=exporter,
            jwks={"keys": [_public_jwk(key)]},
        )


def test_verify_tls_exporter_binding_rejects_single_slot_relay_closure() -> None:
    key = _gen_keypair()
    exporter = bytes.fromhex("aa" * 32)
    claims = _good_claims(nonce_hex=exporter.hex())
    jwt = _make_jwt(key, claims)

    with pytest.raises(AttestationVerificationError, match="fresh nonce must differ"):
        verify_gateway_attestation(
            jwt,
            policy=AttestationPolicy(),
            nonce_hex=exporter.hex(),
            tls_cert_der=_FAKE_CERT,
            tls_exporter=exporter,
            jwks={"keys": [_public_jwk(key)]},
        )


def test_verify_works_when_aud_is_a_string_not_a_list() -> None:
    """Per RFC 7519 `aud` may be string OR array — we accept both."""
    key = _gen_keypair()
    jwks = {"keys": [_public_jwk(key)]}
    claims = _good_claims()
    claims["aud"] = "quill-cloud"  # string form
    jwt = _make_jwt(key, claims)
    policy = AttestationPolicy(expected_image_digest="sha256:abc123")
    result = verify_gateway_attestation(jwt, policy=policy, tls_cert_der=_FAKE_CERT, jwks=jwks)
    assert result.audience == "quill-cloud"


# ---- failure modes ------------------------------------------------------


def test_malformed_jwt_raises() -> None:
    with pytest.raises(AttestationVerificationError, match="3 JWT segments"):
        verify_gateway_attestation(
            b"only.two", policy=AttestationPolicy(), jwks={"keys": []}
        )


def test_bad_base64_in_jwt_raises() -> None:
    with pytest.raises(AttestationVerificationError, match="invalid JWT"):
        verify_gateway_attestation(
            b"!!!.???.@@@", policy=AttestationPolicy(), jwks={"keys": []}
        )


def test_unsupported_alg_raises() -> None:
    key = _gen_keypair()
    jwt = _make_jwt(key, _good_claims(), alg="HS256")
    with pytest.raises(AttestationVerificationError, match="unsupported JWT alg"):
        verify_gateway_attestation(
            jwt, policy=AttestationPolicy(), jwks={"keys": [_public_jwk(key)]}
        )


def test_missing_kid_in_jwks_raises() -> None:
    key = _gen_keypair()
    jwt = _make_jwt(key, _good_claims(), kid="missing-kid")
    with pytest.raises(AttestationVerificationError, match="no JWK with kid"):
        verify_gateway_attestation(
            jwt, policy=AttestationPolicy(), jwks={"keys": [_public_jwk(key, kid="other")]}
        )


def test_signature_mismatch_raises() -> None:
    """JWT signed by key A but verified against JWKS containing key B —
    must fail signature verification."""
    key_a = _gen_keypair()
    key_b = _gen_keypair()
    jwt = _make_jwt(key_a, _good_claims())
    with pytest.raises(AttestationVerificationError, match="signature"):
        verify_gateway_attestation(
            jwt, policy=AttestationPolicy(), jwks={"keys": [_public_jwk(key_b)]}
        )


def test_expired_jwt_raises() -> None:
    key = _gen_keypair()
    claims = _good_claims()
    claims["exp"] = int(time.time()) - 60  # expired a minute ago
    jwt = _make_jwt(key, claims)
    with pytest.raises(AttestationVerificationError, match="expired"):
        verify_gateway_attestation(
            jwt, policy=AttestationPolicy(), jwks={"keys": [_public_jwk(key)]}
        )


@pytest.mark.parametrize("exp", [None, "soon", True])
def test_missing_or_invalid_expiration_raises(exp: object) -> None:
    key = _gen_keypair()
    claims = _good_claims()
    if exp is None:
        del claims["exp"]
    else:
        claims["exp"] = exp
    jwt = _make_jwt(key, claims)
    with pytest.raises(AttestationVerificationError, match="valid expiration"):
        verify_gateway_attestation(
            jwt, policy=AttestationPolicy(), jwks={"keys": [_public_jwk(key)]}
        )


@pytest.mark.parametrize("field", ["dbgstat", "swname", "secboot", "hwmodel"])
def test_production_attestation_claims_fail_closed(field: str) -> None:
    key = _gen_keypair()
    claims = _good_claims()
    del claims[field]
    jwt = _make_jwt(key, claims)
    with pytest.raises(AttestationVerificationError):
        verify_gateway_attestation(
            jwt, policy=AttestationPolicy(), jwks={"keys": [_public_jwk(key)]}
        )


def test_debug_attestation_requires_explicit_development_opt_out() -> None:
    key = _gen_keypair()
    claims = _good_claims()
    claims["dbgstat"] = "enabled"
    jwt = _make_jwt(key, claims)
    with pytest.raises(AttestationVerificationError, match="disabled-since-boot"):
        verify_gateway_attestation(
            jwt, policy=AttestationPolicy(), jwks={"keys": [_public_jwk(key)]}
        )
    result = verify_gateway_attestation(
        jwt,
        policy=AttestationPolicy(allow_debug=True),
        jwks={"keys": [_public_jwk(key)]},
    )
    assert result.raw_claims["dbgstat"] == "enabled"


def test_invalid_audience_shape_raises() -> None:
    key = _gen_keypair()
    claims = _good_claims()
    claims["aud"] = {"quill-cloud": True}
    jwt = _make_jwt(key, claims)
    with pytest.raises(AttestationVerificationError, match="aud must"):
        verify_gateway_attestation(
            jwt, policy=AttestationPolicy(), jwks={"keys": [_public_jwk(key)]}
        )


def test_wrong_issuer_raises() -> None:
    key = _gen_keypair()
    claims = _good_claims()
    claims["iss"] = "https://evil.example/issuer"
    jwt = _make_jwt(key, claims)
    with pytest.raises(AttestationVerificationError, match="issuer"):
        verify_gateway_attestation(
            jwt, policy=AttestationPolicy(), jwks={"keys": [_public_jwk(key)]}
        )


def test_wrong_audience_raises() -> None:
    key = _gen_keypair()
    claims = _good_claims()
    claims["aud"] = ["someone-else"]
    jwt = _make_jwt(key, claims)
    with pytest.raises(AttestationVerificationError, match="audience"):
        verify_gateway_attestation(
            jwt, policy=AttestationPolicy(), jwks={"keys": [_public_jwk(key)]}
        )


def test_image_digest_mismatch_raises() -> None:
    key = _gen_keypair()
    jwt = _make_jwt(key, _good_claims())
    policy = AttestationPolicy(expected_image_digest="sha256:DIFFERENT")
    with pytest.raises(AttestationVerificationError, match="image_digest mismatch"):
        verify_gateway_attestation(
            jwt, policy=policy, tls_cert_der=_FAKE_CERT, jwks={"keys": [_public_jwk(key)]}
        )


def test_image_reference_mismatch_raises() -> None:
    key = _gen_keypair()
    jwt = _make_jwt(key, _good_claims())
    policy = AttestationPolicy(expected_image_reference="europe-docker.pkg.dev/x/y/z:tag")
    with pytest.raises(AttestationVerificationError, match="image_reference mismatch"):
        verify_gateway_attestation(
            jwt, policy=policy, tls_cert_der=_FAKE_CERT, jwks={"keys": [_public_jwk(key)]}
        )


def test_missing_nonce_raises_when_caller_supplied_one() -> None:
    """Replay defense: caller put a nonce in /attestation but the JWT
    doesn't echo it — fail closed."""
    key = _gen_keypair()
    claims = _good_claims()  # has its own nonces but not "expected"
    jwt = _make_jwt(key, claims)
    with pytest.raises(AttestationVerificationError, match="nonce"):
        verify_gateway_attestation(
            jwt,
            policy=AttestationPolicy(),
            nonce_hex="expected-nonce-hex",
            tls_cert_der=_FAKE_CERT,
            jwks={"keys": [_public_jwk(key)]},
        )


def test_missing_cert_binding_raises() -> None:
    """JWT must commit to a cert SHA-256 — without one, we can't bind
    the document to any TLS connection. Refuse to return a result."""
    key = _gen_keypair()
    claims = _good_claims()
    del claims["tls_cert_sha256"]
    claims["eat_nonce"] = []  # no cert sha in nonces either
    jwt = _make_jwt(key, claims)
    with pytest.raises(AttestationVerificationError, match="TLS cert"):
        verify_gateway_attestation(
            jwt, policy=AttestationPolicy(), tls_cert_der=_FAKE_CERT,
            jwks={"keys": [_public_jwk(key)]},
        )


def test_jwt_cert_sha_mismatch_with_actual_tls_cert_raises() -> None:
    """JWT commits to one cert, but the actual TLS cert we're connected
    to has a different SHA-256 — this is exactly the MITM detection
    contract. Must fail."""
    key = _gen_keypair()
    claims = _good_claims()
    claims["tls_cert_sha256"] = "0" * 64  # legit-looking but wrong cert
    claims["eat_nonce"] = ["0" * 64]
    jwt = _make_jwt(key, claims)
    with pytest.raises(AttestationVerificationError, match="TLS cert mismatch"):
        verify_gateway_attestation(
            jwt, policy=AttestationPolicy(), tls_cert_der=_FAKE_CERT,
            jwks={"keys": [_public_jwk(key)]},
        )


def test_policy_pin_overrides_runtime_when_set() -> None:
    """Even if cert+JWT agree, an explicit policy.expected_cert_sha256
    that doesn't match must fail. This is the trust-page-pin path."""
    key = _gen_keypair()
    jwt = _make_jwt(key, _good_claims())
    policy = AttestationPolicy(expected_cert_sha256="0" * 64)
    with pytest.raises(AttestationVerificationError, match="policy pin"):
        verify_gateway_attestation(
            jwt, policy=policy, tls_cert_der=_FAKE_CERT,
            jwks={"keys": [_public_jwk(key)]},
        )


# ---- policy_from_trust_release helper -----------------------------------


def test_policy_from_trust_release_pulls_digest_and_reference() -> None:
    release = {
        "image_digest": "sha256:beef",
        "image_reference": "us-central1-docker.pkg.dev/p/r/i:tag",
    }
    policy = policy_from_trust_release(release=release)
    assert policy.expected_image_digest == "sha256:beef"
    assert policy.expected_image_reference == "us-central1-docker.pkg.dev/p/r/i:tag"
    assert policy.gcp_audience == "quill-cloud"


def test_policy_from_trust_release_handles_missing_fields() -> None:
    """If the trust release lacks the digest/reference, the policy fields
    are None — verifier will skip those checks."""
    policy = policy_from_trust_release(release={})
    assert policy.expected_image_digest is None
    assert policy.expected_image_reference is None
