from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import trustedrouter.attestation as attestation_module
import trustedrouter.receipts as receipts_module
from trustedrouter.attestation import (
    GCP_ISSUER,
    GCP_JWKS_URI,
    AttestationPolicy,
    AttestationVerificationError,
    verify_gateway_attestation,
)
from trustedrouter.receipts import (
    MissingAttestationError,
    MissingBindingError,
    ReceiptAttestationError,
    ReceiptCapture,
    ReceiptHashError,
    ReceiptHeaderError,
    ReceiptIssuerError,
    ReceiptNonceError,
    ReceiptSignatureError,
    ReceiptTimeError,
    ReceiptUpstreamError,
    UnsupportedAttestationError,
    verify_receipt,
)

NOW = 1_756_223_999
EXPECTED_ISSUER = "https://api.trustedrouter.com"


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _digest(value: bytes) -> str:
    return _b64(hashlib.sha256(value).digest())


def _claims(*, response_of: str = "body", response_hash: str | None = None) -> dict[str, Any]:
    response: dict[str, Any] = {
        "alg": "sha256",
        "hash": response_hash or _digest(b"response"),
        "of": response_of,
    }
    if response_of != "body":
        response["events"] = 1
    return {
        "rv": 1,
        "iss": "https://api.trustedrouter.com",
        "iat": NOW,
        "jti": "chatcmpl-test",
        "gen": "gen-test",
        "nonce": "nonce_test",
        "route": "chat.completions",
        "req": {"alg": "sha256", "hash": _digest(b"request"), "of": "body"},
        "resp": response,
        "model": {
            "requested": "requested",
            "selected": "selected",
            "provider": "provider",
            "endpoint": "endpoint",
        },
        "upstream": {
            "tier": "tee-verified",
            "policy": "chutes-tdx-nvidia-e2e-v1",
            "verified_at": NOW - 60,
            "verification_expires_at": NOW + 240,
        },
        "att_sha256": _digest(b"attestation"),
    }


def _sign(
    claims: Mapping[str, Any],
    *,
    key: Ed25519PrivateKey | None = None,
    flattened: bool = False,
    header_updates: Mapping[str, Any] | None = None,
    signing_key: Ed25519PrivateKey | None = None,
) -> tuple[str | dict[str, str], Ed25519PrivateKey]:
    key = key or Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes_raw()
    header: dict[str, Any] = {
        "alg": "EdDSA",
        "typ": "inference-receipt+jws",
        "kid": _digest(public),
        "jwk": {"kty": "OKP", "crv": "Ed25519", "x": _b64(public)},
    }
    if flattened:
        header.update({"att": "fake.jwt.token", "att_kind": "gcp-cs-jwt"})
    if header_updates:
        header.update(header_updates)
    protected = _b64(json.dumps(header, separators=(",", ":")).encode())
    payload = _b64(json.dumps(dict(claims), separators=(",", ":")).encode())
    signature = _b64((signing_key or key).sign(f"{protected}.{payload}".encode()))
    if flattened:
        return {"protected": protected, "payload": payload, "signature": signature}, key
    return f"{protected}.{payload}.{signature}", key


def _receipt_event(receipt: Mapping[str, str]) -> bytes:
    payload = json.dumps(
        {
            "id": "chatcmpl-test",
            "object": "chat.completion.chunk",
            "choices": [],
            "inference_receipt": dict(receipt),
        },
        separators=(",", ":"),
    ).encode()
    return b"data: " + payload + b"\n\n"


def _gcp_key_attestation(nonces: list[str]) -> bytes:
    header = _b64(json.dumps({"alg": "RS256", "kid": "test-kid"}).encode())
    claims = {
        "iss": GCP_ISSUER,
        "aud": ["quill-cloud"],
        "exp": 4_000_000_000,
        "dbgstat": "disabled-since-boot",
        "swname": "CONFIDENTIAL_SPACE",
        "secboot": True,
        "hwmodel": "GCP_AMD_SEV",
        "submods": {
            "container": {
                "image_digest": "sha256:abc123",
                "image_reference": "registry.example/image:tag",
            }
        },
        "eat_nonce": nonces,
    }
    payload = _b64(json.dumps(claims).encode())
    return f"{header}.{payload}.{_b64(b'fake-signature')}".encode()


def _mock_gcp_signature_and_policy(monkeypatch: pytest.MonkeyPatch) -> AttestationPolicy:
    policy = AttestationPolicy(expected_image_digest="sha256:abc123")
    monkeypatch.setattr(attestation_module, "_verify_rs256", lambda *_args: None)
    monkeypatch.setattr(attestation_module, "_fetch_jwks", lambda *_args, **_kwargs: {"keys": []})
    monkeypatch.setattr(receipts_module, "policy_from_trust_release", lambda: policy)
    return policy


def _stream_receipt(
    monkeypatch: pytest.MonkeyPatch, *, events_claim: int = 1
) -> tuple[dict[str, str], bytes]:
    monkeypatch.setattr(receipts_module, "_verify_gcp_attestation", lambda _att, _key: None)
    data_payload = b'{"choices":[{"delta":{"content":"hello"}}]}'
    claims = _claims(response_of="sse-data-v1", response_hash=_digest(data_payload + b"\n"))
    claims.pop("att_sha256")
    claims["resp"]["events"] = events_claim
    receipt, _ = _sign(claims, flattened=True)
    assert isinstance(receipt, dict)
    stream = b"data: " + data_payload + b"\n\n" + _receipt_event(receipt) + b"data: [DONE]\n\n"
    return receipt, stream


def test_compact_receipt_verifies_bodies_with_explicit_attestation_escape() -> None:
    receipt, _ = _sign(_claims())
    claims = verify_receipt(
        receipt,
        expected_issuer=EXPECTED_ISSUER,
        request_body=b"request",
        response_body=b"response",
        expected_nonce="nonce_test",
        max_age_seconds=10,
        now=NOW,
        require_attestation=False,
    )
    assert claims.rv == 1
    assert claims.req.of == "body"
    assert claims.model.provider == "provider"
    assert claims.upstream.tier == "tee-verified"
    assert claims.attestation_status == "unverified_by_this_sdk"


def test_bindings_are_required_by_default_and_can_be_explicitly_disabled() -> None:
    receipt, _ = _sign(_claims())

    with pytest.raises(
        MissingBindingError,
        match="missing request_body and response_body or response_stream",
    ):
        verify_receipt(
            receipt,
            expected_issuer=EXPECTED_ISSUER,
            now=NOW,
            require_attestation=False,
        )

    claims = verify_receipt(
        receipt,
        expected_issuer=EXPECTED_ISSUER,
        now=NOW,
        require_attestation=False,
        require_bindings=False,
    )
    assert claims.iss == EXPECTED_ISSUER


def test_partial_bindings_fail_closed_by_default() -> None:
    receipt, _ = _sign(_claims())

    with pytest.raises(MissingBindingError, match="missing response_body or response_stream"):
        verify_receipt(
            receipt,
            expected_issuer=EXPECTED_ISSUER,
            request_body=b"request",
            now=NOW,
            require_attestation=False,
        )
    with pytest.raises(MissingBindingError, match="missing request_body"):
        verify_receipt(
            receipt,
            expected_issuer=EXPECTED_ISSUER,
            response_body=b"response",
            now=NOW,
            require_attestation=False,
        )


def test_expected_issuer_exact_match_passes_and_mismatch_is_typed() -> None:
    receipt, _ = _sign(_claims())
    verified = verify_receipt(
        receipt,
        expected_issuer=EXPECTED_ISSUER,
        now=NOW,
        require_attestation=False,
        require_bindings=False,
    )
    assert verified.iss == EXPECTED_ISSUER

    with pytest.raises(ReceiptIssuerError, match="iss claim check failed: expected"):
        verify_receipt(
            receipt,
            expected_issuer="https://other.example",
            now=NOW,
            require_attestation=False,
            require_bindings=False,
        )


@pytest.mark.parametrize(
    ("receipt_issuer", "expected_issuer"),
    [
        ("https://API.TrustedRouter.COM/", "HTTPS://api.trustedrouter.com"),
        ("https://API.TrustedRouter.COM:8443/", "https://api.trustedrouter.com:8443"),
    ],
)
def test_issuer_origin_normalization(
    receipt_issuer: str,
    expected_issuer: str,
) -> None:
    claims = _claims()
    claims["iss"] = receipt_issuer
    receipt, _ = _sign(claims)

    verified = verify_receipt(
        receipt,
        expected_issuer=expected_issuer,
        now=NOW,
        require_attestation=False,
        require_bindings=False,
    )
    assert verified.iss == receipt_issuer


def test_issuer_port_must_match_exactly_after_normalization() -> None:
    claims = _claims()
    claims["iss"] = f"{EXPECTED_ISSUER}:8443"
    receipt, _ = _sign(claims)

    with pytest.raises(ReceiptIssuerError, match="iss claim check failed: expected"):
        verify_receipt(
            receipt,
            expected_issuer=EXPECTED_ISSUER,
            now=NOW,
            require_attestation=False,
            require_bindings=False,
        )


def test_http_receipt_issuer_is_rejected() -> None:
    claims = _claims()
    claims["iss"] = "http://api.trustedrouter.com"
    receipt, _ = _sign(claims)

    with pytest.raises(ReceiptIssuerError, match="must use https"):
        verify_receipt(
            receipt,
            expected_issuer=EXPECTED_ISSUER,
            now=NOW,
            require_attestation=False,
            require_bindings=False,
        )


def test_flipped_payload_byte_fails_signature() -> None:
    receipt, _ = _sign(_claims())
    assert isinstance(receipt, str)
    protected, payload, signature = receipt.split(".")
    payload_bytes = bytearray(_decode(payload))
    payload_bytes[-2] ^= 1
    tampered = f"{protected}.{_b64(bytes(payload_bytes))}.{signature}"
    with pytest.raises(ReceiptSignatureError, match="signature check failed"):
        verify_receipt(
            tampered,
            expected_issuer=EXPECTED_ISSUER,
            now=NOW,
            require_attestation=False,
            require_bindings=False,
        )


def test_resigned_with_wrong_key_fails_signature() -> None:
    key = Ed25519PrivateKey.generate()
    receipt, _ = _sign(_claims(), key=key, signing_key=Ed25519PrivateKey.generate())
    with pytest.raises(ReceiptSignatureError, match="signature check failed"):
        verify_receipt(
            receipt,
            expected_issuer=EXPECTED_ISSUER,
            now=NOW,
            require_attestation=False,
            require_bindings=False,
        )


def test_edited_claim_without_resigning_fails_signature() -> None:
    receipt, _ = _sign(_claims())
    assert isinstance(receipt, str)
    protected, payload, signature = receipt.split(".")
    claims = json.loads(_decode(payload))
    claims["model"]["selected"] = "tampered"
    edited = f"{protected}.{_b64(json.dumps(claims).encode())}.{signature}"
    with pytest.raises(ReceiptSignatureError, match="signature check failed"):
        verify_receipt(
            edited,
            expected_issuer=EXPECTED_ISSUER,
            now=NOW,
            require_attestation=False,
            require_bindings=False,
        )


def test_wrong_kid_fails_header_check_before_signature() -> None:
    receipt, _ = _sign(_claims(), header_updates={"kid": _digest(b"wrong")})
    with pytest.raises(ReceiptHeaderError, match="kid check failed"):
        verify_receipt(
            receipt,
            expected_issuer=EXPECTED_ISSUER,
            now=NOW,
            require_attestation=False,
            require_bindings=False,
        )


def test_stream_byte_flip_fails_hash(monkeypatch: pytest.MonkeyPatch) -> None:
    receipt, stream = _stream_receipt(monkeypatch)
    with pytest.raises(ReceiptHashError, match="stream hash check failed"):
        verify_receipt(
            receipt,
            expected_issuer=EXPECTED_ISSUER,
            request_body=b"request",
            response_stream=stream.replace(b"hello", b"jello"),
            now=NOW,
        )


def test_receipt_must_be_last_before_done(monkeypatch: pytest.MonkeyPatch) -> None:
    receipt, stream = _stream_receipt(monkeypatch)
    extra = b'data: {"choices":[]}\n\n'
    tampered = stream.replace(b"data: [DONE]", extra + b"data: [DONE]")
    with pytest.raises(ReceiptHashError, match="not the last data event"):
        verify_receipt(
            receipt,
            expected_issuer=EXPECTED_ISSUER,
            request_body=b"request",
            response_stream=tampered,
            now=NOW,
        )


def test_stream_events_off_by_one_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    receipt, stream = _stream_receipt(monkeypatch, events_claim=2)
    with pytest.raises(ReceiptHashError, match="events check failed"):
        verify_receipt(
            receipt,
            expected_issuer=EXPECTED_ISSUER,
            request_body=b"request",
            response_stream=stream,
            now=NOW,
        )


def test_responses_named_event_domain_and_crlf_verify(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(receipts_module, "_verify_gcp_attestation", lambda _att, _key: None)
    name = b"response.output_text.delta"
    payload = b'{"delta":"hello"}'
    preimage = name + b"\n" + payload + b"\n"
    claims = _claims(response_of="sse-events-v1", response_hash=_digest(preimage))
    claims.pop("att_sha256")
    claims["route"] = "responses"
    receipt, _ = _sign(claims, flattened=True)
    assert isinstance(receipt, dict)
    receipt_event = _receipt_event(receipt).replace(b"\n", b"\r\n")
    stream = (
        b"event: "
        + name
        + b"\r\ndata: "
        + payload
        + b"\r\n\r\n"
        + receipt_event
        + b"data: [DONE]\r\n\r\n"
    )
    verified = verify_receipt(
        receipt,
        expected_issuer=EXPECTED_ISSUER,
        request_body=b"request",
        response_stream=stream,
        now=NOW,
    )
    assert verified.route == "responses"
    assert verified.resp.events == 1


def test_future_iat_fails() -> None:
    claims = _claims()
    claims["iat"] = NOW + 61
    receipt, _ = _sign(claims)
    with pytest.raises(ReceiptTimeError, match="future-skew check failed"):
        verify_receipt(
            receipt,
            expected_issuer=EXPECTED_ISSUER,
            now=NOW,
            require_attestation=False,
            require_bindings=False,
        )


def test_max_age_fails_for_an_old_receipt() -> None:
    receipt, _ = _sign(_claims())
    with pytest.raises(ReceiptTimeError, match="max-age check failed"):
        verify_receipt(
            receipt,
            expected_issuer=EXPECTED_ISSUER,
            now=NOW + 11,
            max_age_seconds=10,
            require_attestation=False,
            require_bindings=False,
        )


def test_expired_tee_verified_window_fails() -> None:
    claims = _claims()
    claims["upstream"]["verification_expires_at"] = NOW
    receipt, _ = _sign(claims)
    with pytest.raises(ReceiptUpstreamError, match="tee-verified window check failed"):
        verify_receipt(
            receipt,
            expected_issuer=EXPECTED_ISSUER,
            now=NOW,
            require_attestation=False,
            require_bindings=False,
        )


def test_nonce_mismatch_fails() -> None:
    receipt, _ = _sign(_claims())
    with pytest.raises(ReceiptNonceError, match="nonce match check failed"):
        verify_receipt(
            receipt,
            expected_issuer=EXPECTED_ISSUER,
            expected_nonce="different",
            now=NOW,
            require_attestation=False,
            require_bindings=False,
        )


@pytest.mark.parametrize("kind", ["aws-nitro-cose", "azure-maa-jwt"])
def test_unsupported_attestation_kind_fails_closed(kind: str) -> None:
    claims = _claims()
    claims.pop("att_sha256")
    receipt, _ = _sign(claims, flattened=True, header_updates={"att_kind": kind})
    with pytest.raises(UnsupportedAttestationError, match="not supported"):
        verify_receipt(
            receipt,
            expected_issuer=EXPECTED_ISSUER,
            now=NOW,
            require_attestation=False,
            require_bindings=False,
        )


def test_missing_attestation_fails_by_default_for_both_delivery_forms() -> None:
    compact, _ = _sign(_claims())
    with pytest.raises(MissingAttestationError, match="compact receipts omit"):
        verify_receipt(
            compact,
            expected_issuer=EXPECTED_ISSUER,
            now=NOW,
            require_bindings=False,
        )

    claims = _claims()
    claims.pop("att_sha256")
    flattened, _ = _sign(
        claims,
        flattened=True,
        header_updates={"att": None, "att_kind": None},
    )
    with pytest.raises(MissingAttestationError, match="no att_kind"):
        verify_receipt(
            flattened,
            expected_issuer=EXPECTED_ISSUER,
            now=NOW,
            require_attestation=False,
            require_bindings=False,
        )


def test_gcp_attestation_reuses_verifier_and_checks_commitment_membership(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = object()
    seen: dict[str, Any] = {}
    monkeypatch.setattr(receipts_module, "policy_from_trust_release", lambda: policy)

    def fake_verify(document: bytes, **kwargs: Any) -> None:
        seen.update(document=document, **kwargs)

    monkeypatch.setattr(receipts_module, "verify_receipt_key_attestation", fake_verify)
    claims = _claims()
    claims.pop("att_sha256")
    receipt, key = _sign(claims, flattened=True)
    verified = verify_receipt(
        receipt,
        expected_issuer=EXPECTED_ISSUER,
        now=NOW,
        require_bindings=False,
    )
    public = key.public_key().public_bytes_raw()
    commitment = hashlib.sha256(b"inference-receipt-key-v1\x00" + public).hexdigest()
    assert verified.attestation_status == "verified"
    assert seen == {
        "document": b"fake.jwt.token",
        "policy": policy,
        "key_commitment_hex": commitment,
    }


def test_receipt_issuer_is_never_used_to_fetch_verification_material(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    hostile_issuer = "https://evil.example"
    policy = AttestationPolicy(expected_image_digest="sha256:abc123")
    key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes_raw()
    commitment = hashlib.sha256(b"inference-receipt-key-v1\x00" + public).hexdigest()
    document = _gcp_key_attestation([commitment])
    claims = _claims()
    claims["iss"] = hostile_issuer
    claims.pop("att_sha256")
    receipt, _ = _sign(
        claims,
        key=key,
        flattened=True,
        header_updates={"att": document.decode("ascii")},
    )
    requested_urls: list[str] = []

    class FakeResponse:
        def raise_for_status(self) -> None:
            pass

        def json(self) -> dict[str, Any]:
            return {"keys": []}

    def guarded_get(_client: Any, url: str) -> FakeResponse:
        requested_urls.append(url)
        if urlsplit(url).hostname == urlsplit(hostile_issuer).hostname:
            pytest.fail("receipt issuer was dereferenced for verification material")
        return FakeResponse()

    monkeypatch.setattr(receipts_module, "policy_from_trust_release", lambda: policy)
    monkeypatch.setattr(attestation_module, "_verify_rs256", lambda *_args: None)
    monkeypatch.setattr(attestation_module.httpx.Client, "get", guarded_get)

    verified = verify_receipt(
        receipt,
        expected_issuer=hostile_issuer,
        now=NOW,
        require_bindings=False,
    )

    assert verified.iss == hostile_issuer
    assert requested_urls == [GCP_JWKS_URI]


@pytest.mark.parametrize("commitment_position", [0, 2])
def test_receipt_key_binding_accepts_nonce_membership_without_live_channel(
    monkeypatch: pytest.MonkeyPatch, commitment_position: int
) -> None:
    policy = _mock_gcp_signature_and_policy(monkeypatch)
    key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes_raw()
    commitment = hashlib.sha256(b"inference-receipt-key-v1\x00" + public).hexdigest()
    nonces = ["a" * 64, "b" * 64]
    nonces.insert(commitment_position, commitment)
    document = _gcp_key_attestation(nonces)
    claims = _claims()
    claims.pop("att_sha256")
    receipt, _ = _sign(
        claims,
        key=key,
        flattened=True,
        header_updates={"att": document.decode("ascii")},
    )

    verified = verify_receipt(
        receipt,
        expected_issuer=EXPECTED_ISSUER,
        now=NOW,
        require_bindings=False,
    )

    assert verified.attestation_status == "verified"
    with pytest.raises(AttestationVerificationError, match="TLS cert"):
        verify_gateway_attestation(document, policy=policy, jwks={"keys": []})


def test_receipt_key_binding_rejects_wrong_commitment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _mock_gcp_signature_and_policy(monkeypatch)
    document = _gcp_key_attestation(["a" * 64, "b" * 64, "c" * 64])
    claims = _claims()
    claims.pop("att_sha256")
    receipt, _ = _sign(
        claims,
        flattened=True,
        header_updates={"att": document.decode("ascii")},
    )

    with pytest.raises(ReceiptAttestationError, match="not present in JWT nonces"):
        verify_receipt(
            receipt,
            expected_issuer=EXPECTED_ISSUER,
            now=NOW,
            require_bindings=False,
        )


def test_compact_receipt_verifies_supplied_pinned_attestation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _mock_gcp_signature_and_policy(monkeypatch)
    key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes_raw()
    commitment = hashlib.sha256(b"inference-receipt-key-v1\x00" + public).hexdigest()
    document = _gcp_key_attestation(["a" * 64, "b" * 64, commitment])
    claims = _claims()
    claims["att_sha256"] = _digest(document)
    receipt, _ = _sign(claims, key=key)

    verified = verify_receipt(
        receipt,
        expected_issuer=EXPECTED_ISSUER,
        attestation=document,
        now=NOW,
        require_bindings=False,
    )

    assert verified.attestation_status == "verified"

    changed = document[:-1] + bytes([document[-1] ^ 1])
    with pytest.raises(ReceiptAttestationError, match="att_sha256 check failed"):
        verify_receipt(
            receipt,
            expected_issuer=EXPECTED_ISSUER,
            attestation=changed,
            now=NOW,
            require_bindings=False,
        )


def test_flattened_receipt_rejects_mismatched_supplied_attestation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _mock_gcp_signature_and_policy(monkeypatch)
    key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes_raw()
    commitment = hashlib.sha256(b"inference-receipt-key-v1\x00" + public).hexdigest()
    document = _gcp_key_attestation(["a" * 64, "b" * 64, commitment])
    claims = _claims()
    claims.pop("att_sha256")
    receipt, _ = _sign(
        claims,
        key=key,
        flattened=True,
        header_updates={"att": document.decode("ascii")},
    )

    with pytest.raises(ReceiptAttestationError, match="does not match.*embedded"):
        verify_receipt(
            receipt,
            expected_issuer=EXPECTED_ISSUER,
            attestation=document + b"x",
            now=NOW,
            require_bindings=False,
        )


def test_receipt_capture_preserves_wire_and_verifies(monkeypatch: pytest.MonkeyPatch) -> None:
    receipt, stream = _stream_receipt(monkeypatch)
    chunks = [stream[:17], stream[17:83], stream[83:]]
    capture = ReceiptCapture(chunks)
    assert b"".join(capture) == stream
    assert capture.captured_bytes == stream
    assert capture.receipt == receipt
    assert (
        capture.verify(
            expected_issuer=EXPECTED_ISSUER,
            request_body=b"request",
            now=NOW,
        ).jti
        == "chatcmpl-test"
    )


_FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "receipts"


def _looks_like_receipt(path: Path) -> bool:
    if (
        not path.is_file()
        or path.name == "README.md"
        or path.suffix not in {".json", ".jws", ".receipt"}
    ):
        return False
    try:
        value = path.read_bytes().strip()
    except OSError:
        return False
    if value.startswith(b"{"):
        try:
            decoded = json.loads(value)
        except (UnicodeDecodeError, json.JSONDecodeError):
            return False
        return isinstance(decoded, dict) and {
            "protected",
            "payload",
            "signature",
        }.issubset(decoded)
    return value.count(b".") == 2 and b"\n" not in value


_FIXTURE_CASES = sorted(
    [path / "receipt.jws" for path in _FIXTURE_ROOT.iterdir() if path.is_dir()]
    + [path for path in _FIXTURE_ROOT.iterdir() if _looks_like_receipt(path)]
)


def _fixture_companion(receipt_path: Path, name: str) -> Path:
    prefixed = receipt_path.parent / f"{receipt_path.stem}.{name}"
    return prefixed if prefixed.exists() else receipt_path.parent / name


@pytest.mark.parametrize("case_dir", _FIXTURE_CASES or [None])
def test_frozen_enclave_receipt_fixtures(
    case_dir: Path | None, monkeypatch: pytest.MonkeyPatch
) -> None:
    if case_dir is None:
        pytest.skip("no frozen enclave receipt fixtures supplied")
    monkeypatch.setattr(receipts_module, "_verify_gcp_attestation", lambda _att, _key: None)
    receipt_path = case_dir
    metadata_path = _fixture_companion(receipt_path, "metadata.json")
    kwargs: dict[str, Any] = (
        json.loads(metadata_path.read_text(encoding="utf-8")) if metadata_path.exists() else {}
    )
    kwargs["expected_issuer"] = EXPECTED_ISSUER
    request_path = _fixture_companion(receipt_path, "request.body")
    response_path = _fixture_companion(receipt_path, "response.body")
    stream_path = _fixture_companion(receipt_path, "response.sse")
    if request_path.exists():
        kwargs["request_body"] = request_path.read_bytes()
    if response_path.exists():
        kwargs["response_body"] = response_path.read_bytes()
    if stream_path.exists():
        kwargs["response_stream"] = stream_path.read_bytes()
    receipt_bytes = receipt_path.read_bytes()
    if not receipt_bytes.lstrip().startswith(b"{"):
        kwargs.setdefault("require_attestation", False)
    verified = verify_receipt(receipt_bytes, **kwargs)
    assert verified.rv == 1
