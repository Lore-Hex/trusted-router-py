"""Offline transport for installed-wheel subprocesses; never distributed.

Real HTTPX request/response, SDK parsing, JWT and receipt verification run.
Only the live TLS session boundary is replaced for CLI routing tests.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa

RSA_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
IMAGE = "sha256:consumer"
CERT = "ab" * 32


def b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def jwt(nonces: list[str] | None = None) -> str:
    header = b64(json.dumps({"alg": "RS256", "kid": "consumer"}).encode())
    claims = {
        "iss": "https://confidentialcomputing.googleapis.com",
        "aud": "quill-cloud", "exp": int(time.time()) + 3600,
        "dbgstat": "disabled-since-boot", "swname": "CONFIDENTIAL_SPACE",
        "secboot": True, "hwmodel": "GCP_AMD_SEV",
        "submods": {"container": {"image_digest": IMAGE, "image_reference": "example/image"}},
        "eat_nonce": nonces or [CERT], "tls_cert_sha256": CERT,
    }
    payload = b64(json.dumps(claims).encode())
    signed = f"{header}.{payload}"
    signature = RSA_KEY.sign(signed.encode(), padding.PKCS1v15(), hashes.SHA256())
    return f"{signed}.{b64(signature)}"


def receipt() -> dict[str, str]:
    key = ed25519.Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes_raw()
    digest = hashlib.sha256(public).digest()
    header = {
        "alg": "EdDSA", "typ": "inference-receipt+jws", "kid": b64(digest),
        "jwk": {"kty": "OKP", "crv": "Ed25519", "x": b64(public)},
        "att": jwt([hashlib.sha256(b"inference-receipt-key-v1\0" + public).hexdigest()]),
        "att_kind": "gcp-cs-jwt",
    }
    now = int(time.time())
    claims = {
        "rv": 1, "iss": "https://api.trustedrouter.com", "iat": now,
        "jti": "consumer", "gen": "consumer", "nonce": "nonce_test",
        "route": "chat.completions",
        "req": {"alg": "sha256", "hash": b64(hashlib.sha256(b"request").digest()), "of": "body"},
        "resp": {"alg": "sha256", "hash": b64(hashlib.sha256(b"response").digest()), "of": "body"},
        "model": {"requested": "auto", "selected": "auto", "provider": "fake", "endpoint": "fake"},
        "upstream": {"tier": "tee-verified", "policy": "chutes-tdx-nvidia-e2e-v1",
                     "verified_at": now - 60, "verification_expires_at": now + 240},
    }
    protected, payload = (b64(json.dumps(part).encode()) for part in (header, claims))
    return {"protected": protected, "payload": payload,
            "signature": b64(key.sign(f"{protected}.{payload}".encode()))}


ATTEMPTS = 0


def respond(request: httpx.Request) -> httpx.Response:
    global ATTEMPTS
    ATTEMPTS += 1
    if log := os.environ.get("CONSUMER_REQUEST_LOG"):
        with Path(log).open("a") as output:
            output.write(json.dumps({"path": request.url.path, "method": request.method,
                                     "body": request.content.decode()}) + "\n")
    status = int(os.environ.get("CONSUMER_STATUS", "200"))
    if status != 200 and not (os.environ.get("CONSUMER_RETRY") and ATTEMPTS > 1):
        return httpx.Response(status, json={"error": {"message": "fixture failure"}},
                              headers={"retry-after": "0", "x-request-id": "consumer-id"})
    path = request.url.path
    if "well-known" in path or request.url.host == "trust.trustedrouter.com":
        return httpx.Response(200, json={"image_digest": IMAGE})
    if "metadata/jwk" in path:
        numbers = RSA_KEY.public_key().public_numbers()
        return httpx.Response(200, json={"keys": [{
            "kty": "RSA", "kid": "consumer", "alg": "RS256",
            "n": b64(numbers.n.to_bytes(256, "big")),
            "e": b64(numbers.e.to_bytes(3, "big")),
        }]})
    if path.endswith("/attestation"):
        return httpx.Response(200, content=jwt().encode())
    if path.endswith("/chat/completions"):
        return httpx.Response(200, headers={"content-type": "text/event-stream"}, content=(
            b'data: {"id":"consumer","choices":[{"index":0,"delta":'
            b'{"role":"assistant","content":"hello consumer"},"finish_reason":"stop"}]}\n\n'
            b'data: [DONE]\n\n'
        ))
    if path.endswith(("/models", "/regions", "/providers")):
        return httpx.Response(200, json={"data": [{"id": path.rsplit("/", 1)[-1]}]})
    if path.endswith("/auth/keys"):
        return httpx.Response(200, json={"key": "fake", "identity": {"sub": "consumer"}})
    if path.endswith("/userinfo"):
        return httpx.Response(200, json={"data": {"sub": "consumer"}})
    if path.endswith("/messages"):
        return httpx.Response(200, json={"id": "consumer", "content": [
            {"type": "text", "text": "hello consumer"}]})
    if path.endswith("/credits"):
        return httpx.Response(200, json={"credits": 100})
    if path.endswith("/activity"):
        return httpx.Response(200, json={"data": []})
    if "checkout" in path:
        return httpx.Response(200, json={"url": "https://example.com/checkout"})
    if path.endswith("/some/new/route"):
        return httpx.Response(200, json={"ok": True})
    if path.endswith("/health"):
        return httpx.Response(200, json={"ok": True})
    raise AssertionError(f"Unexpected offline request: {request.method} {request.url}")


SYNC_INIT = httpx.Client.__init__
ASYNC_INIT = httpx.AsyncClient.__init__


def sync_init(self: httpx.Client, *args: Any, **kwargs: Any) -> None:
    kwargs.setdefault("transport", httpx.MockTransport(respond))
    SYNC_INIT(self, *args, **kwargs)


def async_init(self: httpx.AsyncClient, *args: Any, **kwargs: Any) -> None:
    kwargs.setdefault("transport", httpx.MockTransport(respond))
    ASYNC_INIT(self, *args, **kwargs)


httpx.Client.__init__ = sync_init  # type: ignore[method-assign]
httpx.AsyncClient.__init__ = async_init  # type: ignore[method-assign]

if os.environ.get("CONSUMER_TLS_DOUBLE"):
    import trustedrouter.session as session
    from trustedrouter.attestation import GatewayAttestation

    def fake_session(*, base_url: str, policy: object, connect_ip: str | None = None) -> Any:
        assert base_url.endswith("/v1")
        assert connect_ip in (None, "127.0.0.1")
        if os.environ.get("CONSUMER_SESSION_FAIL"):
            raise ValueError("session fixture failure")
        attestation = GatewayAttestation(CERT, IMAGE, "example/image", None, None, None, None, {})
        return SimpleNamespace(
            attestation=attestation, exporter=b"exporter",
            connection=SimpleNamespace(shutdown=lambda: None, close=lambda: None),
        )

    session.verify_gateway_session = fake_session  # type: ignore[assignment]
    session.fetch_attestation_again = lambda session: session.attestation
