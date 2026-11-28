"""Verify a Nitro COSE document with the live socket's challenge and TLS bindings."""

from __future__ import annotations

import hashlib
import io
import re
import time
from typing import Any

import cbor2
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from OpenSSL import crypto

from trustedrouter.attestation import (
    AttestationPolicy,
    AttestationVerificationError,
    GatewayAttestation,
)

# SHA-256 of the DER AWS Nitro Enclaves Root-G1 certificate, not a system TLS CA.
_ROOT = "641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b"


def _decode(data: bytes, *, indefinite: bool = False) -> Any:
    stream = io.BytesIO(data)
    result = cbor2.CBORDecoder(
        stream,
        max_depth=10,
        allow_indefinite=indefinite,
        allow_duplicate_keys=False,
        read_size=1,
    ).decode()
    if stream.read(1):
        raise ValueError("trailing CBOR data")
    return result


def verify_nitro_session(
    document: bytes,
    policy: AttestationPolicy,
    nonce_hex: str | None,
    tls_cert_der: bytes | None,
    exporter: bytes | None,
) -> GatewayAttestation:
    if not (
        0 < len(document) <= 16384
        and tls_cert_der
        and nonce_hex
        and re.fullmatch(r"[0-9a-fA-F]{64}", nonce_hex)
        and exporter
        and len(exporter) == 32
        and exporter != bytes(32)
        and exporter != bytes.fromhex(nonce_hex)
    ):
        raise AttestationVerificationError("Nitro requires bounded evidence and fresh TLS bindings")
    try:
        return _verify(document, policy, nonce_hex, tls_cert_der, exporter)
    except (
        ValueError,
        TypeError,
        KeyError,
        IndexError,
        OverflowError,
        cbor2.CBORDecodeError,
        InvalidSignature,
        x509.ExtensionNotFound,
        crypto.X509StoreContextError,
        crypto.Error,
    ) as exc:
        raise AttestationVerificationError("Nitro evidence failed verification") from exc


def _verify(
    document: bytes,
    policy: AttestationPolicy,
    nonce_hex: str,
    tls_cert_der: bytes,
    exporter: bytes,
) -> GatewayAttestation:
    envelope = _decode(document)
    if isinstance(envelope, cbor2.CBORTag) and envelope.tag == 18:
        envelope = envelope.value
    protected, unprotected, body, signature = envelope
    if (
        not isinstance(body, bytes)
        or not isinstance(protected, bytes)
        or not isinstance(signature, bytes)
        or len(signature) != 96
        or unprotected != {}
        or _decode(protected) != {1: -35}
    ):
        raise ValueError("expected Nitro COSE_Sign1 ES384")
    # Nitro emits an indefinite-length map inside the bounded signed payload.
    doc = _decode(body, indefinite=True)
    if not isinstance(doc, dict) or doc["digest"] != "SHA384":
        raise ValueError("invalid Nitro payload")
    bundle = doc["cabundle"]
    if not isinstance(bundle, list) or not 1 <= len(bundle) <= 16:
        raise ValueError("invalid Nitro certificate bundle")
    store = crypto.X509Store()
    intermediates = []
    for der in bundle:
        cert = x509.load_der_x509_certificate(der)
        openssl_cert = crypto.X509.from_cryptography(cert)
        if hashlib.sha256(der).hexdigest() == _ROOT:
            store.add_cert(openssl_cert)
        else:
            intermediates.append(openssl_cert)
    leaf = x509.load_der_x509_certificate(doc["certificate"])
    if leaf.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
        raise ValueError("Nitro signing leaf cannot be a CA")
    crypto.X509StoreContext(
        store, crypto.X509.from_cryptography(leaf), intermediates
    ).verify_certificate()
    key = leaf.public_key()
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP384R1):
        raise TypeError("expected P-384 Nitro signing key")
    der_sig = encode_dss_signature(
        int.from_bytes(signature[:48], "big"), int.from_bytes(signature[48:], "big")
    )
    key.verify(
        der_sig, cbor2.dumps(["Signature1", protected, b"", body]), ec.ECDSA(hashes.SHA384())
    )
    t = doc["timestamp"]
    if type(t) is not int or abs(time.time() * 1000 - t) > 300_000:
        raise ValueError("stale Nitro evidence")
    pcr0 = doc["pcrs"][0]
    if not isinstance(pcr0, bytes) or pcr0.hex() not in policy.expected_nitro_pcr0s:
        raise ValueError("unapproved Nitro PCR0")
    if doc["nonce"] != bytes.fromhex(nonce_hex):
        raise ValueError("Nitro challenge mismatch")
    spki = (
        x509.load_der_x509_certificate(tls_cert_der)
        .public_key()
        .public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    )
    fingerprint = hashlib.sha256(tls_cert_der).digest()
    data = doc["user_data"]
    if (
        doc["public_key"] != spki
        or not isinstance(data, bytes)
        or len(data) not in (96, 128)
        or data[:32] != fingerprint
        or data[64:96] != exporter
        or (policy.expected_cert_sha256 and policy.expected_cert_sha256 != fingerprint.hex())
    ):
        raise ValueError("Nitro TLS certificate or exporter mismatch")
    return GatewayAttestation(
        cert_sha256=fingerprint.hex(),
        image_digest="",
        image_reference="",
        nonce=nonce_hex,
        expires_at=None,
        issuer="AWS Nitro Root-G1",
        audience=None,
        raw_claims={"pcr0": pcr0.hex()},
        binding="tls-exporter",
    )
