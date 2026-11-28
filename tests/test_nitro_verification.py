from __future__ import annotations

import hashlib
import time
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import cbor2
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509.oid import NameOID

from trustedrouter import _nitro, session
from trustedrouter.attestation import (
    AttestationPolicy,
    AttestationVerificationError,
    verify_gateway_attestation,
)

PCR = bytes(range(48))
EXPORTER = b"x" * 32
NONCE = b"n" * 32


def certificate(name, key, *, issuer=None, issuer_key=None, ca=False, expired=False):
    now = datetime.now(timezone.utc)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer.subject if issuer else subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=2))
        .not_valid_after(now + timedelta(days=-1 if expired else 1))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        .sign(issuer_key or key, hashes.SHA384())
    )


@pytest.mark.parametrize(
    "case",
    [
        "valid",
        "bad signature",
        "foreign root",
        "stale",
        "wrong PCR",
        "wrong nonce",
        "other key",
        "other cert",
        "other exporter",
        "CA leaf",
        "expired leaf",
        "trailing CBOR",
        "JWT",
        "zero exporter",
        "missing exporter",
        "oversize",
        "wrong cert pin",
    ],
)
def test_nitro_signed_live_bindings(monkeypatch, case):
    root_key = ec.generate_private_key(ec.SECP384R1())
    root = certificate("test root", root_key, ca=True)
    root_der = root.public_bytes(Encoding.DER)
    if case != "foreign root":
        monkeypatch.setattr(_nitro, "_ROOT", hashlib.sha256(root_der).hexdigest())
    key = ec.generate_private_key(ec.SECP384R1())
    leaf = certificate(
        "test NSM",
        key,
        issuer=root,
        issuer_key=root_key,
        ca=case == "CA leaf",
        expired=case == "expired leaf",
    )
    tls_key = ec.generate_private_key(ec.SECP256R1())
    tls = certificate("test TLS", tls_key).public_bytes(Encoding.DER)
    fp = hashlib.sha256(tls).digest()
    spki = tls_key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    body = cbor2.dumps(
        {
            "digest": "SHA384",
            "cabundle": [root_der],
            "certificate": leaf.public_bytes(Encoding.DER),
            "timestamp": int(time.time() * 1000) - (600000 if case == "stale" else 0),
            "pcrs": {0: bytes(48) if case == "wrong PCR" else PCR},
            "nonce": bytes(32) if case == "wrong nonce" else NONCE,
            "public_key": b"wrong" if case == "other key" else spki,
            "user_data": (
                (bytes(32) if case == "other cert" else fp)
                + bytes(32)
                + (bytes(32) if case == "other exporter" else EXPORTER)
            ),
        }
    )
    header = cbor2.dumps({1: -35})
    r, s = decode_dss_signature(
        key.sign(cbor2.dumps(["Signature1", header, b"", body]), ec.ECDSA(hashes.SHA384()))
    )
    sig = r.to_bytes(48, "big") + s.to_bytes(48, "big")
    envelope = cbor2.dumps([header, {}, body, bytes(96) if case == "bad signature" else sig])
    doc = {
        "trailing CBOR": envelope + b"x",
        "JWT": b"ey.invalid.jwt",
        "oversize": bytes(16385),
    }.get(case, envelope)
    policy = AttestationPolicy(
        expected_nitro_pcr0s=(PCR.hex(),),
        expected_cert_sha256="bad" if case == "wrong cert pin" else fp.hex(),
    )

    def verify():
        return verify_gateway_attestation(
            doc,
            policy=policy,
            nonce_hex=NONCE.hex(),
            tls_cert_der=tls,
            tls_exporter={"zero exporter": bytes(32), "missing exporter": None}.get(case, EXPORTER),
        )

    if case == "valid":
        proof = verify()
        assert (proof.issuer, proof.binding, proof.raw_claims["pcr0"]) == (
            "AWS Nitro Root-G1",
            "tls-exporter",
            PCR.hex(),
        )
    else:
        with pytest.raises(AttestationVerificationError):
            verify()


@pytest.mark.parametrize(
    "changes",
    [
        {"expected_nitro_pcr0s": ("0" * 96,)},
        {"expected_nitro_pcr0s": ("bad",)},
        {"expected_image_reference": "gcp"},
        {"expected_image_digest": "sha256:" + "f" * 64},
        {"gcp_audience": "custom"},
        {"allow_debug": True},
    ],
)
def test_provider_policies_cannot_mix(changes):
    with pytest.raises(AttestationVerificationError):
        AttestationPolicy(**({"expected_nitro_pcr0s": (PCR.hex(),)} | changes))


def test_nitro_tls12_sends_no_http_bytes(monkeypatch):
    ssl = MagicMock()
    conn = ssl.Connection.return_value
    conn.get_protocol_version_name.return_value = "TLSv1.2"
    monkeypatch.setattr(session, "_load_pyopenssl", lambda: (ssl, MagicMock()))
    monkeypatch.setattr(session, "_new_pyopenssl_context", MagicMock())
    monkeypatch.setattr(session.socket, "create_connection", MagicMock())
    with pytest.raises(AttestationVerificationError, match=r"negotiated TLS 1\.3"):
        session.verify_gateway_session(
            base_url="https://example.com",
            policy=AttestationPolicy(expected_nitro_pcr0s=(PCR.hex(),)),
        )
    conn.send.assert_not_called()
    conn.sendall.assert_not_called()
    conn.get_peer_certificate.assert_not_called()
