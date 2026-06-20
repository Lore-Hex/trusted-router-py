"""GCP Confidential Space attestation verification for TrustedRouter.

The hosted gateway runs as a Confidential Space workload. On request,
its `/attestation` endpoint mints an OIDC JWT signed by Google's
Confidential Space signer that commits to:

  - the workload's container image digest (sha256:...)
  - the workload's image reference (Artifact Registry path:tag)
  - a caller-supplied `nonce` (binds the doc to this exact request)
  - the workload's TLS leaf cert SHA-256 (binds the doc to the
    connection the client is already on)

This module verifies the JWT signature against Google's JWKS, then
checks each claim against an `AttestationPolicy` derived from the
public trust release. If everything matches, the gateway is provably
the build the trust page advertises — and any downstream chat call on
the SAME TLS connection inherits that guarantee.

The verification uses the `cryptography` library which is shipped as
an optional extra: `pip install trusted-router-py[attestation]`. The
base SDK doesn't pull it because most users only want chat completions
and shouldn't pay the install cost.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

import httpx

from trustedrouter.client import (
    DEFAULT_TRUST_RELEASE_URL,
    fetch_trust_release,
)
from trustedrouter.models import TrustRelease

GCP_ISSUER = "https://confidentialcomputing.googleapis.com"
GCP_JWKS_URI = (
    "https://www.googleapis.com/service_accounts/v1/metadata/jwk/"
    "signer@confidentialspace-sign.iam.gserviceaccount.com"
)


class AttestationVerificationError(ValueError):
    """Raised when the gateway's attestation document fails any required
    trust check (signature, claim mismatch, expired, or cert binding)."""


@dataclass(frozen=True, slots=True)
class AttestationPolicy:
    """Pinned values the JWT claims must match. Build one with
    `policy_from_trust_release()` to derive these from the live
    trust page, or construct directly to pin to a specific build."""

    gcp_audience: str = "quill-cloud"
    expected_cert_sha256: str | None = None
    expected_image_digest: str | None = None
    expected_image_reference: str | None = None
    # Require the Confidential Space VM to have booted non-debug (dbgstat
    # 'disabled-since-boot'). A debug-enabled CVM's memory-encryption guarantee
    # is effectively void, so default to rejecting it; set False only to test
    # against a deliberately debug image.
    require_production_cvm: bool = True


@dataclass(frozen=True, slots=True)
class GatewayAttestation:
    """Verified attestation result. `cert_sha256` is the SHA-256 of the
    gateway's TLS leaf cert as committed by the JWT — callers can
    re-use it to pin subsequent connections without re-fetching the
    JWT each time."""

    cert_sha256: str
    image_digest: str
    image_reference: str
    nonce: str | None
    expires_at: int | None
    issuer: str | None
    audience: str | None
    # True only when the caller passed the live connection's leaf cert
    # (tls_cert_der) AND it matched the JWT-committed hash. False means the
    # JWT committed to *a* cert but we did not confirm it is THIS connection's.
    connection_bound: bool
    raw_claims: Mapping[str, Any]

    def as_dict(self) -> dict[str, object]:
        return {
            "cert_sha256": self.cert_sha256,
            "image_digest": self.image_digest,
            "image_reference": self.image_reference,
            "nonce": self.nonce,
            "expires_at": self.expires_at,
            "issuer": self.issuer,
            "audience": self.audience,
            "connection_bound": self.connection_bound,
        }


def policy_from_trust_release(
    release: Mapping[str, Any] | TrustRelease | None = None,
    *,
    audience: str = "quill-cloud",
    cert_sha256: str | None = None,
    trust_release_url: str = DEFAULT_TRUST_RELEASE_URL,
) -> AttestationPolicy:
    """Build a policy by reading the published trust release. If
    `release` isn't provided, fetches it from `trust_release_url`. The
    audience defaults to "quill-cloud" — the gateway hard-codes this."""
    release_obj = release if release is not None else fetch_trust_release(trust_release_url)
    if isinstance(release_obj, TrustRelease):
        image_digest = release_obj.image_digest
        image_reference = release_obj.image_reference
    else:
        image_digest = str(release_obj.get("image_digest") or "") or None
        image_reference = str(release_obj.get("image_reference") or "") or None
    if image_digest is None and image_reference is None:
        raise AttestationVerificationError(
            "trust release pins neither image_digest nor image_reference; "
            "refusing to build an image-unbound attestation policy"
        )
    return AttestationPolicy(
        gcp_audience=audience,
        expected_cert_sha256=cert_sha256,
        expected_image_digest=image_digest,
        expected_image_reference=image_reference,
    )


# ---- low-level JWT verification -----------------------------------------


def _b64url_decode(segment: str) -> bytes:
    pad = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + pad)


def _jwt_split(token: bytes) -> tuple[dict[str, Any], dict[str, Any], bytes, bytes]:
    """Decode a compact JWS into (header, payload, signing_input, sig_bytes).
    Raises AttestationVerificationError on shape problems."""
    text = token.decode("ascii", errors="replace").strip()
    parts = text.split(".")
    if len(parts) != 3:
        raise AttestationVerificationError(
            f"expected 3 JWT segments, got {len(parts)}"
        )
    h_b64, p_b64, s_b64 = parts
    try:
        header = json.loads(_b64url_decode(h_b64))
        payload = json.loads(_b64url_decode(p_b64))
        signature = _b64url_decode(s_b64)
    except (binascii.Error, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise AttestationVerificationError(f"invalid JWT encoding: {exc}") from exc
    signing_input = f"{h_b64}.{p_b64}".encode("ascii")
    return header, payload, signing_input, signature


def _verify_rs256(jwks: Mapping[str, Any], header: Mapping[str, Any],
                  signing_input: bytes, signature: bytes) -> None:
    """Find the matching JWK by `kid`, build an RSA public key, verify
    the RS256 signature. Raises AttestationVerificationError on any
    mismatch or unsupported parameter."""
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding, rsa
    except ImportError as exc:  # pragma: no cover — dep missing path
        raise AttestationVerificationError(
            "attestation verification requires the `cryptography` package; "
            "install with `pip install trusted-router-py[attestation]`"
        ) from exc

    if header.get("alg") != "RS256":
        raise AttestationVerificationError(
            f"unsupported JWT alg {header.get('alg')!r}; expected RS256"
        )
    kid = header.get("kid")
    keys = jwks.get("keys") or []
    matching = next((k for k in keys if k.get("kid") == kid), None)
    if matching is None:
        raise AttestationVerificationError(
            f"no JWK with kid={kid!r} in JWKS — gateway key may have rotated"
        )
    if matching.get("kty") != "RSA":
        raise AttestationVerificationError("expected RSA key in JWKS")

    try:
        n_bytes = _b64url_decode(matching["n"])
        e_bytes = _b64url_decode(matching["e"])
    except (binascii.Error, KeyError) as exc:
        raise AttestationVerificationError(f"malformed JWK: {exc}") from exc

    n = int.from_bytes(n_bytes, "big")
    e = int.from_bytes(e_bytes, "big")
    public_key = rsa.RSAPublicNumbers(e=e, n=n).public_key()
    try:
        public_key.verify(signature, signing_input, padding.PKCS1v15(), hashes.SHA256())
    except InvalidSignature as exc:
        raise AttestationVerificationError("JWT signature verification failed") from exc


def _check_claims(
    claims: Mapping[str, Any],
    *,
    policy: AttestationPolicy,
    nonce_hex: str | None,
    tls_cert_der: bytes | None,
) -> GatewayAttestation:
    """Validate every claim the policy requires. Raises on any mismatch.
    Returns a GatewayAttestation if everything checks out."""
    now = int(time.time())
    # Fail CLOSED on a missing/non-numeric exp: an absent or float exp must
    # not silently skip the expiry check (a never-expiring or expired token
    # would otherwise pass). `bool` is an int subclass, so exclude it.
    exp = claims.get("exp")
    if not isinstance(exp, (int, float)) or isinstance(exp, bool):
        raise AttestationVerificationError("JWT missing or non-numeric 'exp' claim")
    if exp <= now:
        raise AttestationVerificationError(f"JWT expired at {exp} (now={now})")

    iss = claims.get("iss")
    if iss != GCP_ISSUER:
        raise AttestationVerificationError(
            f"unexpected issuer {iss!r}; expected {GCP_ISSUER}"
        )

    aud = claims.get("aud")
    # `aud` may be a string OR a list per RFC 7519; reject any other type
    # rather than letting list()/`in` do something surprising on a dict/int.
    if isinstance(aud, str):
        aud_list = [aud]
    elif isinstance(aud, (list, tuple)):
        aud_list = list(aud)
    else:
        raise AttestationVerificationError(
            f"invalid 'aud' claim type: {type(aud).__name__}"
        )
    if policy.gcp_audience not in aud_list:
        raise AttestationVerificationError(
            f"audience {policy.gcp_audience!r} not in JWT aud {aud_list!r}"
        )

    submods = (claims.get("submods") or {}).get("container") or {}
    image_digest = submods.get("image_digest") or ""
    image_reference = submods.get("image_reference") or ""

    if policy.expected_image_digest and not _safe_eq(
        image_digest, policy.expected_image_digest
    ):
        raise AttestationVerificationError(
            f"image_digest mismatch: workload={image_digest!r}, "
            f"policy={policy.expected_image_digest!r}"
        )
    if policy.expected_image_reference and not _safe_eq(
        image_reference, policy.expected_image_reference
    ):
        raise AttestationVerificationError(
            f"image_reference mismatch: workload={image_reference!r}, "
            f"policy={policy.expected_image_reference!r}"
        )

    # Nonce binding: the gateway echoes the caller-supplied nonce in
    # the `nonces` claim (a list per CSP convention). If we sent one
    # but the JWT doesn't carry it, this is either a replay or a
    # misbehaving gateway — fail closed.
    nonces = claims.get("eat_nonce") or claims.get("nonces") or []
    nonce_match: str | None = None
    if isinstance(nonces, str):
        nonces = [nonces]
    if nonce_hex is not None:
        if nonce_hex not in nonces:
            raise AttestationVerificationError(
                f"nonce {nonce_hex!r} not present in JWT nonces {nonces!r}"
            )
        nonce_match = nonce_hex

    # Cert binding: the gateway includes the SHA-256 hex of its TLS
    # leaf cert as a nonce-style claim too (`tls_cert_sha256` or
    # `dbgstat`/`hwmodel` fields differ by CSP version). We accept
    # several known field names.
    cert_sha = (
        claims.get("tls_cert_sha256")
        or claims.get("workload_tls_cert_sha256")
        or _find_cert_in_nonces(nonces, tls_cert_der)
    )
    if not isinstance(cert_sha, str) or len(cert_sha) != 64:
        raise AttestationVerificationError(
            "JWT does not commit to a TLS cert SHA-256 — cannot bind connection"
        )
    cert_sha = cert_sha.lower()

    connection_bound = False
    if tls_cert_der is not None:
        actual = hashlib.sha256(tls_cert_der).hexdigest()
        if not _safe_eq(actual, cert_sha):
            raise AttestationVerificationError(
                f"TLS cert mismatch: connection={actual!r}, JWT={cert_sha!r}"
            )
        connection_bound = True

    if policy.expected_cert_sha256 and not _safe_eq(
        cert_sha, policy.expected_cert_sha256.lower()
    ):
        raise AttestationVerificationError(
            "JWT-committed cert SHA-256 doesn't match policy pin"
        )

    # Confidentiality guarantee: reject a debug-booted CVM. `dbgstat` lives
    # top-level or under submods.confidential_space depending on CSP token
    # version; only 'disabled-since-boot' means memory encryption held.
    if policy.require_production_cvm:
        cs = (claims.get("submods") or {}).get("confidential_space") or {}
        dbgstat = claims.get("dbgstat") or cs.get("dbgstat")
        if dbgstat != "disabled-since-boot":
            raise AttestationVerificationError(
                f"non-production Confidential Space VM (dbgstat={dbgstat!r}); "
                "expected 'disabled-since-boot'"
            )

    return GatewayAttestation(
        cert_sha256=cert_sha,
        image_digest=str(image_digest),
        image_reference=str(image_reference),
        nonce=nonce_match,
        expires_at=int(exp),
        issuer=str(iss) if iss else None,
        audience=policy.gcp_audience,
        connection_bound=connection_bound,
        raw_claims=dict(claims),
    )


def _find_cert_in_nonces(nonces: list[Any], tls_cert_der: bytes | None) -> str | None:
    """Some CSP versions stick the cert hash into the nonces list rather
    than a dedicated claim. We pick whichever 64-hex string in `nonces`
    matches the actual cert (when we have the cert to compare)."""
    if tls_cert_der is None:
        return None
    actual = hashlib.sha256(tls_cert_der).hexdigest()
    for n in nonces:
        if isinstance(n, str) and n.lower() == actual:
            return n.lower()
    return None


def _safe_eq(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())


# ---- jwks fetch ---------------------------------------------------------


def _fetch_jwks(url: str = GCP_JWKS_URI, *, timeout: float = 10.0) -> dict[str, Any]:
    with httpx.Client(timeout=timeout) as client:
        response = client.get(url)
        response.raise_for_status()
        data = response.json()
    if not isinstance(data, dict) or "keys" not in data:
        raise AttestationVerificationError(
            f"GCP JWKS at {url} returned unexpected shape"
        )
    return data


# ---- public entrypoint --------------------------------------------------


def verify_gateway_attestation(
    document: bytes,
    *,
    policy: AttestationPolicy,
    nonce_hex: str | None = None,
    tls_cert_der: bytes | None = None,
    jwks: Mapping[str, Any] | None = None,
    jwks_url: str = GCP_JWKS_URI,
) -> GatewayAttestation:
    """Verify a GCP Confidential Space attestation JWT.

    `document` is the raw bytes returned by `client.attestation()`.
    `policy` says which image_digest / image_reference / cert_sha256
    the JWT must commit to (build with `policy_from_trust_release()`).
    `nonce_hex` should be the same nonce the caller put in the
    /attestation request (binds the doc to this request).
    `tls_cert_der` is the DER bytes of the leaf cert from the live TLS
    connection — when provided, we re-derive its SHA-256 and require
    the JWT to commit to the same cert.

    Pass `jwks=` to inject a pre-fetched JWKS dict (e.g. for offline
    verification or tests); otherwise the function fetches Google's
    public JWKS at boot.

    Returns a GatewayAttestation on success. Raises
    AttestationVerificationError on any failure — never returns False
    or None for a failed verification."""
    header, payload, signing_input, signature = _jwt_split(document)
    if jwks is None:
        jwks = _fetch_jwks(jwks_url)
    _verify_rs256(jwks, header, signing_input, signature)
    return _check_claims(
        payload,
        policy=policy,
        nonce_hex=nonce_hex,
        tls_cert_der=tls_cert_der,
    )


__all__ = [
    "AttestationPolicy",
    "AttestationVerificationError",
    "GCP_ISSUER",
    "GCP_JWKS_URI",
    "GatewayAttestation",
    "policy_from_trust_release",
    "verify_gateway_attestation",
]
