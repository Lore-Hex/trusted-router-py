"""Offline verification for signed inference receipts (wire format v1)."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import re
import time
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass
from typing import Any, Literal
from urllib.parse import urlsplit

from trustedrouter.attestation import (
    policy_from_trust_release,
    verify_receipt_key_attestation,
)

_RECEIPT_TYPE = "inference-receipt+jws"
_KEY_COMMITMENT_DOMAIN = b"inference-receipt-key-v1\x00"
_B64URL_RE = re.compile(r"[A-Za-z0-9_-]*\Z")
_NONCE_RE = re.compile(r"[A-Za-z0-9_-]{1,88}\Z")


class ReceiptVerificationError(ValueError):
    """Base class for every fail-closed receipt verification error."""


class ReceiptStructureError(ReceiptVerificationError):
    """The compact or flattened JWS structure is malformed."""


class ReceiptHeaderError(ReceiptVerificationError):
    """The protected JWS header is invalid or unsupported."""


class ReceiptSignatureError(ReceiptVerificationError):
    """The Ed25519 signature is invalid or cannot be checked."""


class ReceiptClaimsError(ReceiptVerificationError):
    """A required receipt claim is missing, malformed, or unsupported."""


class MissingBindingError(ReceiptClaimsError):
    """Required caller traffic for a receipt digest binding is absent."""


class ReceiptIssuerError(ReceiptClaimsError):
    """The receipt issuer is invalid or does not match the caller's pin."""


class ReceiptTimeError(ReceiptClaimsError):
    """The receipt issue time or requested age bound is invalid."""


class ReceiptNonceError(ReceiptClaimsError):
    """The receipt does not echo the caller's expected nonce."""


class ReceiptUpstreamError(ReceiptClaimsError):
    """The upstream verification window or tier claims are invalid."""


class ReceiptHashError(ReceiptVerificationError):
    """A request or response byte digest check failed."""


class ReceiptAttestationError(ReceiptVerificationError):
    """The receipt signing key is not bound by a valid attestation."""


class MissingAttestationError(ReceiptAttestationError):
    """Required embedded attestation evidence is absent."""


class UnsupportedAttestationError(ReceiptAttestationError):
    """The receipt uses an attestation kind this SDK cannot verify."""


@dataclass(frozen=True, slots=True)
class ReceiptHashClaims:
    alg: str
    hash: str
    of: str
    events: int | None = None


@dataclass(frozen=True, slots=True)
class ReceiptModelClaims:
    requested: str
    selected: str
    provider: str
    endpoint: str


@dataclass(frozen=True, slots=True)
class ReceiptUpstreamClaims:
    tier: str
    policy: str | None = None
    verified_at: int | None = None
    verification_expires_at: int | None = None
    cert_sha256: str | None = None


@dataclass(frozen=True, slots=True)
class ReceiptClaims:
    """Verified v1 claims plus the SDK's attestation verification status."""

    rv: int
    iss: str
    iat: int
    jti: str
    gen: str | None
    nonce: str | None
    route: str
    req: ReceiptHashClaims
    resp: ReceiptHashClaims
    model: ReceiptModelClaims
    upstream: ReceiptUpstreamClaims
    att_sha256: str | None
    attestation_status: Literal["verified", "unverified_by_this_sdk"]

    @property
    def attestation(self) -> Literal["verified", "unverified_by_this_sdk"]:
        """Alias for the receipt's SDK attestation-verification result."""
        return self.attestation_status


@dataclass(frozen=True, slots=True)
class _JWSEnvelope:
    protected: str
    payload: str
    signature: str
    flattened: bool
    flattened_value: Mapping[str, Any] | None


@dataclass(frozen=True, slots=True)
class _SSEEvent:
    name: bytes
    payload: bytes
    done: bool


def _json_object_no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON member {key!r}")
        result[key] = value
    return result


def _load_json(data: str | bytes, *, check: str) -> Any:
    try:
        return json.loads(data, object_pairs_hook=_json_object_no_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ReceiptStructureError(f"{check} check failed: invalid JSON: {exc}") from exc


def _b64url_decode(value: str, *, check: str, allow_empty: bool = False) -> bytes:
    if (
        not isinstance(value, str)
        or (not value and not allow_empty)
        or not _B64URL_RE.fullmatch(value)
    ):
        raise ReceiptStructureError(f"{check} check failed: invalid base64url encoding")
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (binascii.Error, ValueError) as exc:
        raise ReceiptStructureError(f"{check} check failed: invalid base64url encoding") from exc


def _b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _parse_envelope(receipt: str | bytes | Mapping[str, Any]) -> _JWSEnvelope:
    flattened_value: Mapping[str, Any] | None = None
    if isinstance(receipt, Mapping):
        flattened_value = receipt
    else:
        if isinstance(receipt, bytes):
            try:
                text = receipt.decode("ascii")
            except UnicodeDecodeError as exc:
                raise ReceiptStructureError(
                    "JWS structure check failed: receipt bytes must be ASCII"
                ) from exc
        elif isinstance(receipt, str):
            text = receipt
        else:
            raise ReceiptStructureError(
                "JWS structure check failed: receipt must be compact str/bytes or flattened JWS"
            )
        text = text.strip()
        if text.startswith("{"):
            decoded = _load_json(text, check="JWS structure")
            if not isinstance(decoded, Mapping):
                raise ReceiptStructureError(
                    "JWS structure check failed: flattened JWS must be a JSON object"
                )
            flattened_value = decoded
        else:
            parts = text.split(".")
            if len(parts) != 3 or any(not part for part in parts):
                raise ReceiptStructureError(
                    "JWS structure check failed: compact JWS must have 3 "
                    f"non-empty segments, got {len(parts)}"
                )
            return _JWSEnvelope(parts[0], parts[1], parts[2], False, None)

    if "header" in flattened_value:
        raise ReceiptStructureError(
            "JWS structure check failed: unprotected flattened headers are not allowed"
        )
    required = ("protected", "payload", "signature")
    values = tuple(flattened_value.get(name) for name in required)
    if any(not isinstance(value, str) or not value for value in values):
        raise ReceiptStructureError(
            "JWS structure check failed: flattened JWS requires non-empty string "
            "protected, payload, and signature members"
        )
    protected, payload, signature = values
    assert isinstance(protected, str)
    assert isinstance(payload, str)
    assert isinstance(signature, str)
    return _JWSEnvelope(protected, payload, signature, True, flattened_value)


def _parse_header(envelope: _JWSEnvelope) -> tuple[Mapping[str, Any], bytes]:
    raw = _b64url_decode(envelope.protected, check="protected header")
    header = _load_json(raw, check="protected header")
    if not isinstance(header, Mapping):
        raise ReceiptHeaderError("protected header check failed: header must be a JSON object")
    if header.get("alg") != "EdDSA":
        raise ReceiptHeaderError(
            f"protected header alg check failed: expected 'EdDSA', got {header.get('alg')!r}"
        )
    if header.get("typ") != _RECEIPT_TYPE:
        raise ReceiptHeaderError(
            f"protected header typ check failed: expected {_RECEIPT_TYPE!r}, "
            f"got {header.get('typ')!r}"
        )
    jwk = header.get("jwk")
    if not isinstance(jwk, Mapping):
        raise ReceiptHeaderError("protected header jwk check failed: jwk must be an object")
    if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519" or "d" in jwk:
        raise ReceiptHeaderError(
            "protected header jwk check failed: expected a public OKP/Ed25519 JWK"
        )
    x = jwk.get("x")
    if not isinstance(x, str):
        raise ReceiptHeaderError("protected header jwk.x check failed: x must be a string")
    try:
        public_key = _b64url_decode(x, check="protected header jwk.x")
    except ReceiptStructureError as exc:
        raise ReceiptHeaderError(str(exc)) from exc
    if len(public_key) != 32:
        raise ReceiptHeaderError(
            "protected header jwk.x check failed: Ed25519 public key is "
            f"{len(public_key)} bytes, expected 32"
        )
    kid = header.get("kid")
    expected_kid = _b64url_encode(hashlib.sha256(public_key).digest())
    if not isinstance(kid, str) or not hmac.compare_digest(kid, expected_kid):
        raise ReceiptHeaderError(
            "protected header kid check failed: kid does not equal b64url(sha256(jwk.x))"
        )
    return header, public_key


def _verify_signature(envelope: _JWSEnvelope, public_key: bytes) -> bytes:
    payload = _b64url_decode(envelope.payload, check="JWS payload")
    try:
        signature = _b64url_decode(envelope.signature, check="JWS signature")
    except ReceiptStructureError as exc:
        raise ReceiptSignatureError(str(exc)) from exc
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError as exc:  # pragma: no cover - exercised only without the extra
        raise ReceiptSignatureError(
            "Ed25519 signature check failed: install trusted-router-py[receipts]"
        ) from exc
    signing_input = f"{envelope.protected}.{envelope.payload}".encode("ascii")
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, signing_input)
    except (InvalidSignature, ValueError) as exc:
        raise ReceiptSignatureError("Ed25519 signature check failed") from exc
    return payload


def _required_mapping(
    claims: Mapping[str, Any],
    name: str,
    *,
    error_type: type[ReceiptVerificationError] = ReceiptClaimsError,
) -> Mapping[str, Any]:
    value = claims.get(name)
    if not isinstance(value, Mapping):
        raise error_type(f"{name} claim check failed: required object is missing or invalid")
    return value


def _required_str(claims: Mapping[str, Any], name: str, *, family: str = "claims") -> str:
    value = claims.get(name)
    if not isinstance(value, str) or not value:
        raise ReceiptClaimsError(
            f"{family} {name} check failed: required string is missing or empty"
        )
    return value


def _optional_str(claims: Mapping[str, Any], name: str, *, family: str = "claims") -> str | None:
    if name not in claims:
        return None
    value = claims[name]
    if not isinstance(value, str) or not value:
        raise ReceiptClaimsError(f"{family} {name} check failed: value must be a non-empty string")
    return value


def _canonical_https_origin(value: Any, *, check: str) -> str:
    if not isinstance(value, str) or not value:
        raise ReceiptIssuerError(f"{check} check failed: required HTTPS origin is missing")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise ReceiptIssuerError(f"{check} check failed: invalid HTTPS origin") from exc
    if parsed.scheme.lower() != "https":
        raise ReceiptIssuerError(f"{check} check failed: issuer origin must use https")
    if (
        parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ReceiptIssuerError(
            f"{check} check failed: expected an origin with no path, query, or fragment"
        )
    host = parsed.hostname.lower()
    if any(character.isspace() for character in host):
        raise ReceiptIssuerError(f"{check} check failed: invalid HTTPS origin host")
    if ":" in host:
        host = f"[{host}]"
    canonical = f"https://{host}{f':{port}' if port is not None else ''}"
    normalized_input = value[:-1] if value.endswith("/") else value
    if normalized_input.lower() != canonical:
        raise ReceiptIssuerError(f"{check} check failed: invalid HTTPS origin")
    return canonical


def _require_traffic_bindings(
    *,
    request_body: bytes | bytearray | memoryview | None,
    response_body: bytes | bytearray | memoryview | None,
    response_stream: bytes | bytearray | memoryview | None,
    require_bindings: bool,
) -> None:
    if require_bindings is False:
        return
    missing_request = request_body is None
    missing_response = response_body is None and response_stream is None
    if missing_request and missing_response:
        raise MissingBindingError(
            "receipt binding check failed: missing request_body and "
            "response_body or response_stream"
        )
    if missing_request:
        raise MissingBindingError("receipt binding check failed: missing request_body")
    if missing_response:
        raise MissingBindingError(
            "receipt binding check failed: missing response_body or response_stream"
        )


def _integer(value: Any, *, check: str, error_type: type[ReceiptClaimsError]) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise error_type(f"{check} check failed: expected an integer")
    return value


def _digest_claim(record: Mapping[str, Any], *, name: str, response: bool) -> ReceiptHashClaims:
    alg = record.get("alg")
    if alg != "sha256":
        raise ReceiptHashError(f"{name}.alg check failed: expected 'sha256', got {alg!r}")
    encoded = record.get("hash")
    if not isinstance(encoded, str):
        raise ReceiptHashError(f"{name}.hash check failed: required string is missing")
    try:
        digest = _b64url_decode(encoded, check=f"{name}.hash")
    except ReceiptStructureError as exc:
        raise ReceiptHashError(str(exc)) from exc
    if len(digest) != 32:
        raise ReceiptHashError(f"{name}.hash check failed: SHA-256 digest must be 32 bytes")
    of = record.get("of")
    allowed = {"body", "sse-data-v1", "sse-events-v1"} if response else {"body"}
    if of not in allowed:
        raise ReceiptHashError(f"{name}.of check failed: unsupported hash domain {of!r}")
    events_value = record.get("events")
    events: int | None = None
    if response and of != "body":
        if not isinstance(events_value, int) or isinstance(events_value, bool) or events_value < 0:
            raise ReceiptHashError(
                f"{name}.events check failed: streaming receipts require a non-negative integer"
            )
        events = events_value
    elif events_value is not None:
        raise ReceiptHashError(f"{name}.events check failed: body receipts must omit events")
    return ReceiptHashClaims(alg=alg, hash=encoded, of=of, events=events)


def _body_bytes(value: bytes | bytearray | memoryview, *, check: str) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise ReceiptHashError(f"{check} check failed: exact body bytes are required")
    return bytes(value)


def _decode_sse_event(raw: bytes) -> _SSEEvent:
    if raw.endswith(b"\r\n\r\n"):
        body = raw[:-4]
    elif raw.endswith(b"\n\n"):
        body = raw[:-2]
    else:
        raise ReceiptHashError("response stream framing check failed: incomplete SSE event")
    name = b""
    payload = b""
    saw_name = False
    saw_data = False
    for line in body.split(b"\n"):
        if line.endswith(b"\r"):
            line = line[:-1]
        if line.startswith(b"data:"):
            if saw_data:
                raise ReceiptHashError(
                    "response stream framing check failed: SSE event has multiple data fields"
                )
            saw_data = True
            payload = line[5:]
            if payload.startswith(b" "):
                payload = payload[1:]
        elif line.startswith(b"event:"):
            if saw_name:
                raise ReceiptHashError(
                    "response stream framing check failed: SSE event has multiple event fields"
                )
            saw_name = True
            name = line[6:]
            if name.startswith(b" "):
                name = name[1:]
        else:
            raise ReceiptHashError(
                "response stream framing check failed: SSE event contains an unsupported field"
            )
    if not saw_data:
        raise ReceiptHashError("response stream framing check failed: SSE event has no data field")
    return _SSEEvent(name=name, payload=payload, done=payload == b"[DONE]")


def _next_sse_event(data: bytes, offset: int) -> tuple[bytes, int] | None:
    lf = data.find(b"\n\n", offset)
    crlf = data.find(b"\r\n\r\n", offset)
    if lf < 0 and crlf < 0:
        return None
    if lf >= 0 and (crlf < 0 or lf < crlf):
        end = lf + 2
    else:
        end = crlf + 4
    return data[offset:end], end


def _embedded_receipt(payload: bytes) -> Mapping[str, Any] | None:
    try:
        decoded = json.loads(payload, object_pairs_hook=_json_object_no_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        return None
    if not isinstance(decoded, Mapping) or "inference_receipt" not in decoded:
        return None
    receipt = decoded["inference_receipt"]
    if not isinstance(receipt, Mapping):
        raise ReceiptHashError(
            "response stream receipt position check failed: inference_receipt must be "
            "a flattened JWS object"
        )
    return receipt


def _stream_digest(
    stream: bytes, *, domain: str, expected_receipt: Mapping[str, Any] | None
) -> tuple[bytes, int]:
    digest = hashlib.sha256()
    events = 0
    offset = 0
    saw_done = False
    saw_receipt = False
    while offset < len(stream):
        found = _next_sse_event(stream, offset)
        if found is None:
            raise ReceiptHashError(
                "response stream framing check failed: stream has an incomplete SSE tail"
            )
        raw, offset = found
        event = _decode_sse_event(raw)
        if saw_done:
            raise ReceiptHashError(
                "response stream receipt position check failed: data event follows [DONE]"
            )
        if event.done:
            saw_done = True
            continue
        embedded = _embedded_receipt(event.payload)
        if embedded is not None:
            if saw_receipt:
                raise ReceiptHashError(
                    "response stream receipt position check failed: multiple receipt events"
                )
            if expected_receipt is None or dict(embedded) != dict(expected_receipt):
                raise ReceiptHashError(
                    "response stream receipt position check failed: embedded receipt "
                    "does not match the verified flattened JWS"
                )
            saw_receipt = True
            continue
        if saw_receipt:
            raise ReceiptHashError(
                "response stream receipt position check failed: receipt is not the last "
                "data event before [DONE]"
            )
        if domain == "sse-data-v1":
            if event.name:
                raise ReceiptHashError(
                    "response stream hash check failed: sse-data-v1 events must be unnamed"
                )
        elif domain == "sse-events-v1":
            digest.update(event.name)
            digest.update(b"\n")
        else:  # guarded by _digest_claim
            raise ReceiptHashError(
                f"response stream hash check failed: unsupported domain {domain!r}"
            )
        digest.update(event.payload)
        digest.update(b"\n")
        events += 1
    if not saw_receipt:
        raise ReceiptHashError(
            "response stream receipt position check failed: receipt event is missing"
        )
    if not saw_done:
        raise ReceiptHashError(
            "response stream receipt position check failed: receipt is not followed by [DONE]"
        )
    return digest.digest(), events


def _verify_gcp_attestation(attestation: bytes, commitment: bytes) -> None:
    """Verify a GCP receipt-key attestation and its commitment membership."""
    policy = policy_from_trust_release()
    verify_receipt_key_attestation(
        attestation, policy=policy, key_commitment_hex=commitment.hex()
    )


def _attestation_status(
    envelope: _JWSEnvelope,
    header: Mapping[str, Any],
    public_key: bytes,
    *,
    attestation: bytes | None,
    att_sha256: str | None,
    require_attestation: bool,
) -> Literal["verified", "unverified_by_this_sdk"]:
    if not envelope.flattened:
        if attestation is None:
            if not require_attestation:
                return "unverified_by_this_sdk"
            raise MissingAttestationError(
                "attestation check failed: compact receipts omit attestation evidence; "
                "obtain the pinned document or explicitly pass require_attestation=False"
            )
        if att_sha256 is None:  # guarded by the claims check in verify_receipt
            raise MissingAttestationError(
                "attestation check failed: compact receipt has no att_sha256 claim"
            )
        expected_digest = _b64url_decode(att_sha256, check="att_sha256 claim")
        actual_digest = hashlib.sha256(attestation).digest()
        if not hmac.compare_digest(actual_digest, expected_digest):
            raise ReceiptAttestationError(
                "att_sha256 check failed: supplied attestation does not match the compact receipt"
            )
        document = attestation
    else:
        kind = header.get("att_kind")
        embedded = header.get("att")
        if kind in {"aws-nitro-cose", "azure-maa-jwt"}:
            raise UnsupportedAttestationError(
                f"attestation kind check failed: {kind!r} is not supported by this SDK"
            )
        if kind != "gcp-cs-jwt":
            if kind is None:
                raise MissingAttestationError(
                    "attestation check failed: flattened receipt has no att_kind"
                )
            raise UnsupportedAttestationError(
                f"attestation kind check failed: unsupported att_kind {kind!r}"
            )
        if not isinstance(embedded, str) or not embedded:
            raise MissingAttestationError(
                "attestation check failed: flattened receipt has no embedded att"
            )
        try:
            document = embedded.encode("ascii")
        except UnicodeEncodeError as exc:
            raise ReceiptAttestationError(
                "attestation check failed: flattened receipt att must be ASCII"
            ) from exc
        if attestation is not None and not hmac.compare_digest(attestation, document):
            raise ReceiptAttestationError(
                "attestation check failed: supplied attestation does not match the "
                "flattened receipt's embedded attestation"
            )

    commitment = hashlib.sha256(_KEY_COMMITMENT_DOMAIN + public_key).digest()
    try:
        _verify_gcp_attestation(document, commitment)
    except ReceiptVerificationError:
        raise
    except Exception as exc:
        raise ReceiptAttestationError(f"GCP attestation check failed: {exc}") from exc
    return "verified"


def verify_receipt(
    receipt: str | bytes | Mapping[str, Any],
    *,
    expected_issuer: str,
    request_body: bytes | bytearray | memoryview | None = None,
    response_body: bytes | bytearray | memoryview | None = None,
    response_stream: bytes | bytearray | memoryview | None = None,
    expected_nonce: str | None = None,
    max_age_seconds: int | float | None = None,
    now: int | float | None = None,
    attestation: bytes | None = None,
    require_attestation: bool = True,
    require_bindings: bool = True,
) -> ReceiptClaims:
    """Verify a compact or flattened inference receipt and return typed claims.

    ``expected_issuer`` pins the receipt to an HTTPS origin after normalizing
    the scheme and host case and removing one trailing slash. Request bytes
    and exactly one response representation are required by default so the
    signed digests are bound to the caller's traffic. Passing
    ``require_bindings=False`` explicitly permits signature-only or partial
    binding inspection.

    Compact receipts cannot carry their attestation document. Pass its exact
    bytes as ``attestation=`` to check the pinned digest and verify the key
    binding. Passing ``require_attestation=False`` is an explicit
    signature-and-hashes-only escape hatch when those bytes are unavailable.
    Flattened receipts always verify their embedded evidence; if
    ``attestation=`` is also supplied, it must equal the embedded document.
    """
    _require_traffic_bindings(
        request_body=request_body,
        response_body=response_body,
        response_stream=response_stream,
        require_bindings=require_bindings,
    )
    canonical_expected_issuer = _canonical_https_origin(
        expected_issuer, check="expected_issuer"
    )
    envelope = _parse_envelope(receipt)
    header, public_key = _parse_header(envelope)
    payload_bytes = _verify_signature(envelope, public_key)
    payload = _load_json(payload_bytes, check="receipt claims")
    if not isinstance(payload, Mapping):
        raise ReceiptClaimsError("rv claim check failed: receipt claims must be a JSON object")
    if attestation is not None and not isinstance(attestation, bytes):
        raise ReceiptAttestationError("attestation check failed: attestation must be bytes")

    rv = payload.get("rv")
    if not isinstance(rv, int) or isinstance(rv, bool) or rv != 1:
        raise ReceiptClaimsError(f"rv claim check failed: expected integer 1, got {rv!r}")

    iss = _required_str(payload, "iss")
    canonical_issuer = _canonical_https_origin(iss, check="iss claim")
    if not hmac.compare_digest(canonical_issuer, canonical_expected_issuer):
        raise ReceiptIssuerError(
            "iss claim check failed: "
            f"expected {canonical_expected_issuer!r}, got {canonical_issuer!r}"
        )

    iat = _integer(payload.get("iat"), check="iat claim", error_type=ReceiptTimeError)
    if now is None:
        checked_now = time.time()
    elif isinstance(now, (int, float)) and not isinstance(now, bool):
        checked_now = float(now)
    else:
        raise ReceiptTimeError("iat check failed: now must be Unix seconds")
    if iat > checked_now + 60:
        raise ReceiptTimeError(
            f"iat future-skew check failed: iat={iat} is more than 60 seconds "
            f"after now={checked_now:g}"
        )
    if max_age_seconds is not None:
        if (
            not isinstance(max_age_seconds, (int, float))
            or isinstance(max_age_seconds, bool)
            or max_age_seconds < 0
        ):
            raise ReceiptTimeError("iat max-age check failed: max_age_seconds must be non-negative")
        if checked_now - iat > max_age_seconds:
            raise ReceiptTimeError(
                f"iat max-age check failed: receipt age {checked_now - iat:g}s "
                f"exceeds {max_age_seconds:g}s"
            )

    nonce = payload.get("nonce")
    if "nonce" in payload and (not isinstance(nonce, str) or _NONCE_RE.fullmatch(nonce) is None):
        raise ReceiptNonceError(
            "nonce claim check failed: nonce must contain 1-88 base64url characters"
        )
    if expected_nonce is not None and not isinstance(expected_nonce, str):
        raise ReceiptNonceError("nonce match check failed: expected_nonce must be a string")
    if expected_nonce is not None and (
        not isinstance(nonce, str) or not hmac.compare_digest(nonce, expected_nonce)
    ):
        raise ReceiptNonceError(
            f"nonce match check failed: expected {expected_nonce!r}, got {nonce!r}"
        )

    upstream_raw = _required_mapping(payload, "upstream", error_type=ReceiptUpstreamError)
    tier = upstream_raw.get("tier")
    if tier == "tee-verified":
        verified_at = _integer(
            upstream_raw.get("verified_at"),
            check="upstream.verified_at",
            error_type=ReceiptUpstreamError,
        )
        verification_expires_at = _integer(
            upstream_raw.get("verification_expires_at"),
            check="upstream.verification_expires_at",
            error_type=ReceiptUpstreamError,
        )
        if not verified_at <= iat < verification_expires_at:
            raise ReceiptUpstreamError(
                "tee-verified window check failed: expected "
                "verified_at <= iat < verification_expires_at"
            )
    elif tier == "tls-webpki":
        verified_at = None
        verification_expires_at = None
    else:
        raise ReceiptUpstreamError(f"upstream.tier check failed: unsupported tier {tier!r}")

    att_sha256 = _optional_str(payload, "att_sha256")
    if att_sha256 is not None:
        try:
            att_digest = _b64url_decode(att_sha256, check="att_sha256 claim")
        except ReceiptStructureError as exc:
            raise ReceiptClaimsError(str(exc)) from exc
        if len(att_digest) != 32:
            raise ReceiptClaimsError(
                "att_sha256 claim check failed: SHA-256 digest must be 32 bytes"
            )
    if not envelope.flattened and att_sha256 is None:
        raise ReceiptClaimsError(
            "att_sha256 claim check failed: compact receipts must pin an attestation document"
        )

    attestation_status = _attestation_status(
        envelope,
        header,
        public_key,
        attestation=attestation,
        att_sha256=att_sha256,
        require_attestation=require_attestation,
    )

    req = _digest_claim(
        _required_mapping(payload, "req", error_type=ReceiptHashError),
        name="req",
        response=False,
    )
    if request_body is not None:
        actual = hashlib.sha256(_body_bytes(request_body, check="request body hash")).digest()
        if not hmac.compare_digest(actual, _b64url_decode(req.hash, check="req.hash")):
            raise ReceiptHashError("request body hash check failed: req.hash does not match")

    resp = _digest_claim(
        _required_mapping(payload, "resp", error_type=ReceiptHashError),
        name="resp",
        response=True,
    )
    if response_body is not None and response_stream is not None:
        raise ReceiptHashError(
            "response hash check failed: provide response_body or response_stream, not both"
        )
    expected_response_digest = _b64url_decode(resp.hash, check="resp.hash")
    if response_body is not None:
        if resp.of != "body":
            raise ReceiptHashError(
                f"response body hash check failed: resp.of is {resp.of!r}, expected 'body'"
            )
        actual = hashlib.sha256(_body_bytes(response_body, check="response body hash")).digest()
        if not hmac.compare_digest(actual, expected_response_digest):
            raise ReceiptHashError("response body hash check failed: resp.hash does not match")
    elif response_stream is not None:
        if resp.of not in {"sse-data-v1", "sse-events-v1"}:
            raise ReceiptHashError(
                f"response stream hash check failed: resp.of is {resp.of!r}, expected an SSE domain"
            )
        stream = _body_bytes(response_stream, check="response stream hash")
        actual, event_count = _stream_digest(
            stream, domain=resp.of, expected_receipt=envelope.flattened_value
        )
        if not hmac.compare_digest(actual, expected_response_digest):
            raise ReceiptHashError("response stream hash check failed: resp.hash does not match")
        if event_count != resp.events:
            raise ReceiptHashError(
                f"response stream events check failed: counted {event_count}, "
                f"receipt claims {resp.events}"
            )

    jti = _required_str(payload, "jti")
    gen = _optional_str(payload, "gen")
    route = _required_str(payload, "route")
    if route not in {"chat.completions", "responses"}:
        raise ReceiptClaimsError(f"route claim check failed: unsupported route {route!r}")
    model_raw = _required_mapping(payload, "model")
    model = ReceiptModelClaims(
        requested=_required_str(model_raw, "requested", family="model"),
        selected=_required_str(model_raw, "selected", family="model"),
        provider=_required_str(model_raw, "provider", family="model"),
        endpoint=_required_str(model_raw, "endpoint", family="model"),
    )
    policy = _optional_str(upstream_raw, "policy", family="upstream")
    if tier == "tee-verified" and policy is None:
        raise ReceiptUpstreamError(
            "upstream.policy check failed: tee-verified receipts require a policy"
        )
    cert_sha256 = _optional_str(upstream_raw, "cert_sha256", family="upstream")
    upstream = ReceiptUpstreamClaims(
        tier=tier,
        policy=policy,
        verified_at=verified_at,
        verification_expires_at=verification_expires_at,
        cert_sha256=cert_sha256,
    )
    return ReceiptClaims(
        rv=rv,
        iss=iss,
        iat=iat,
        jti=jti,
        gen=gen,
        nonce=nonce,
        route=route,
        req=req,
        resp=resp,
        model=model,
        upstream=upstream,
        att_sha256=att_sha256,
        attestation_status=attestation_status,
    )


class ReceiptCapture(Iterator[bytes]):
    """Wrap raw SSE byte chunks, preserving them exactly for receipt verification."""

    def __init__(self, source: Iterable[bytes]) -> None:
        self._source = iter(source)
        self._wire = bytearray()
        self._receipt: dict[str, Any] | None = None

    def __iter__(self) -> ReceiptCapture:
        return self

    def __next__(self) -> bytes:
        chunk = next(self._source)
        if not isinstance(chunk, bytes):
            raise TypeError("ReceiptCapture source must yield raw bytes")
        self._wire.extend(chunk)
        self._refresh_receipt()
        return chunk

    @property
    def receipt(self) -> dict[str, Any] | None:
        return self._receipt

    @property
    def captured_bytes(self) -> bytes:
        return bytes(self._wire)

    def _refresh_receipt(self) -> None:
        data = bytes(self._wire)
        offset = 0
        while offset < len(data):
            found = _next_sse_event(data, offset)
            if found is None:
                return
            raw, offset = found
            try:
                event = _decode_sse_event(raw)
                embedded = _embedded_receipt(event.payload)
            except ReceiptVerificationError:
                continue
            if embedded is not None:
                self._receipt = dict(embedded)

    def verify(self, *, expected_issuer: str, **kwargs: Any) -> ReceiptClaims:
        """Verify the captured receipt and SSE bytes against a pinned issuer."""
        if self._receipt is None:
            self._refresh_receipt()
        if self._receipt is None:
            raise ReceiptStructureError(
                "receipt capture check failed: no flattened receipt event has been captured"
            )
        if "response_stream" in kwargs:
            raise TypeError("ReceiptCapture.verify supplies response_stream from captured bytes")
        return verify_receipt(
            self._receipt,
            expected_issuer=expected_issuer,
            response_stream=bytes(self._wire),
            **kwargs,
        )


__all__ = [
    "MissingAttestationError",
    "MissingBindingError",
    "ReceiptAttestationError",
    "ReceiptCapture",
    "ReceiptClaims",
    "ReceiptClaimsError",
    "ReceiptHashClaims",
    "ReceiptHashError",
    "ReceiptHeaderError",
    "ReceiptIssuerError",
    "ReceiptModelClaims",
    "ReceiptNonceError",
    "ReceiptSignatureError",
    "ReceiptStructureError",
    "ReceiptTimeError",
    "ReceiptUpstreamClaims",
    "ReceiptUpstreamError",
    "ReceiptVerificationError",
    "UnsupportedAttestationError",
    "verify_receipt",
]
