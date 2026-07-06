"""Attested TLS session verification for TrustedRouter gateways.

This module exists because Python's stdlib ``ssl`` module does not expose
RFC 9266 TLS exporter material. The G6 path uses pyOpenSSL only for the
connection that fetches ``/attestation`` and returns that same live connection
so callers can pin the next sensitive request to the attested TLS session.
"""
from __future__ import annotations

import ipaddress
import secrets
import select
import socket
import time
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from trustedrouter.attestation import (
    EXPORTER_LABEL,
    EXPORTER_LENGTH,
    GCP_JWKS_URI,
    AttestationPolicy,
    AttestationVerificationError,
    GatewayAttestation,
    verify_gateway_attestation,
)

_TLS_IO_TIMEOUT_SECONDS = 15.0
_DUPLICATE_FRAMING_HEADER_ERROR = (
    "malformed attestation response: duplicate framing header"
)


@dataclass
class GatewaySession:
    """Verified session binding result.

    ``connection`` is the live pyOpenSSL ``SSL.Connection`` used to fetch and
    verify ``/attestation``. Keep it open for the request being pinned.
    """

    attestation: GatewayAttestation
    connection: Any
    exporter: bytes
    leaf_der: bytes


def _load_pyopenssl() -> tuple[Any, Any]:
    try:
        from OpenSSL import SSL, crypto  # type: ignore[import-not-found,import-untyped]
    except ImportError as exc:  # pragma: no cover - depends on local extras
        raise ImportError(
            "G6 TLS session verification requires pyOpenSSL; install with "
            "`pip install trustedrouter[attestation]` or `pip install pyopenssl`."
        ) from exc
    return SSL, crypto


def _verify_callback(
    _conn: Any,
    _cert: Any,
    _errnum: int,
    _depth: int,
    ok: int,
) -> bool:
    return bool(ok)


def _normalize_dns_name(name: str) -> str:
    labels = name.rstrip(".").split(".")
    return ".".join(
        label if label == "*" else label.encode("idna").decode("ascii")
        for label in labels
    ).lower()


def _dnsname_matches(pattern: str, host: str) -> bool:
    try:
        pattern_norm = _normalize_dns_name(pattern)
        host_norm = _normalize_dns_name(host)
    except UnicodeError:
        return False
    if "*" not in pattern_norm:
        return host_norm == pattern_norm

    pattern_labels = pattern_norm.split(".")
    host_labels = host_norm.split(".")
    if pattern_norm.count("*") != 1 or pattern_labels[0] != "*" or len(pattern_labels) < 3:
        return False
    return (
        len(host_labels) == len(pattern_labels)
        and host_labels[1:] == pattern_labels[1:]
        and host_labels[0] != ""
    )


def _ip_literal(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    value = host.strip()
    if value.startswith("[") and value.endswith("]"):
        value = value[1:-1]
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def _assert_cert_matches_hostname(cert_der: bytes, host: str) -> None:
    try:
        from cryptography import x509
    except ImportError as exc:  # pragma: no cover - pyOpenSSL normally depends on it
        raise AttestationVerificationError(
            "session verification requires the `cryptography` package; install with "
            "`pip install trustedrouter[attestation]`"
        ) from exc

    cert = x509.load_der_x509_certificate(cert_der)
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        san = None
    dns_names = san.get_values_for_type(x509.DNSName) if san is not None else []
    ip_addresses = san.get_values_for_type(x509.IPAddress) if san is not None else []
    if not dns_names and not ip_addresses:
        raise AttestationVerificationError(
            f"TLS certificate has no DNS/IP SubjectAlternativeName for {host}"
        )

    host_ip = _ip_literal(host)
    if host_ip is not None:
        if any(host_ip == candidate for candidate in ip_addresses):
            return
    elif any(_dnsname_matches(pattern, host) for pattern in dns_names):
        return

    san_text = [f"DNS:{name}" for name in dns_names]
    san_text.extend(f"IP:{addr}" for addr in ip_addresses)
    raise AttestationVerificationError(
        f"TLS certificate hostname mismatch for {host}: "
        f"no matching SubjectAlternativeName in {san_text}"
    )


def _new_pyopenssl_context() -> Any:
    SSL, _crypto = _load_pyopenssl()
    ctx = SSL.Context(SSL.TLS_CLIENT_METHOD)
    if hasattr(ctx, "set_min_proto_version") and hasattr(SSL, "TLS1_3_VERSION"):
        ctx.set_min_proto_version(SSL.TLS1_3_VERSION)
    else:
        ctx.set_options(SSL.OP_NO_TLSv1 | SSL.OP_NO_TLSv1_1 | SSL.OP_NO_TLSv1_2)
    ctx.set_default_verify_paths()
    ctx.set_verify(SSL.VERIFY_PEER, _verify_callback)
    return ctx


def _ssl_call(sock: socket.socket, op: Any, *, timeout: float, what: str) -> Any:
    """Run a pyOpenSSL socket-BIO operation with select retries.

    pyOpenSSL exposes WantRead/WantWrite for timeout-mode sockets. The G6
    transport must preserve the same TLS session, so every handshake/read/write
    is retried on the original fd instead of falling back to another client.
    """
    SSL, _crypto = _load_pyopenssl()
    deadline = time.monotonic() + timeout
    while True:
        try:
            return op()
        except SSL.WantReadError as exc:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([sock], [], [], remaining)[0]:
                raise TimeoutError(f"{what}: TLS read timeout") from exc
        except SSL.WantWriteError as exc:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([], [sock], [], remaining)[1]:
                raise TimeoutError(f"{what}: TLS write timeout") from exc


def _tls_timeout_remaining(deadline: float, what: str) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError(f"{what}: TLS operation deadline exceeded")
    return min(_TLS_IO_TIMEOUT_SECONDS, remaining)


def _ssl_send_all(
    sock: socket.socket,
    conn: Any,
    data: bytes,
    *,
    deadline: float,
    what: str,
) -> None:
    sent = 0
    while sent < len(data):
        chunk = data[sent:]
        n = _ssl_call(
            sock,
            lambda chunk=chunk: conn.send(chunk),
            timeout=_tls_timeout_remaining(deadline, what),
            what=what,
        )
        if n <= 0:
            raise EOFError(f"{what}: TLS send returned {n}")
        sent += n


def _recv_or_fail(conn: Any, raw: socket.socket, context: str, *, deadline: float) -> bytes:
    SSL, _crypto = _load_pyopenssl()
    try:
        chunk = _ssl_call(
            raw,
            lambda: conn.recv(65536),
            timeout=_tls_timeout_remaining(deadline, f"{context} recv"),
            what=f"{context} recv",
        )
    except SSL.ZeroReturnError as exc:
        raise EOFError(context) from exc
    if not chunk:
        raise EOFError(context)
    return chunk


def _read_http_response(
    conn: Any,
    raw: socket.socket,
    context: str,
    *,
    deadline: float,
) -> tuple[str, dict[str, str], bytes]:
    response = bytearray()
    while b"\r\n\r\n" not in response:
        response.extend(_recv_or_fail(conn, raw, context, deadline=deadline))
    header, sep, rest = bytes(response).partition(b"\r\n\r\n")
    if sep == b"":
        raise AttestationVerificationError(
            f"{context} HTTP response had no header/body separator"
        )
    lines = header.splitlines()
    if not lines:
        raise AttestationVerificationError(f"{context} HTTP response had no status line")
    status_line = lines[0].decode("latin1", "replace")
    headers: dict[str, str] = {}
    framing_headers_seen: set[str] = set()
    for line in lines[1:]:
        name, colon, value = line.partition(b":")
        if colon:
            header_name = name.decode("latin1").strip().lower()
            if header_name in {"content-length", "connection"}:
                if header_name in framing_headers_seen:
                    raise AttestationVerificationError(_DUPLICATE_FRAMING_HEADER_ERROR)
                framing_headers_seen.add(header_name)
            headers[header_name] = value.decode("latin1").strip()
    try:
        content_length = int(headers["content-length"])
    except KeyError as exc:
        raise AttestationVerificationError(
            f"{context} HTTP response had no Content-Length"
        ) from exc
    except ValueError as exc:
        raise AttestationVerificationError(
            f"{context} HTTP response had invalid Content-Length: "
            f"{headers.get('content-length')!r}"
        ) from exc
    if content_length < 0:
        raise AttestationVerificationError(
            f"{context} HTTP response had negative Content-Length"
        )
    body = bytearray(rest)
    while len(body) < content_length:
        body.extend(_recv_or_fail(conn, raw, context, deadline=deadline))
    return status_line, headers, bytes(body[:content_length])


def _connection_close_requested(headers: Mapping[str, str]) -> bool:
    return any(
        token.strip().lower() == "close"
        for token in headers.get("connection", "").split(",")
    )


def _attestation_request(host_header: str, nonce_hex: str) -> bytes:
    return (
        f"GET /attestation?nonce={nonce_hex} HTTP/1.1\r\n"
        f"Host: {host_header}\r\n"
        "Accept: application/jwt, application/cbor, */*\r\n"
        "Connection: keep-alive\r\n"
        "\r\n"
    ).encode("ascii")


def _ascii_host(host: str) -> str:
    if _ip_literal(host) is not None:
        return host
    return host.encode("idna").decode("ascii")


def _host_header(host: str, port: int, explicit_port: bool) -> str:
    host_ascii = _ascii_host(host)
    if _ip_literal(host_ascii) is not None and ":" in host_ascii:
        host_ascii = f"[{host_ascii}]"
    if explicit_port and port != 443:
        return f"{host_ascii}:{port}"
    return host_ascii


def _parse_base_url(base_url: str) -> tuple[str, int, str]:
    parsed = urlsplit(base_url)
    if parsed.scheme != "https":
        raise ValueError("verify_gateway_session requires an https base_url")
    if parsed.username or parsed.password:
        raise ValueError("verify_gateway_session base_url must not include credentials")
    host = parsed.hostname
    if not host:
        raise ValueError("verify_gateway_session base_url must include a host")
    try:
        port = parsed.port or 443
    except ValueError as exc:
        raise ValueError(f"invalid base_url port: {exc}") from exc
    return host, port, _host_header(host, port, parsed.port is not None)


def _close_connection(conn: Any | None, raw: socket.socket | None = None) -> None:
    if conn is not None:
        with suppress(Exception):
            conn.shutdown()
        with suppress(Exception):
            conn.close()
        return
    if raw is not None:
        with suppress(Exception):
            raw.close()


def _read_attestation(
    *,
    conn: Any,
    raw: socket.socket,
    host_header: str,
    nonce_hex: str,
    deadline: float,
    context: str,
) -> bytes:
    _ssl_send_all(
        raw,
        conn,
        _attestation_request(host_header, nonce_hex),
        deadline=deadline,
        what=f"{context} request",
    )
    status_line, headers, body = _read_http_response(
        conn,
        raw,
        context,
        deadline=deadline,
    )
    if " 200 " not in status_line:
        raise AttestationVerificationError(
            f"{context} HTTP status was not 200: {status_line}"
        )
    if not body:
        raise AttestationVerificationError(f"empty {context} attestation body")
    if _connection_close_requested(headers):
        raise AttestationVerificationError(
            f"{context} response requested Connection: close; session is unpinnable"
        )
    return body


def verify_gateway_session(
    *,
    base_url: str,
    policy: AttestationPolicy,
    jwks: Mapping[str, Any] | None = None,
    jwks_url: str = GCP_JWKS_URI,
    connect_ip: str | None = None,
    timeout: float = 15.0,
) -> GatewaySession:
    """Verify G6 attestation on one TLS 1.3 connection and return it pinned."""
    SSL, crypto = _load_pyopenssl()
    host, port, host_header = _parse_base_url(base_url)
    ctx = _new_pyopenssl_context()
    deadline = time.monotonic() + timeout
    raw: socket.socket | None = None
    conn: Any | None = None
    try:
        # connect_ip targets one backend while SNI, Host, cert validation, and
        # attestation policy all stay on the canonical base-url hostname.
        raw = socket.create_connection((connect_ip or host, port), timeout=min(10.0, timeout))
        conn = SSL.Connection(ctx, raw)
        conn.set_tlsext_host_name(_ascii_host(host).encode("ascii"))
        conn.set_connect_state()
        _ssl_call(
            raw,
            conn.do_handshake,
            timeout=_tls_timeout_remaining(deadline, "handshake"),
            what="handshake",
        )
        peer = conn.get_peer_certificate()
        if peer is None:
            raise AttestationVerificationError("TLS handshake returned no peer certificate")
        leaf_der = crypto.dump_certificate(crypto.FILETYPE_ASN1, peer)
        _assert_cert_matches_hostname(leaf_der, host)
        exporter = conn.export_keying_material(EXPORTER_LABEL, EXPORTER_LENGTH)

        nonce_hex = secrets.token_hex(32)
        body = _read_attestation(
            conn=conn,
            raw=raw,
            host_header=host_header,
            nonce_hex=nonce_hex,
            deadline=deadline,
            context="attestation",
        )
        attestation = verify_gateway_attestation(
            body,
            policy=policy,
            nonce_hex=nonce_hex,
            tls_cert_der=leaf_der,
            tls_exporter=exporter,
            jwks=jwks,
            jwks_url=jwks_url,
        )
        session = GatewaySession(
            attestation=attestation,
            connection=conn,
            exporter=exporter,
            leaf_der=leaf_der,
        )
        session._raw_socket = raw  # type: ignore[attr-defined]
        session._host_header = host_header  # type: ignore[attr-defined]
        session._policy = policy  # type: ignore[attr-defined]
        session._jwks = jwks  # type: ignore[attr-defined]
        session._jwks_url = jwks_url  # type: ignore[attr-defined]
        session._timeout = timeout  # type: ignore[attr-defined]
        return session
    except Exception:
        _close_connection(conn, raw)
        raise


def fetch_attestation_again(session: GatewaySession) -> GatewayAttestation:
    """Fetch and verify a second `/attestation` on the same pinned connection."""
    raw = getattr(session, "_raw_socket", None)
    host_header = getattr(session, "_host_header", None)
    policy = getattr(session, "_policy", None)
    jwks = getattr(session, "_jwks", None)
    jwks_url = getattr(session, "_jwks_url", GCP_JWKS_URI)
    timeout = getattr(session, "_timeout", _TLS_IO_TIMEOUT_SECONDS)
    if not isinstance(raw, socket.socket) or not isinstance(host_header, str):
        raise AttestationVerificationError(
            "GatewaySession is missing its pinned raw socket metadata"
        )
    if not isinstance(policy, AttestationPolicy):
        raise AttestationVerificationError(
            "GatewaySession is missing its attestation policy metadata"
        )

    deadline = time.monotonic() + float(timeout)
    nonce_hex = secrets.token_hex(32)
    body = _read_attestation(
        conn=session.connection,
        raw=raw,
        host_header=host_header,
        nonce_hex=nonce_hex,
        deadline=deadline,
        context="follow-up attestation",
    )
    followup_exporter = session.connection.export_keying_material(
        EXPORTER_LABEL,
        EXPORTER_LENGTH,
    )
    if followup_exporter != session.exporter:
        raise AttestationVerificationError("TLS exporter changed on a reused socket")
    return verify_gateway_attestation(
        body,
        policy=policy,
        nonce_hex=nonce_hex,
        tls_cert_der=session.leaf_der,
        tls_exporter=session.exporter,
        jwks=jwks,
        jwks_url=jwks_url,
    )


__all__ = [
    "GatewaySession",
    "fetch_attestation_again",
    "verify_gateway_session",
]
