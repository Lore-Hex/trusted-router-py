from __future__ import annotations

import base64
import datetime as dt
import hashlib
import importlib.util
import json
import socket
import tempfile
import threading
import time
import urllib.parse
from contextlib import suppress
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

import trustedrouter.session as tr_session
from trustedrouter.attestation import GCP_ISSUER, AttestationPolicy, GatewayAttestation


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _public_jwk(key: rsa.RSAPrivateKey, kid: str = "loopback-kid") -> dict[str, str]:
    public = key.public_key()
    numbers = public.public_numbers()
    n = numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")
    e = numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")
    return {
        "kid": kid,
        "kty": "RSA",
        "alg": "RS256",
        "use": "sig",
        "n": _b64url(n),
        "e": _b64url(e),
    }


def _make_jwt(
    key: rsa.RSAPrivateKey,
    claims: dict[str, object],
    *,
    kid: str = "loopback-kid",
) -> bytes:
    header = {"alg": "RS256", "typ": "JWT", "kid": kid}
    h = _b64url(json.dumps(header).encode())
    p = _b64url(json.dumps(claims).encode())
    signing_input = f"{h}.{p}".encode()
    sig = key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return f"{h}.{p}.{_b64url(sig)}".encode()


def _make_ca_and_server_cert() -> tuple[bytes, bytes, bytes, bytes]:
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = dt.datetime.now(dt.timezone.utc)
    ca_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "TR test CA")])
    server_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])

    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_subject)
        .issuer_name(ca_subject)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=1))
        .not_valid_after(now + dt.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    server_cert = (
        x509.CertificateBuilder()
        .subject_name(server_subject)
        .issuer_name(ca_cert.subject)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=1))
        .not_valid_after(now + dt.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    return (
        server_cert.public_bytes(serialization.Encoding.DER),
        server_cert.public_bytes(serialization.Encoding.PEM),
        server_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ),
        ca_cert.public_bytes(serialization.Encoding.PEM),
    )


def _set_tls13_minimum(ctx: Any, ssl_mod: Any) -> None:
    if hasattr(ctx, "set_min_proto_version") and hasattr(ssl_mod, "TLS1_3_VERSION"):
        ctx.set_min_proto_version(ssl_mod.TLS1_3_VERSION)
    else:
        ctx.set_options(ssl_mod.OP_NO_TLSv1 | ssl_mod.OP_NO_TLSv1_1 | ssl_mod.OP_NO_TLSv1_2)


def _close_pyopenssl_connection(conn: Any) -> None:
    with suppress(Exception):
        conn.shutdown()
    with suppress(Exception):
        conn.close()


def _http_response(body: bytes, *, connection: str = "keep-alive") -> bytes:
    return (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: application/jwt\r\n"
        + f"Connection: {connection}\r\n".encode("ascii")
        + f"Content-Length: {len(body)}\r\n".encode("ascii")
        + b"\r\n"
        + body
    )


def _read_fake_http_response(
    response: bytes,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[str, dict[str, str], bytes]:
    class WantReadError(Exception):
        pass

    class WantWriteError(Exception):
        pass

    class ZeroReturnError(Exception):
        pass

    fake_ssl = SimpleNamespace(
        WantReadError=WantReadError,
        WantWriteError=WantWriteError,
        ZeroReturnError=ZeroReturnError,
    )

    class FakeConnection:
        def __init__(self, data: bytes) -> None:
            self.data: list[bytes] = [data]

        def recv(self, _size: int) -> bytes:
            if self.data:
                return self.data.pop(0)
            return b""

    monkeypatch.setattr(tr_session, "_load_pyopenssl", lambda: (fake_ssl, object()))
    first, second = socket.socketpair()
    try:
        return tr_session._read_http_response(
            FakeConnection(response),
            first,
            "attestation",
            deadline=time.monotonic() + 1.0,
        )
    finally:
        first.close()
        second.close()


def test_verify_gateway_session_raises_clear_hint_without_pyopenssl() -> None:
    if importlib.util.find_spec("OpenSSL") is not None:
        pytest.skip("pyOpenSSL is installed")

    with pytest.raises(ImportError, match="pyOpenSSL"):
        tr_session.verify_gateway_session(
            base_url="https://localhost",
            policy=AttestationPolicy(),
            jwks={"keys": []},
        )


def test_parse_base_url_and_connection_close_helpers() -> None:
    assert tr_session._parse_base_url("https://localhost:8443/v1") == (
        "localhost",
        8443,
        "localhost:8443",
    )
    assert tr_session._parse_base_url("https://[::1]:9443") == (
        "::1",
        9443,
        "[::1]:9443",
    )
    assert tr_session._connection_close_requested({"connection": "keep-alive, close"})
    assert not tr_session._connection_close_requested({"connection": "keep-alive"})
    with pytest.raises(ValueError, match="https"):
        tr_session._parse_base_url("http://localhost")


def test_session_hostname_verifier_accepts_san_and_rejects_mismatch() -> None:
    leaf_der, _cert_pem, _key_pem, _ca_pem = _make_ca_and_server_cert()

    tr_session._assert_cert_matches_hostname(leaf_der, "localhost")
    with pytest.raises(tr_session.AttestationVerificationError, match="hostname mismatch"):
        tr_session._assert_cert_matches_hostname(leaf_der, "example.com")


@pytest.mark.parametrize(
    "response",
    [
        (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: application/jwt\r\n"
            b"Connection: keep-alive\r\n"
            b"Content-Length: 3\r\n"
            b"Content-Length: 4\r\n"
            b"\r\n"
            b"jwt"
        ),
        (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: application/jwt\r\n"
            b"Connection: close\r\n"
            b"Connection: keep-alive\r\n"
            b"Content-Length: 3\r\n"
            b"\r\n"
            b"jwt"
        ),
    ],
)
def test_read_http_response_rejects_duplicate_framing_headers(
    response: bytes,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(
        tr_session.AttestationVerificationError,
        match="malformed attestation response: duplicate framing header",
    ):
        _read_fake_http_response(response, monkeypatch)


def test_ssl_call_retries_want_read_and_want_write(monkeypatch: pytest.MonkeyPatch) -> None:
    class WantReadError(Exception):
        pass

    class WantWriteError(Exception):
        pass

    class ZeroReturnError(Exception):
        pass

    FakeSSL = SimpleNamespace(
        WantReadError=WantReadError,
        WantWriteError=WantWriteError,
        ZeroReturnError=ZeroReturnError,
    )

    monkeypatch.setattr(tr_session, "_load_pyopenssl", lambda: (FakeSSL, object()))

    first, second = socket.socketpair()
    try:
        second.send(b"x")
        read_calls = 0

        def read_op() -> str:
            nonlocal read_calls
            read_calls += 1
            if read_calls == 1:
                raise WantReadError
            return "read-ok"

        write_calls = 0

        def write_op() -> str:
            nonlocal write_calls
            write_calls += 1
            if write_calls == 1:
                raise WantWriteError
            return "write-ok"

        assert tr_session._ssl_call(first, read_op, timeout=1.0, what="read") == "read-ok"
        assert tr_session._ssl_call(first, write_op, timeout=1.0, what="write") == "write-ok"
    finally:
        first.close()
        second.close()


def test_verify_gateway_session_with_fake_pyopenssl_transport(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    leaf_der = b"fake-leaf-der"
    exporter = bytes.fromhex("cd" * 32)
    bodies = [b"first-jwt", b"followup-jwt"]
    responses = [_http_response(body) for body in bodies]
    client_sock, server_sock = socket.socketpair()
    instances: list[Any] = []

    class WantReadError(Exception):
        pass

    class WantWriteError(Exception):
        pass

    class ZeroReturnError(Exception):
        pass

    class FakeContext:
        def __init__(self, _method: object) -> None:
            self.min_proto_version: object | None = None

        def set_min_proto_version(self, version: object) -> None:
            self.min_proto_version = version

        def set_default_verify_paths(self) -> None:
            return None

        def set_verify(self, _mode: int, _callback: object) -> None:
            return None

    class FakeConnection:
        def __init__(self, _ctx: FakeContext, raw: socket.socket) -> None:
            self.raw = raw
            self.sent: list[bytes] = []
            self.responses = list(responses)
            self.closed = False
            instances.append(self)

        def set_tlsext_host_name(self, name: bytes) -> None:
            assert name == b"localhost"

        def set_connect_state(self) -> None:
            return None

        def do_handshake(self) -> None:
            return None

        def get_peer_certificate(self) -> object:
            return object()

        def export_keying_material(self, label: bytes, length: int) -> bytes:
            assert label == tr_session.EXPORTER_LABEL
            assert length == tr_session.EXPORTER_LENGTH
            return exporter

        def send(self, data: bytes) -> int:
            self.sent.append(data)
            return len(data)

        def recv(self, _size: int) -> bytes:
            if not self.responses:
                raise ZeroReturnError
            return self.responses.pop(0)

        def shutdown(self) -> None:
            return None

        def close(self) -> None:
            self.closed = True
            self.raw.close()

    FakeSSL = SimpleNamespace(
        TLS_CLIENT_METHOD=object(),
        TLS1_3_VERSION=object(),
        VERIFY_PEER=1,
        OP_NO_TLSv1=1,
        OP_NO_TLSv1_1=2,
        OP_NO_TLSv1_2=4,
        Context=FakeContext,
        Connection=FakeConnection,
        WantReadError=WantReadError,
        WantWriteError=WantWriteError,
        ZeroReturnError=ZeroReturnError,
    )

    class FakeCrypto:
        FILETYPE_ASN1 = object()

        @staticmethod
        def dump_certificate(_filetype: object, _peer: object) -> bytes:
            return leaf_der

    verified: list[dict[str, object]] = []

    def fake_verify_gateway_attestation(
        document: bytes,
        *,
        policy: AttestationPolicy,
        nonce_hex: str | None,
        tls_cert_der: bytes | None,
        tls_exporter: bytes | None,
        jwks: object,
        jwks_url: str,
    ) -> GatewayAttestation:
        verified.append(
            {
                "document": document,
                "policy": policy,
                "nonce_hex": nonce_hex,
                "tls_cert_der": tls_cert_der,
                "tls_exporter": tls_exporter,
                "jwks": jwks,
                "jwks_url": jwks_url,
            }
        )
        assert nonce_hex is not None
        assert nonce_hex != exporter.hex()
        return GatewayAttestation(
            cert_sha256="1" * 64,
            image_digest="sha256:fake",
            image_reference="localhost/fake:test",
            nonce=nonce_hex,
            expires_at=None,
            issuer=GCP_ISSUER,
            audience="quill-cloud",
            raw_claims={},
        )

    def fake_create_connection(
        target: tuple[str, int],
        timeout: float,
    ) -> socket.socket:
        assert target == ("127.0.0.1", 9443)
        assert timeout == 5.0
        return client_sock

    monkeypatch.setattr(tr_session, "_load_pyopenssl", lambda: (FakeSSL, FakeCrypto))
    monkeypatch.setattr(tr_session.socket, "create_connection", fake_create_connection)

    def fake_assert_cert_matches_hostname(cert: bytes, host: str) -> None:
        assert cert == leaf_der
        assert host == "localhost"

    monkeypatch.setattr(
        tr_session,
        "_assert_cert_matches_hostname",
        fake_assert_cert_matches_hostname,
    )
    monkeypatch.setattr(
        tr_session,
        "verify_gateway_attestation",
        fake_verify_gateway_attestation,
    )

    policy = AttestationPolicy(expected_image_digest="sha256:fake")
    jwks: dict[str, list[object]] = {"keys": []}
    gateway_session = tr_session.verify_gateway_session(
        base_url="https://localhost:9443/v1",
        policy=policy,
        jwks=jwks,
        jwks_url="https://jwks.example/keys",
        connect_ip="127.0.0.1",
        timeout=5.0,
    )
    try:
        assert gateway_session.exporter == exporter
        assert gateway_session.leaf_der == leaf_der
        followup = tr_session.fetch_attestation_again(gateway_session)
        assert followup.cert_sha256 == "1" * 64
    finally:
        gateway_session.connection.close()
        server_sock.close()

    assert [call["document"] for call in verified] == bodies
    sent = b"".join(instances[0].sent)
    assert b"GET /attestation?nonce=" in sent
    assert b"Host: localhost:9443\r\n" in sent
    assert b"Connection: keep-alive\r\n" in sent


def test_verify_gateway_session_loopback_binds_same_tls_exporter(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    openssl = pytest.importorskip("OpenSSL")
    SSL = openssl.SSL
    if not hasattr(SSL.Connection, "export_keying_material"):
        pytest.skip("pyOpenSSL export_keying_material unavailable")

    leaf_der, cert_pem, key_pem, ca_pem = _make_ca_and_server_cert()
    cert_sha = hashlib.sha256(leaf_der).hexdigest()
    signing_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwks = {"keys": [_public_jwk(signing_key)]}
    policy = AttestationPolicy(
        expected_image_digest="sha256:loopback",
        expected_image_reference="localhost/trustedrouter:test",
    )
    server_exporters: list[bytes] = []
    server_errors: list[BaseException] = []

    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        cert_path = temp_path / "server.pem"
        key_path = temp_path / "server-key.pem"
        ca_path = temp_path / "ca.pem"
        cert_path.write_bytes(cert_pem)
        key_path.write_bytes(key_pem)
        ca_path.write_bytes(ca_pem)

        server_ctx = SSL.Context(SSL.TLS_SERVER_METHOD)
        _set_tls13_minimum(server_ctx, SSL)
        server_ctx.use_certificate_file(str(cert_path))
        server_ctx.use_privatekey_file(str(key_path))
        server_ctx.check_privatekey()

        original_context = tr_session._new_pyopenssl_context

        def client_context() -> Any:
            ctx = original_context()
            ctx.load_verify_locations(str(ca_path))
            return ctx

        monkeypatch.setattr(tr_session, "_new_pyopenssl_context", client_context)

        def claims_for(nonce_hex: str, exporter: bytes) -> dict[str, object]:
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
                        "image_digest": "sha256:loopback",
                        "image_reference": "localhost/trustedrouter:test",
                    }
                },
                "tls_cert_sha256": cert_sha,
                "eat_nonce": [cert_sha, exporter.hex(), nonce_hex],
            }

        def serve_connection(raw: socket.socket) -> None:
            conn = SSL.Connection(server_ctx, raw)
            served = 0
            try:
                conn.set_accept_state()
                tr_session._ssl_call(
                    raw,
                    conn.do_handshake,
                    timeout=5.0,
                    what="loopback server handshake",
                )
                exporter = conn.export_keying_material(
                    tr_session.EXPORTER_LABEL,
                    tr_session.EXPORTER_LENGTH,
                )
                server_exporters.append(exporter)
                while True:
                    request = bytearray()
                    try:
                        while b"\r\n\r\n" not in request:
                            chunk = tr_session._ssl_call(
                                raw,
                                lambda: conn.recv(65536),
                                timeout=5.0 if served == 0 else 1.0,
                                what="loopback server recv",
                            )
                            if not chunk:
                                return
                            request.extend(chunk)
                    except TimeoutError:
                        if served > 0:
                            return
                        raise
                    except SSL.ZeroReturnError:
                        return

                    request_line = bytes(request).split(b"\r\n", 1)[0].decode("ascii")
                    method, target, _version = request_line.split(" ", 2)
                    assert method == "GET"
                    query = urllib.parse.parse_qs(urllib.parse.urlsplit(target).query)
                    nonce_hex = query["nonce"][0]
                    body = _make_jwt(signing_key, claims_for(nonce_hex, exporter))
                    response = (
                        b"HTTP/1.1 200 OK\r\n"
                        b"Content-Type: application/jwt\r\n"
                        b"Connection: keep-alive\r\n"
                        + f"Content-Length: {len(body)}\r\n".encode("ascii")
                        + b"\r\n"
                        + body
                    )
                    tr_session._ssl_send_all(
                        raw,
                        conn,
                        response,
                        deadline=time.monotonic() + 5.0,
                        what="loopback server send",
                    )
                    served += 1
            finally:
                _close_pyopenssl_connection(conn)

        port = 9443
        socket_pairs = [socket.socketpair(), socket.socketpair()]
        pending_clients = [client for client, _server in socket_pairs]
        server_sockets = [server for _client, server in socket_pairs]

        def fake_create_connection(
            target: tuple[str, int],
            timeout: float,
        ) -> socket.socket:
            assert target == ("127.0.0.1", port)
            assert timeout == 5.0
            if not pending_clients:
                raise AssertionError("unexpected loopback client connection")
            return pending_clients.pop(0)

        monkeypatch.setattr(tr_session.socket, "create_connection", fake_create_connection)

        def socketpair_loop() -> None:
            try:
                for raw in server_sockets:
                    serve_connection(raw)
            except BaseException as exc:
                server_errors.append(exc)

        thread = threading.Thread(target=socketpair_loop, daemon=True)
        thread.start()
        try:
            first = tr_session.verify_gateway_session(
                base_url=f"https://localhost:{port}/v1",
                policy=policy,
                jwks=jwks,
                connect_ip="127.0.0.1",
                timeout=5.0,
            )
            try:
                assert first.leaf_der == leaf_der
                assert first.exporter == server_exporters[0]
                followup = tr_session.fetch_attestation_again(first)
                assert followup.cert_sha256 == cert_sha
            finally:
                _close_pyopenssl_connection(first.connection)

            second = tr_session.verify_gateway_session(
                base_url=f"https://localhost:{port}/v1",
                policy=policy,
                jwks=jwks,
                connect_ip="127.0.0.1",
                timeout=5.0,
            )
            try:
                assert second.exporter == server_exporters[1]
                assert second.exporter != first.exporter
            finally:
                _close_pyopenssl_connection(second.connection)
        finally:
            for raw in pending_clients:
                with suppress(Exception):
                    raw.close()
            thread.join(timeout=10.0)
            if thread.is_alive():
                for raw in server_sockets:
                    with suppress(Exception):
                        raw.close()
                thread.join(timeout=1.0)

    assert not thread.is_alive()
    if server_errors:
        raise server_errors[0]
