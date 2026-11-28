"""HTTP/1 inference on the TLS socket verified by the gateway session verifier."""

from __future__ import annotations

import re
import time
from collections.abc import AsyncIterator, Iterator, Mapping
from typing import Any
from urllib.parse import urlsplit

import anyio
import httpcore
import httpx

from .attestation import AttestationPolicy, AttestationVerificationError
from .session import (
    GatewaySession,
    _close_connection,
    _load_pyopenssl,
    _ssl_call,
    _ssl_send_all,
    verify_gateway_session,
)


def private_requested(url: str, body: object) -> bool:
    if {"trusted", "confidential"}.intersection((urlsplit(url).hostname or "").split(".")):
        return True
    if not isinstance(body, Mapping):
        return False
    provider = body.get("provider")
    floor = provider.get("min_privacy") if isinstance(provider, Mapping) else None
    if isinstance(floor, str) and floor.strip().lower() in {
        "trusted",
        "confidential",
        "e2e",
        "e2ee",
        "max",
        "maximum",
    }:
        return True
    fallbacks = body.get("models")
    ids = [body.get("model"), *(fallbacks if isinstance(fallbacks, list) else [])]
    return any(
        isinstance(i, str)
        and re.match(
            r"^(trustedrouter|nyte)/(trusted|confidential|e2e)(:|$)",
            i.strip(),
            re.I,
        )
        for i in ids
    )


def check_policy(policy: AttestationPolicy) -> AttestationPolicy:
    if policy.expected_nitro_pcr0s:
        return policy
    pins = policy.expected_image_digests or (policy.expected_image_digest,)
    if policy.allow_debug or not all(p and re.fullmatch(r"sha256:[a-f0-9]{64}", p) for p in pins):
        raise AttestationVerificationError("private inference requires non-debug sha256 image pins")
    return policy


class _Socket(httpcore.NetworkStream):
    def __init__(self, session: GatewaySession) -> None:
        self.session = session

    def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        s = self.session
        assert s._raw_socket is not None
        ssl, _ = _load_pyopenssl()
        try:
            chunk = _ssl_call(
                s._raw_socket,
                lambda: s.connection.recv(max_bytes),
                timeout=timeout if timeout is not None else 60,
                what="inference read",
            )
        except ssl.ZeroReturnError:
            return b""
        if not isinstance(chunk, bytes):
            raise AttestationVerificationError("invalid TLS read")
        return chunk

    def write(self, buffer: bytes, timeout: float | None = None) -> None:
        s = self.session
        assert s._raw_socket is not None
        _ssl_send_all(
            s._raw_socket,
            s.connection,
            buffer,
            deadline=time.monotonic() + (timeout if timeout is not None else 60),
            what="inference write",
        )

    def close(self) -> None:
        _close_connection(self.session.connection, self.session._raw_socket)


def _open(request: httpx.Request, policy: AttestationPolicy) -> _Socket:
    if request.url.scheme != "https" or request.url.userinfo:
        raise AttestationVerificationError("verified inference requires HTTPS without userinfo")
    timeout = request.extensions.get("timeout", {}).get("connect")
    return _Socket(
        verify_gateway_session(
            base_url=str(request.url), policy=policy, timeout=15 if timeout is None else timeout
        )
    )


def _request(request: httpx.Request) -> httpcore.Request:
    headers = httpx.Headers(request.headers)
    headers["host"] = request.url.netloc.decode("ascii")
    return httpcore.Request(
        request.method,
        str(request.url),
        headers=headers.raw,
        content=request.content,
        extensions=request.extensions,
    )


class _Body(httpx.SyncByteStream):
    def __init__(self, response: httpcore.Response, stream: _Socket) -> None:
        self.response, self.stream = response, stream

    def __iter__(self) -> Iterator[bytes]:
        yield from self.response.iter_stream()

    def close(self) -> None:
        try:
            self.response.close()
        finally:
            self.stream.close()


class VerifiedTransport(httpx.BaseTransport):
    def __init__(self, policy: AttestationPolicy) -> None:
        self.policy = check_policy(policy)

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        req = _request(request)
        sock = _open(request, self.policy)
        try:
            conn = httpcore.HTTP11Connection(req.url.origin, sock)
            res = conn.handle_request(req)
            return httpx.Response(res.status, headers=res.headers, stream=_Body(res, sock))
        except BaseException:
            sock.close()
            raise


class _AsyncSocket(httpcore.AsyncNetworkStream):
    def __init__(self, stream: _Socket) -> None:
        self.stream = stream

    async def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        return await anyio.to_thread.run_sync(self.stream.read, max_bytes, timeout)

    async def write(self, buffer: bytes, timeout: float | None = None) -> None:
        await anyio.to_thread.run_sync(self.stream.write, buffer, timeout)

    async def aclose(self) -> None:
        self.stream.close()


class _AsyncBody(httpx.AsyncByteStream):
    def __init__(self, response: httpcore.Response, stream: _Socket) -> None:
        self.response, self.stream = response, stream

    async def __aiter__(self) -> AsyncIterator[bytes]:
        async for chunk in self.response.aiter_stream():
            yield chunk

    async def aclose(self) -> None:
        try:
            await self.response.aclose()
        finally:
            self.stream.close()


class AsyncVerifiedTransport(httpx.AsyncBaseTransport):
    def __init__(self, policy: AttestationPolicy) -> None:
        self.policy = check_policy(policy)

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        req = _request(request)
        sock = await anyio.to_thread.run_sync(_open, request, self.policy)
        try:
            conn = httpcore.AsyncHTTP11Connection(req.url.origin, _AsyncSocket(sock))
            res = await conn.handle_async_request(req)
            return httpx.Response(res.status, headers=res.headers, stream=_AsyncBody(res, sock))
        except BaseException:
            sock.close()
            raise


class VerifiedClient(httpx.Client):
    pass


class AsyncVerifiedClient(httpx.AsyncClient):
    pass


def require_verified(
    client: httpx.Client | httpx.AsyncClient, url: str, kwargs: Mapping[str, Any]
) -> None:
    if not isinstance(client, (VerifiedClient, AsyncVerifiedClient)) and private_requested(
        url, kwargs.get("json")
    ):
        raise AttestationVerificationError(
            "private inference requires an image-pinned gateway_policy"
        )
