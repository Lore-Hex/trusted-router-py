"""Stream codec (L5): SSE frame/line parsing and typed chunk iteration.

Pure functions over an already-opened response. No retry logic may ever
live here — the transport engine owns retries, and it never retries after
the first surfaced body byte.
"""

from __future__ import annotations

import json as jsonlib
from collections.abc import AsyncIterator, Iterator, Mapping
from typing import Any

import httpx

from trustedrouter._errors import _stream_protocol_error


def _sse_data(line: str) -> str | None:
    if not line.startswith("data:"):
        return None
    return line[len("data:") :].strip()


def _parse_sse_line(line: str) -> dict[str, Any] | None:
    """Parse one JSON ``data:`` line.

    Non-data lines and the terminal sentinel return ``None``.  A data frame
    that claims to be JSON but is malformed is a protocol failure rather than
    a heartbeat: silently dropping it can turn a corrupt answer into a valid-
    looking partial completion.
    """
    payload = _sse_data(line)
    if payload is None:
        return None
    if not payload or payload == "[DONE]":
        return None
    try:
        decoded = jsonlib.loads(payload)
    except jsonlib.JSONDecodeError as exc:
        raise _stream_protocol_error("Malformed JSON in TrustedRouter SSE data frame") from exc
    if not isinstance(decoded, dict):
        raise _stream_protocol_error(
            "TrustedRouter SSE data frame must contain a JSON object",
            payload=decoded,
        )
    if isinstance(decoded.get("error"), (dict, str)):
        raise _stream_protocol_error(
            "TrustedRouter SSE stream reported an error",
            payload=decoded,
        )
    return decoded


def _event_from_sse_frame(lines: list[str]) -> dict[str, Any] | None:
    event_name: str | None = None
    data_parts: list[str] = []
    for line in lines:
        if line.startswith("event:"):
            event_name = line[len("event:") :].strip()
        elif line.startswith("data:"):
            data_parts.append(line[len("data:") :].strip())
    data = "\n".join(data_parts).strip()
    if not data or data == "[DONE]":
        return None
    try:
        payload = jsonlib.loads(data)
    except jsonlib.JSONDecodeError as exc:
        raise _stream_protocol_error("Malformed JSON in TrustedRouter SSE event") from exc
    if event_name and isinstance(payload, dict) and "event" not in payload:
        payload = {"event": event_name, **payload}
    return payload if isinstance(payload, dict) else {"event": event_name, "data": payload}


def _iter_sse_events(response: httpx.Response) -> Iterator[dict[str, Any]]:
    frame: list[str] = []
    saw_done = False
    for line in response.iter_lines():
        if line:
            frame.append(line)
            continue
        if any(_sse_data(item) == "[DONE]" for item in frame):
            saw_done = True
            frame = []
            continue
        if saw_done and any(_sse_data(item) for item in frame):
            raise _stream_protocol_error("TrustedRouter SSE emitted data after [DONE]")
        event = _event_from_sse_frame(frame)
        frame = []
        if event is not None:
            yield event
    if frame:
        if any(_sse_data(item) == "[DONE]" for item in frame):
            saw_done = True
        else:
            if saw_done and any(_sse_data(item) for item in frame):
                raise _stream_protocol_error("TrustedRouter SSE emitted data after [DONE]")
            event = _event_from_sse_frame(frame)
            if event is not None:
                yield event
    if not saw_done:
        raise _stream_protocol_error("TrustedRouter SSE stream ended before data: [DONE]")


async def _aiter_sse_events(response: httpx.Response) -> AsyncIterator[dict[str, Any]]:
    frame: list[str] = []
    saw_done = False
    async for line in response.aiter_lines():
        if line:
            frame.append(line)
            continue
        if any(_sse_data(item) == "[DONE]" for item in frame):
            saw_done = True
            frame = []
            continue
        if saw_done and any(_sse_data(item) for item in frame):
            raise _stream_protocol_error("TrustedRouter SSE emitted data after [DONE]")
        event = _event_from_sse_frame(frame)
        frame = []
        if event is not None:
            yield event
    if frame:
        if any(_sse_data(item) == "[DONE]" for item in frame):
            saw_done = True
        else:
            if saw_done and any(_sse_data(item) for item in frame):
                raise _stream_protocol_error("TrustedRouter SSE emitted data after [DONE]")
            event = _event_from_sse_frame(frame)
            if event is not None:
                yield event
    if not saw_done:
        raise _stream_protocol_error("TrustedRouter SSE stream ended before data: [DONE]")


def _delta_text(chunk: Mapping[str, Any]) -> str:
    choices = chunk.get("choices") or []
    if not choices:
        return ""
    delta = choices[0].get("delta") or {}
    content = delta.get("content")
    return content if isinstance(content, str) else ""


def _iter_sse_chunks(response: httpx.Response) -> Iterator[dict[str, Any]]:
    """Walk an open SSE response and yield each parsed `data: {...}` chunk
    as a dict. Skips blank lines and `[DONE]` sentinels. Shared by the
    sync chat_completions* methods so the SSE parsing lives in one place."""
    saw_done = False
    for line in response.iter_lines():
        data = _sse_data(line)
        if data == "[DONE]":
            saw_done = True
            continue
        if saw_done and data:
            raise _stream_protocol_error("TrustedRouter SSE emitted data after [DONE]")
        chunk = _parse_sse_line(line)
        if chunk is not None:
            yield chunk
    if not saw_done:
        raise _stream_protocol_error("TrustedRouter SSE stream ended before data: [DONE]")


async def _aiter_sse_chunks(response: httpx.Response) -> AsyncIterator[dict[str, Any]]:
    """Async twin of _iter_sse_chunks."""
    saw_done = False
    async for line in response.aiter_lines():
        data = _sse_data(line)
        if data == "[DONE]":
            saw_done = True
            continue
        if saw_done and data:
            raise _stream_protocol_error("TrustedRouter SSE emitted data after [DONE]")
        chunk = _parse_sse_line(line)
        if chunk is not None:
            yield chunk
    if not saw_done:
        raise _stream_protocol_error("TrustedRouter SSE stream ended before data: [DONE]")
