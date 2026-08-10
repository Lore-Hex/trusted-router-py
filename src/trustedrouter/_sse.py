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


def _parse_sse_line(line: str) -> dict[str, Any] | None:
    """Parse one `data: {...}` line. Returns None for non-data lines or [DONE]."""
    if not line.startswith("data: "):
        return None
    payload = line[len("data: ") :].strip()
    if not payload or payload == "[DONE]":
        return None
    try:
        return jsonlib.loads(payload)  # type: ignore[no-any-return]
    except jsonlib.JSONDecodeError:
        return None


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
    except jsonlib.JSONDecodeError:
        payload = {"data": data}
    if event_name and isinstance(payload, dict) and "event" not in payload:
        payload = {"event": event_name, **payload}
    return payload if isinstance(payload, dict) else {"event": event_name, "data": payload}


def _iter_sse_events(response: httpx.Response) -> Iterator[dict[str, Any]]:
    frame: list[str] = []
    for line in response.iter_lines():
        if line:
            frame.append(line)
            continue
        event = _event_from_sse_frame(frame)
        frame = []
        if event is not None:
            yield event
    event = _event_from_sse_frame(frame)
    if event is not None:
        yield event


async def _aiter_sse_events(response: httpx.Response) -> AsyncIterator[dict[str, Any]]:
    frame: list[str] = []
    async for line in response.aiter_lines():
        if line:
            frame.append(line)
            continue
        event = _event_from_sse_frame(frame)
        frame = []
        if event is not None:
            yield event
    event = _event_from_sse_frame(frame)
    if event is not None:
        yield event


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
    for line in response.iter_lines():
        chunk = _parse_sse_line(line)
        if chunk is not None:
            yield chunk


async def _aiter_sse_chunks(response: httpx.Response) -> AsyncIterator[dict[str, Any]]:
    """Async twin of _iter_sse_chunks."""
    async for line in response.aiter_lines():
        chunk = _parse_sse_line(line)
        if chunk is not None:
            yield chunk
