"""Stream -> completion collection (L5).

Reconstructs buffered response shapes from streamed chunk lists. Pure
functions; no I/O, no retry logic.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


def _collect_completion(chunks: list[dict[str, Any]]) -> dict[str, Any]:
    """Reconstruct the OpenAI chat.completion JSON shape from a list of
    chat.completion.chunk frames. Used so callers that asked for
    stream=False still get a JSON object even though the gateway
    insists on streaming."""
    if not chunks:
        return {
            "id": "",
            "object": "chat.completion",
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": ""},
                    "finish_reason": "stop",
                }
            ],
        }
    text_parts: list[str] = []
    finish_reason: str | None = None
    role = "assistant"
    usage: dict[str, Any] | None = None
    trustedrouter = _collect_trustedrouter_metadata(chunks)
    # tool-call deltas arrive fragmented and keyed by `index`; the arguments
    # stream in pieces and must be concatenated in arrival order.
    tool_calls: dict[int, dict[str, Any]] = {}
    for c in chunks:
        chunk_usage = c.get("usage")
        if isinstance(chunk_usage, dict):
            usage = chunk_usage
        choices = c.get("choices") or []
        if not choices:
            continue
        choice0 = choices[0]
        delta = choice0.get("delta") or {}
        if isinstance(delta.get("role"), str):
            role = delta["role"]
        if isinstance(delta.get("content"), str):
            text_parts.append(delta["content"])
        for tc in delta.get("tool_calls") or []:
            if not isinstance(tc, dict):
                continue
            idx = tc.get("index", 0)
            slot = tool_calls.setdefault(
                idx, {"index": idx, "type": "function", "function": {"name": "", "arguments": ""}}
            )
            if tc.get("id"):
                slot["id"] = tc["id"]
            if tc.get("type"):
                slot["type"] = tc["type"]
            fn = tc.get("function")
            if isinstance(fn, dict):
                if fn.get("name"):
                    slot["function"]["name"] = fn["name"]
                if isinstance(fn.get("arguments"), str):
                    slot["function"]["arguments"] += fn["arguments"]
        if choice0.get("finish_reason"):
            finish_reason = choice0["finish_reason"]
    last = chunks[-1]
    content = "".join(text_parts)
    # OpenAI sets content to null when a turn is only tool calls.
    message: dict[str, Any] = {
        "role": role,
        "content": content if content else (None if tool_calls else ""),
    }
    if tool_calls:
        message["tool_calls"] = [tool_calls[i] for i in sorted(tool_calls)]
    result: dict[str, Any] = {
        "id": last.get("id", ""),
        "object": "chat.completion",
        "created": last.get("created", 0),
        "model": last.get("model", ""),
        "choices": [
            {
                "index": 0,
                "message": message,
                "finish_reason": finish_reason or "stop",
            }
        ],
    }
    if usage is not None:
        result["usage"] = usage
    if trustedrouter is not None:
        result["trustedrouter"] = trustedrouter
    return result


def _collect_trustedrouter_metadata(chunks: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Preserve TrustedRouter extension metadata from streamed chunks.

    The gateway streams Synth observability as top-level ``trustedrouter`` events
    with empty ``choices``. The collector used to rebuild only OpenAI core fields,
    which meant callers of ``chat_completions`` lost panel/judge/final details.
    """

    synth_events: list[dict[str, Any]] = []
    synth_details: dict[str, Any] = {}

    for chunk in chunks:
        trusted = chunk.get("trustedrouter")
        if not isinstance(trusted, Mapping):
            continue
        synth = trusted.get("synth")
        if not isinstance(synth, Mapping):
            continue

        synth_dict = dict(synth)
        if "event" in synth_dict:
            synth_events.append(synth_dict)
        else:
            synth_details.update(synth_dict)

    if not synth_events and not synth_details:
        return None

    synth_out = dict(synth_details)
    if synth_events:
        synth_out["events"] = synth_events

    panel: list[dict[str, Any]] = []
    judge_attempts: list[dict[str, Any]] = []
    final_attempts: list[dict[str, Any]] = []
    for event in synth_events:
        event_name = event.get("event")
        detail = _trustedrouter_synth_event_detail(event)
        if detail is None:
            continue
        if event_name == "panel.done":
            panel.append(detail)
        elif event_name == "judge.done":
            judge_attempts.append(detail)
        elif event_name == "final.done":
            final_attempts.append(detail)

    if panel and "panel" not in synth_out:
        synth_out["panel"] = panel
    if judge_attempts:
        synth_out.setdefault("judge_attempts", judge_attempts)
        synth_out.setdefault("judge", judge_attempts[-1])
    if final_attempts and "final_attempts" not in synth_out:
        synth_out["final_attempts"] = final_attempts

    return {"synth": synth_out}


def _trustedrouter_synth_event_detail(event: Mapping[str, Any]) -> dict[str, Any] | None:
    detail = event.get("detail")
    if not isinstance(detail, Mapping):
        return None
    out = dict(detail)
    for key in ("stage", "index", "model"):
        if key in event and key not in out:
            out[key] = event[key]
    return out


def _with_usage(params: Mapping[str, Any]) -> dict[str, Any]:
    """Ask the gateway to emit a trailing usage frame so a *collected*
    completion carries token counts. The streamed transport omits usage
    unless ``stream_options.include_usage`` is set; default it on (callers
    can still override by passing their own ``stream_options``)."""
    merged = dict(params)
    stream_options = dict(merged.get("stream_options") or {})
    stream_options.setdefault("include_usage", True)
    merged["stream_options"] = stream_options
    return merged
