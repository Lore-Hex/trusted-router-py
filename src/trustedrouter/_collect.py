"""Stream -> completion collection (L5).

Reconstructs buffered response shapes from streamed chunk lists. Pure
functions; no I/O, no retry logic.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from trustedrouter._errors import _stream_protocol_error

_CONCATENATED_DELTA_FIELDS = frozenset({"content", "reasoning", "reasoning_content", "refusal"})


def _collect_completion(chunks: list[dict[str, Any]]) -> dict[str, Any]:
    """Reconstruct the OpenAI chat.completion JSON shape from a list of
    chat.completion.chunk frames. Used so callers that asked for
    stream=False still get a JSON object even though the gateway
    insists on streaming."""
    if not chunks:
        raise _stream_protocol_error("TrustedRouter returned an empty completion stream")

    usage: dict[str, Any] | None = None
    trustedrouter = _collect_trustedrouter_metadata(chunks)
    envelope: dict[str, Any] = {}
    choices_by_index: dict[int, dict[str, Any]] = {}

    for c in chunks:
        for key, value in c.items():
            if key not in {"choices", "usage", "trustedrouter", "object"}:
                envelope[key] = value
        chunk_usage = c.get("usage")
        if isinstance(chunk_usage, dict):
            usage = chunk_usage
        choices = c.get("choices") or []
        if not isinstance(choices, list):
            continue
        for ordinal, choice in enumerate(choices):
            if not isinstance(choice, Mapping):
                continue
            raw_index = choice.get("index", ordinal)
            index = raw_index if isinstance(raw_index, int) else ordinal
            state = choices_by_index.setdefault(
                index,
                {
                    "index": index,
                    "role": "assistant",
                    "parts": {},
                    "seen_delta_fields": set(),
                    "message_extras": {},
                    "choice_extras": {},
                    "tool_calls": {},
                    "function_call": {"name": "", "arguments": ""},
                    "saw_function_call": False,
                    "finish_reason": None,
                },
            )
            for key, value in choice.items():
                if key not in {"index", "delta", "finish_reason"}:
                    state["choice_extras"][key] = value

            delta = choice.get("delta") or {}
            if not isinstance(delta, Mapping):
                raise _stream_protocol_error(
                    "TrustedRouter completion choice delta must be an object",
                    payload=dict(choice),
                )
            for key, value in delta.items():
                state["seen_delta_fields"].add(key)
                if key == "role" and isinstance(value, str):
                    state["role"] = value
                elif key in _CONCATENATED_DELTA_FIELDS:
                    if isinstance(value, str):
                        state["parts"].setdefault(key, []).append(value)
                    elif value is not None:
                        state["message_extras"][key] = value
                elif key == "tool_calls":
                    _merge_tool_call_deltas(state["tool_calls"], value)
                elif key == "function_call":
                    _merge_function_call_delta(state, value)
                else:
                    state["message_extras"][key] = value
            if "finish_reason" in choice and choice.get("finish_reason") is not None:
                state["finish_reason"] = choice["finish_reason"]

    if not choices_by_index:
        raise _stream_protocol_error("TrustedRouter completion stream contained no choices")

    collected_choices: list[dict[str, Any]] = []
    for index in sorted(choices_by_index):
        state = choices_by_index[index]
        message: dict[str, Any] = {"role": state["role"], **state["message_extras"]}
        for field in _CONCATENATED_DELTA_FIELDS:
            parts = state["parts"].get(field)
            if parts:
                message[field] = "".join(parts)
            elif field in state["seen_delta_fields"] and field not in message:
                message[field] = None
        tool_calls = state["tool_calls"]
        if tool_calls:
            message["tool_calls"] = [tool_calls[i] for i in sorted(tool_calls)]
        if state["saw_function_call"]:
            message["function_call"] = state["function_call"]
        if "content" not in message:
            message["content"] = (
                None
                if tool_calls
                or state["saw_function_call"]
                or any(field in message for field in ("reasoning", "reasoning_content", "refusal"))
                else ""
            )
        collected_choices.append(
            {
                **state["choice_extras"],
                "index": index,
                "message": message,
                "finish_reason": state["finish_reason"],
            }
        )

    result: dict[str, Any] = {
        **envelope,
        "id": envelope.get("id", ""),
        "object": "chat.completion",
        "created": envelope.get("created", 0),
        "model": envelope.get("model", ""),
        "choices": collected_choices,
    }
    if usage is not None:
        result["usage"] = usage
    if trustedrouter is not None:
        result["trustedrouter"] = trustedrouter
    return result


def _merge_tool_call_deltas(tool_calls: dict[int, dict[str, Any]], value: Any) -> None:
    if not isinstance(value, list):
        return
    for ordinal, tool_call in enumerate(value):
        if not isinstance(tool_call, Mapping):
            continue
        raw_index = tool_call.get("index", ordinal)
        index = raw_index if isinstance(raw_index, int) else ordinal
        slot = tool_calls.setdefault(
            index,
            {
                "index": index,
                "type": "function",
                "function": {"name": "", "arguments": ""},
            },
        )
        for key, item in tool_call.items():
            if key not in {"index", "function"}:
                slot[key] = item
        function = tool_call.get("function")
        if isinstance(function, Mapping):
            for key, item in function.items():
                if key == "arguments" and isinstance(item, str):
                    slot["function"]["arguments"] += item
                elif item is not None:
                    slot["function"][key] = item


def _merge_function_call_delta(state: dict[str, Any], value: Any) -> None:
    if not isinstance(value, Mapping):
        return
    state["saw_function_call"] = True
    for key, item in value.items():
        if key == "arguments" and isinstance(item, str):
            state["function_call"]["arguments"] += item
        elif item is not None:
            state["function_call"][key] = item


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
