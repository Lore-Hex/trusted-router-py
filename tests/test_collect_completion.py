"""Coverage for `_collect_completion` — the helper that rolls a list of
chat.completion.chunk frames into a single chat.completion dict (so
callers asking for stream=False still get an OpenAI-shape result)."""
from __future__ import annotations

from typing import Any

import pytest

from trustedrouter import InternalError
from trustedrouter.client import _collect_completion


def test_empty_chunk_list_is_a_protocol_error() -> None:
    with pytest.raises(InternalError, match="empty completion stream"):
        _collect_completion([])


def test_concatenates_text_deltas_and_propagates_id_model_created() -> None:
    """Last chunk wins for envelope fields (id/model/created); content
    is the concatenation of every delta string in order."""
    chunks: list[dict[str, Any]] = [
        {"id": "first", "model": "m-1", "created": 100,
         "choices": [{"delta": {"content": "hel"}}]},
        {"id": "mid", "model": "m-2", "created": 101,
         "choices": [{"delta": {"content": "lo "}}]},
        {"id": "last", "model": "m-3", "created": 102,
         "choices": [{"delta": {"content": "world"}, "finish_reason": "stop"}]},
    ]
    result = _collect_completion(chunks)
    assert result["id"] == "last"
    assert result["model"] == "m-3"
    assert result["created"] == 102
    assert result["choices"][0]["message"]["content"] == "hello world"
    assert result["choices"][0]["finish_reason"] == "stop"


def test_skips_chunks_with_no_choices_array() -> None:
    """Some providers send heartbeat-style chunks with no `choices` —
    we must not crash and must not contribute anything to the rolled-up
    text."""
    chunks: list[dict[str, Any]] = [
        {"id": "a", "choices": []},
        {"id": "b"},  # no choices key at all
        {"id": "c", "choices": [{"delta": {"content": "hi"}}]},
    ]
    result = _collect_completion(chunks)
    assert result["choices"][0]["message"]["content"] == "hi"


def test_non_string_content_delta_is_ignored() -> None:
    """Defensive: if a provider sends `content: null` or a non-string
    type, _collect_completion shouldn't crash. The valid string deltas
    around it must still concatenate cleanly."""
    chunks: list[dict[str, Any]] = [
        {"choices": [{"delta": {"content": "ok "}}]},
        {"choices": [{"delta": {"content": None}}]},   # provider quirk
        {"choices": [{"delta": {"content": ["a", "b"]}}]},  # malformed
        {"choices": [{"delta": {"content": "good"}, "finish_reason": "stop"}]},
    ]
    result = _collect_completion(chunks)
    assert result["choices"][0]["message"]["content"] == "ok good"
    assert result["choices"][0]["finish_reason"] == "stop"


def test_missing_finish_reason_is_preserved_instead_of_fabricated() -> None:
    chunks = [
        {"choices": [{"delta": {"content": "abc"}}]},
        {"choices": [{"delta": {"content": "def"}}]},
    ]
    result = _collect_completion(chunks)
    assert result["choices"][0]["finish_reason"] is None


def test_uses_last_seen_finish_reason() -> None:
    """If multiple chunks set finish_reason (rare but possible), the
    LAST one wins — matches what providers actually do."""
    chunks = [
        {"choices": [{"delta": {"content": "x"}, "finish_reason": "length"}]},
        {"choices": [{"delta": {}, "finish_reason": "stop"}]},
    ]
    result = _collect_completion(chunks)
    assert result["choices"][0]["finish_reason"] == "stop"


def test_aggregates_streamed_tool_calls() -> None:
    """A tool-calling turn streams the function name once and the JSON
    arguments in fragments, keyed by index. We must reassemble each call
    with its id/name and the concatenated arguments — without this the
    whole tool-using/agentic path silently loses every function call."""
    chunks: list[dict[str, Any]] = [
        {"id": "x", "model": "m", "choices": [{"delta": {"role": "assistant", "tool_calls": [
            {"index": 0, "id": "call_a", "type": "function",
             "function": {"name": "web_search", "arguments": ""}}]}}]},
        {"choices": [{"delta": {"tool_calls": [
            {"index": 0, "function": {"arguments": '{"query":'}}]}}]},
        {"choices": [{"delta": {"tool_calls": [
            {"index": 0, "function": {"arguments": ' "taiwan"}'}}]}}]},
        {"choices": [{"delta": {}, "finish_reason": "tool_calls"}]},
    ]
    result = _collect_completion(chunks)
    msg = result["choices"][0]["message"]
    assert msg["content"] is None  # a tool-call-only turn has null content
    assert result["choices"][0]["finish_reason"] == "tool_calls"
    calls = msg["tool_calls"]
    assert len(calls) == 1
    assert calls[0]["id"] == "call_a"
    assert calls[0]["type"] == "function"
    assert calls[0]["function"]["name"] == "web_search"
    assert calls[0]["function"]["arguments"] == '{"query": "taiwan"}'


def test_aggregates_parallel_tool_calls_by_index() -> None:
    """Parallel tool calls arrive interleaved under different indexes and
    must stay separate, ordered by index."""
    chunks: list[dict[str, Any]] = [
        {"choices": [{"delta": {"tool_calls": [
            {"index": 0, "id": "c0", "function": {"name": "a", "arguments": "{}"}},
            {"index": 1, "id": "c1", "function": {"name": "b", "arguments": ""}}]}}]},
        {"choices": [{"delta": {"tool_calls": [
            {"index": 1, "function": {"arguments": "{}"}}]}, "finish_reason": "tool_calls"}]},
    ]
    calls = _collect_completion(chunks)["choices"][0]["message"]["tool_calls"]
    assert [c["function"]["name"] for c in calls] == ["a", "b"]
    assert calls[1]["function"]["arguments"] == "{}"


def test_captures_trailing_usage_frame() -> None:
    """With stream_options.include_usage the gateway emits a final frame
    carrying token usage and an empty choices array. We must surface it on
    the collected completion (it was dropped entirely before)."""
    chunks: list[dict[str, Any]] = [
        {
            "id": "u",
            "model": "m",
            "choices": [{"delta": {"content": "hi"}, "finish_reason": "stop"}],
        },
        {
            "id": "u",
            "model": "m",
            "choices": [],
            "usage": {"prompt_tokens": 11, "completion_tokens": 3, "total_tokens": 14},
        },
    ]
    result = _collect_completion(chunks)
    assert result["choices"][0]["message"]["content"] == "hi"
    assert result["usage"] == {"prompt_tokens": 11, "completion_tokens": 3, "total_tokens": 14}


def test_no_usage_frame_means_no_usage_key() -> None:
    """When no usage is streamed, omit the key rather than inventing zeros."""
    result = _collect_completion(
        [{"choices": [{"delta": {"content": "x"}, "finish_reason": "stop"}]}]
    )
    assert "usage" not in result


def test_plain_text_turn_still_has_no_tool_calls_key() -> None:
    """Regression guard: an ordinary text answer must not grow a spurious
    empty tool_calls list."""
    result = _collect_completion(
        [{"choices": [{"delta": {"content": "hello"}, "finish_reason": "stop"}]}]
    )
    assert "tool_calls" not in result["choices"][0]["message"]
    assert result["choices"][0]["message"]["content"] == "hello"


def test_preserves_trustedrouter_synth_stream_events_and_details() -> None:
    """Synth observability is streamed as TR extension chunks with no choices.
    Collected chat completions should keep those details for logging/debugging."""
    chunks: list[dict[str, Any]] = [
        {
            "id": "r",
            "model": "trustedrouter/synth",
            "choices": [],
            "trustedrouter": {"synth": {"event": "synth.started", "preset": "quality"}},
        },
        {
            "id": "r",
            "model": "trustedrouter/synth",
            "choices": [],
            "trustedrouter": {
                "synth": {
                    "event": "panel.done",
                    "stage": "panel",
                    "index": 0,
                    "model": "model/a",
                    "detail": {
                        "model": "model/a",
                        "finish_reason": "stop",
                        "visible_answer": "candidate answer",
                    },
                }
            },
        },
        {
            "id": "r",
            "model": "model/final",
            "choices": [{"delta": {"content": "final answer"}, "finish_reason": "stop"}],
        },
        {
            "id": "r",
            "model": "model/final",
            "choices": [],
            "usage": {"prompt_tokens": 11, "completion_tokens": 3, "total_tokens": 14},
            "trustedrouter": {"synth": {"cost_microdollars": 42}},
        },
    ]

    result = _collect_completion(chunks)

    assert result["choices"][0]["message"]["content"] == "final answer"
    assert result["trustedrouter"]["synth"]["cost_microdollars"] == 42
    assert [e["event"] for e in result["trustedrouter"]["synth"]["events"]] == [
        "synth.started",
        "panel.done",
    ]
    assert result["trustedrouter"]["synth"]["panel"] == [
        {
            "model": "model/a",
            "finish_reason": "stop",
            "visible_answer": "candidate answer",
            "stage": "panel",
            "index": 0,
        }
    ]
