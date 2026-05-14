"""Coverage for `_collect_completion` — the helper that rolls a list of
chat.completion.chunk frames into a single chat.completion dict (so
callers asking for stream=False still get an OpenAI-shape result)."""
from __future__ import annotations

from typing import Any

from trustedrouter.client import _collect_completion


def test_empty_chunk_list_returns_minimal_assistant_envelope() -> None:
    """Empty stream — the gateway hung up before yielding anything.
    We must still return a parseable empty completion so callers don't
    need to special-case None."""
    result = _collect_completion([])
    assert result["object"] == "chat.completion"
    assert result["id"] == ""
    assert result["choices"][0]["message"]["role"] == "assistant"
    assert result["choices"][0]["message"]["content"] == ""
    assert result["choices"][0]["finish_reason"] == "stop"


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


def test_finish_reason_falls_back_to_stop_when_never_set() -> None:
    """Unterminated stream (provider didn't emit finish_reason) — we
    default to "stop" so the response is well-formed for downstream
    OpenAI-shape consumers."""
    chunks = [
        {"choices": [{"delta": {"content": "abc"}}]},
        {"choices": [{"delta": {"content": "def"}}]},
    ]
    result = _collect_completion(chunks)
    assert result["choices"][0]["finish_reason"] == "stop"


def test_uses_last_seen_finish_reason() -> None:
    """If multiple chunks set finish_reason (rare but possible), the
    LAST one wins — matches what providers actually do."""
    chunks = [
        {"choices": [{"delta": {"content": "x"}, "finish_reason": "length"}]},
        {"choices": [{"delta": {}, "finish_reason": "stop"}]},
    ]
    result = _collect_completion(chunks)
    assert result["choices"][0]["finish_reason"] == "stop"
