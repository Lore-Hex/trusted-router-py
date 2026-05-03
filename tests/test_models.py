"""Direct coverage for the pydantic response models — independent of
the client. Keeps the model layer testable in isolation."""
from __future__ import annotations

from trustedrouter.models import (
    ChatChoice,
    ChatChoiceDelta,
    ChatCompletion,
    ChatCompletionChunk,
    ChatMessage,
    EmbeddingResponse,
    MessagesResponse,
    ModelInfo,
    ModelList,
    ModelPricing,
    TrustRelease,
)


def test_chat_completion_round_trips_minimal_payload() -> None:
    """The `_collect_completion` helper produces this minimal envelope
    when the upstream returns no chunks at all. Validating it ensures
    callers can always rely on the typed shape."""
    payload = {
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
    cc = ChatCompletion.model_validate(payload)
    assert cc.choices[0].message.content == ""
    assert cc.choices[0].finish_reason == "stop"
    # Round-trip through model_dump preserves the OpenAI shape.
    assert cc.model_dump()["object"] == "chat.completion"


def test_chat_completion_chunk_handles_role_only_delta() -> None:
    """First chunk in many provider streams has only role, no content.
    Must not crash and must give content=None (not empty string)."""
    chunk = ChatCompletionChunk.model_validate({
        "choices": [{"delta": {"role": "assistant"}}]
    })
    assert chunk.choices[0].delta.role == "assistant"
    assert chunk.choices[0].delta.content is None


def test_chat_completion_chunk_handles_finish_only_chunk() -> None:
    """Last chunk often has empty delta with finish_reason=stop."""
    chunk = ChatCompletionChunk.model_validate({
        "choices": [{"delta": {}, "finish_reason": "stop"}]
    })
    assert chunk.choices[0].finish_reason == "stop"


def test_extra_fields_are_preserved_on_model_dump() -> None:
    """Forward-compat contract: gateway adds new fields, SDK doesn't
    barf, and `.model_dump()` shows them — so existing code can read
    them too without an SDK release."""
    payload = {
        "id": "x",
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": "hi", "experimental_field": True},
            "finish_reason": "stop",
        }],
        "future_field": {"some": "thing"},
    }
    cc = ChatCompletion.model_validate(payload)
    dumped = cc.model_dump()
    assert dumped["future_field"] == {"some": "thing"}
    assert dumped["choices"][0]["message"]["experimental_field"] is True


def test_model_list_by_id_lookup_returns_model_or_none() -> None:
    listing = ModelList.model_validate({
        "data": [
            {"id": "a", "name": "A"},
            {"id": "b", "name": "B"},
        ],
    })
    assert listing.by_id("a").id == "a"
    assert listing.by_id("missing") is None
    # Iteration over .data is the canonical walk
    assert [m.id for m in listing.data] == ["a", "b"]


def test_model_pricing_carries_auto_max_fields() -> None:
    """The Auto model exposes pricing.prompt_max / completion_max (the
    range across candidates). Make sure the typed model surfaces both."""
    p = ModelPricing.model_validate({
        "prompt": "0.00000013",
        "completion": "0.00000027",
        "prompt_max": "0.00000499",
        "completion_max": "0.00002499",
    })
    assert p.prompt_max == "0.00000499"
    assert p.completion_max == "0.00002499"


def test_model_info_defaults_for_minimal_stub() -> None:
    """Stub-shape responses (just an id) must validate cleanly — useful
    in tests, hosted gateway always sends `name`."""
    m = ModelInfo.model_validate({"id": "stub"})
    assert m.id == "stub"
    assert m.name == ""  # default


def test_chat_message_optional_fields_missing_is_fine() -> None:
    """Tool-call fields are optional; a plain text message validates
    without them."""
    msg = ChatMessage.model_validate({"role": "user", "content": "hi"})
    assert msg.tool_calls is None
    assert msg.tool_call_id is None


def test_embedding_response_supports_base64_form() -> None:
    """OpenAI offers encoding_format=base64 which serializes the vector
    as a string. Embedding.embedding is typed list[float] | str."""
    r = EmbeddingResponse.model_validate({
        "data": [{"embedding": "AAECAwQF", "index": 0}],
        "model": "text-embed",
    })
    assert r.data[0].embedding == "AAECAwQF"


def test_messages_response_typed_content_blocks() -> None:
    r = MessagesResponse.model_validate({
        "id": "msg_1",
        "model": "claude",
        "content": [
            {"type": "text", "text": "hello"},
            {"type": "tool_use", "name": "search"},
        ],
        "stop_reason": "end_turn",
    })
    assert r.content[0].text == "hello"
    assert r.content[1].type == "tool_use"
    assert r.stop_reason == "end_turn"


def test_trust_release_optional_fields_default_to_none() -> None:
    tr = TrustRelease.model_validate({})
    assert tr.image_digest is None
    assert tr.image_reference is None


def test_chat_choice_chunk_default_delta_is_empty_delta_model() -> None:
    """If a chunk has no `delta` key at all, we still produce a
    ChatChoiceDelta() so callers can `.delta.content` without
    None-checking."""
    chunk = ChatCompletionChunk.model_validate({"choices": [{}]})
    assert isinstance(chunk.choices[0].delta, ChatChoiceDelta)
    assert chunk.choices[0].delta.content is None


def test_chat_choice_message_required_role_and_content() -> None:
    """ChatMessage requires role; everything else is optional."""
    cc = ChatChoice.model_validate({
        "message": {"role": "assistant", "content": "x"},
    })
    assert cc.index == 0  # default
    assert cc.message.role == "assistant"
